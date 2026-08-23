/*
 * LinuxGuard - Embedded Linux Process Watchdog
 * -----------------------------------------------
 * Samples /proc periodically, builds a rolling per-process baseline
 * (CPU%, RSS), flags deviations, and writes a JSON snapshot that the
 * dashboard reads.
 *
 * Build:  make            (see Makefile)
 * Run:    ./watchdog [interval_seconds] [output_path] [audit_log_path] [flags...]
 *         defaults: interval=2s, output=/tmp/linuxguard_metrics.json,
 *                   audit=/tmp/linuxguard_audit.log
 *
 * Optional flags (all opt-in, off by default so plain `./watchdog` still
 * behaves exactly as before):
 *   --mqtt=host:port   Publish each alert/recovery to an MQTT broker
 *                      (topic "linuxguard/alerts") for remote/headless
 *                      monitoring. Hand-rolled QoS0 client, no libs.
 *   --contain          On a CPU-spike alert, throttle the offending
 *                      process via a cgroups v2 CPU quota instead of
 *                      just reporting it. Requires root and a pure
 *                      cgroup v2 mount with the cpu controller
 *                      delegated; otherwise this silently no-ops.
 *   --taskstats        Enrich each process's metrics with kernel
 *                      delay-accounting (time spent waiting for CPU,
 *                      block I/O, swap-in) via taskstats netlink.
 *                      Requires root and CONFIG_TASKSTATS; otherwise
 *                      this silently no-ops.
 *
 * Audit log: every time a process's verdict changes (a new alert fires,
 * or an alert clears) an append-only JSONL line is written to the audit
 * log. The dashboard's kill switch also appends "kill_action" entries
 * there via server.py. Containment actions log "contained"/"released".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "cgroups.h"
#include "mqtt_client.h"
#include "taskstats_client.h"

#define MAX_PROCS       512
#define NAME_LEN        64
#define HISTORY_LEN     5      /* samples kept for trend detection */
#define CPU_SPIKE_MULT  3.0    /* flag if cpu% > baseline * this   */
#define RSS_LEAK_GROWTH 1.15   /* flag if rss grew >15% every sample in a row */
#define RESTART_WINDOW  30     /* seconds - repeated restarts within this = crash loop */

typedef struct {
    int  pid;
    char name[NAME_LEN];
    unsigned long long utime, stime;   /* raw jiffies from /proc/[pid]/stat */
    unsigned long long starttime;
    long rss_kb;

    double cpu_pct;
    double cpu_baseline;   /* exponential moving average */
    long   rss_history[HISTORY_LEN];
    int    rss_hist_count;

    time_t last_seen;
    time_t first_seen;
    int    restart_count;

    char   verdict[64];    /* root-cause classification, empty if healthy */
    char   last_verdict[64]; /* verdict as of the previous sample, for edge-detecting audit events */
    int    active;         /* seen in this sampling pass */

    int    contained;      /* 1 if currently throttled via cgroups (--contain) */

    /* Delay-accounting, only populated when --taskstats is enabled */
    unsigned long long cpu_delay_ns;
    unsigned long long blkio_delay_ns;
    unsigned long long swapin_delay_ns;
} proc_info_t;

static proc_info_t procs[MAX_PROCS];
static int proc_count = 0;
static long clk_tck;
static char audit_path[300] = "/tmp/linuxguard_audit.log";

/* --contain */
static int contain_enabled = 0;
static int cgroups_ok = 0;
#define CONTAIN_CPU_PCT 20.0 /* cap a flagged process to 20% of one core */

/* --mqtt=host:port */
static int mqtt_enabled = 0;
static char mqtt_host[128] = "";
static int mqtt_port = 1883;
static int mqtt_fd = -1;

/* --taskstats */
static int taskstats_enabled = 0;
static int taskstats_fd = -1;

/* Append one JSONL event to the audit log. Best-effort - a failure to log
 * should never take the daemon down. Also publishes to MQTT if enabled. */
static void log_audit_event(const char *event_type, int pid, const char *name,
                             const char *detail) {
    FILE *f = fopen(audit_path, "a");
    if (f) {
        fprintf(f, "{\"ts\": %ld, \"type\": \"%s\", \"pid\": %d, \"name\": \"%s\", \"detail\": \"%s\"}\n",
                time(NULL), event_type, pid, name, detail);
        fclose(f);
    }

    if (mqtt_enabled) {
        if (mqtt_fd < 0) { /* lazily reconnect - broker may have been down */
            mqtt_fd = mqtt_connect(mqtt_host, mqtt_port, "linuxguard-watchdog");
        }
        if (mqtt_fd >= 0) {
            char payload[256];
            snprintf(payload, sizeof(payload),
                     "{\"ts\": %ld, \"type\": \"%s\", \"pid\": %d, \"name\": \"%s\", \"detail\": \"%s\"}",
                     time(NULL), event_type, pid, name, detail);
            if (mqtt_publish(mqtt_fd, "linuxguard/alerts", payload) != 0) {
                mqtt_disconnect(mqtt_fd);
                mqtt_fd = -1; /* retry connect on the next event */
            }
        }
    }
}

static proc_info_t *find_or_create(int pid, const char *name) {
    for (int i = 0; i < proc_count; i++) {
        if (procs[i].pid == pid) return &procs[i];
    }
    /* look for a same-named process that recently died -> restart tracking */
    for (int i = 0; i < proc_count; i++) {
        if (!procs[i].active && strcmp(procs[i].name, name) == 0 &&
            (time(NULL) - procs[i].last_seen) < RESTART_WINDOW) {
            procs[i].pid = pid;
            procs[i].restart_count++;
            procs[i].first_seen = time(NULL);
            procs[i].rss_hist_count = 0;
            snprintf(procs[i].verdict, sizeof(procs[i].verdict),
                     "crash loop (%d restarts)", procs[i].restart_count);
            return &procs[i];
        }
    }
    if (proc_count >= MAX_PROCS) return NULL;
    proc_info_t *p = &procs[proc_count++];
    memset(p, 0, sizeof(*p));
    p->pid = pid;
    strncpy(p->name, name, NAME_LEN - 1);
    p->first_seen = time(NULL);
    p->cpu_baseline = -1; /* not established yet */
    return p;
}

/* Parse /proc/[pid]/stat for name, utime, stime, starttime */
static int read_stat(int pid, char *name, unsigned long long *utime,
                      unsigned long long *stime, unsigned long long *starttime) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);

    /* name is in parentheses, may contain spaces - find last ')' */
    char *lp = strchr(buf, '(');
    char *rp = strrchr(buf, ')');
    if (!lp || !rp) return -1;
    size_t nlen = rp - lp - 1;
    if (nlen >= NAME_LEN) nlen = NAME_LEN - 1;
    strncpy(name, lp + 1, nlen);
    name[nlen] = '\0';

    /* fields after ')' : state, ppid, ... utime(14) stime(15) ... starttime(22) */
    char *rest = rp + 2;
    int field = 3; /* state is field 3 */
    unsigned long long ut = 0, st = 0, stt = 0;
    char *tok = strtok(rest, " ");
    while (tok) {
        if (field == 14) ut = strtoull(tok, NULL, 10);
        if (field == 15) st = strtoull(tok, NULL, 10);
        if (field == 22) { stt = strtoull(tok, NULL, 10); break; }
        tok = strtok(NULL, " ");
        field++;
    }
    *utime = ut; *stime = st; *starttime = stt;
    return 0;
}

static long read_rss_kb(int pid) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long rss = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

static void mark_all_inactive(void) {
    for (int i = 0; i < proc_count; i++) procs[i].active = 0;
}

static void classify(proc_info_t *p) {
    p->verdict[0] = '\0';

    /* CPU spike vs its own baseline */
    if (p->cpu_baseline >= 0.5 && p->cpu_pct > p->cpu_baseline * CPU_SPIKE_MULT) {
        snprintf(p->verdict, sizeof(p->verdict),
                 "CPU spike (%.1f%% vs baseline %.1f%%)", p->cpu_pct, p->cpu_baseline);
        return;
    }

    /* Sustained RSS growth -> possible memory leak */
    if (p->rss_hist_count == HISTORY_LEN) {
        int growing = 1;
        for (int i = 1; i < HISTORY_LEN; i++) {
            if (p->rss_history[i] <= p->rss_history[i - 1]) { growing = 0; break; }
        }
        if (growing && p->rss_history[HISTORY_LEN - 1] >
                        p->rss_history[0] * RSS_LEAK_GROWTH) {
            snprintf(p->verdict, sizeof(p->verdict),
                     "possible memory leak (RSS %ldKB -> %ldKB)",
                     p->rss_history[0], p->rss_history[HISTORY_LEN - 1]);
            return;
        }
    }
}

static void write_json(const char *out_path, double interval) {
    char tmp_path[300];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", out_path);
    FILE *f = fopen(tmp_path, "w");
    if (!f) { perror("fopen output"); return; }

    time_t now = time(NULL);
    fprintf(f, "{\n  \"timestamp\": %ld,\n  \"interval_sec\": %.1f,\n  \"processes\": [\n",
            now, interval);

    int first = 1;
    for (int i = 0; i < proc_count; i++) {
        proc_info_t *p = &procs[i];
        if (!p->active) continue;
        if (!first) fprintf(f, ",\n");
        first = 0;
        fprintf(f,
            "    {\"pid\": %d, \"name\": \"%s\", \"cpu_pct\": %.2f, "
            "\"cpu_baseline\": %.2f, \"rss_kb\": %ld, \"restarts\": %d, "
            "\"verdict\": \"%s\", \"status\": \"%s\", \"contained\": %s, "
            "\"cpu_delay_ms\": %.2f, \"blkio_delay_ms\": %.2f, \"swapin_delay_ms\": %.2f}",
            p->pid, p->name, p->cpu_pct, p->cpu_baseline < 0 ? 0 : p->cpu_baseline,
            p->rss_kb, p->restart_count, p->verdict,
            p->verdict[0] ? "warning" : "ok",
            p->contained ? "true" : "false",
            p->cpu_delay_ns / 1e6, p->blkio_delay_ns / 1e6, p->swapin_delay_ns / 1e6);
    }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    rename(tmp_path, out_path); /* atomic swap so dashboard never reads a half-written file */
}

int main(int argc, char **argv) {
    double interval = 2.0;
    const char *out_path = "/tmp/linuxguard_metrics.json";

    if (argc > 1) interval = atof(argv[1]);
    if (argc > 2) out_path = argv[2];
    if (argc > 3) strncpy(audit_path, argv[3], sizeof(audit_path) - 1);

    for (int i = 4; i < argc; i++) {
        if (strncmp(argv[i], "--mqtt=", 7) == 0) {
            const char *hostport = argv[i] + 7;
            const char *colon = strrchr(hostport, ':');
            if (colon) {
                size_t hlen = (size_t)(colon - hostport);
                if (hlen >= sizeof(mqtt_host)) hlen = sizeof(mqtt_host) - 1;
                strncpy(mqtt_host, hostport, hlen);
                mqtt_host[hlen] = '\0';
                mqtt_port = atoi(colon + 1);
            } else {
                strncpy(mqtt_host, hostport, sizeof(mqtt_host) - 1);
            }
            mqtt_enabled = 1;
        } else if (strcmp(argv[i], "--contain") == 0) {
            contain_enabled = 1;
        } else if (strcmp(argv[i], "--taskstats") == 0) {
            taskstats_enabled = 1;
        } else {
            fprintf(stderr, "Unknown flag: %s\n", argv[i]);
        }
    }

    clk_tck = sysconf(_SC_CLK_TCK);
    printf("LinuxGuard watchdog starting. interval=%.1fs output=%s audit=%s\n",
           interval, out_path, audit_path);

    if (mqtt_enabled) {
        mqtt_fd = mqtt_connect(mqtt_host, mqtt_port, "linuxguard-watchdog");
        if (mqtt_fd < 0) {
            fprintf(stderr, "MQTT: could not connect to %s:%d at startup - "
                             "will keep retrying on each alert.\n", mqtt_host, mqtt_port);
        } else {
            printf("MQTT: publishing alerts to %s:%d (topic linuxguard/alerts)\n",
                   mqtt_host, mqtt_port);
        }
    }

    if (contain_enabled) {
        cgroups_ok = cgroups_v2_available();
        if (!cgroups_ok) {
            fprintf(stderr, "--contain requested but cgroup v2 (with the cpu "
                             "controller delegated) isn't available - "
                             "containment will be skipped, alerts still work.\n");
        } else {
            printf("Containment enabled: flagged CPU spikes will be capped to "
                   "%.0f%% of one core via cgroups v2.\n", CONTAIN_CPU_PCT);
        }
    }

    if (taskstats_enabled) {
        taskstats_fd = taskstats_init();
        if (taskstats_fd < 0) {
            fprintf(stderr, "--taskstats requested but the kernel's taskstats "
                             "netlink interface isn't available (needs root and "
                             "CONFIG_TASKSTATS) - delay-accounting will be skipped.\n");
            taskstats_enabled = 0;
        } else {
            printf("Taskstats enabled: enriching metrics with CPU/IO/swap delay accounting.\n");
        }
    }

    while (1) {
        mark_all_inactive();
        DIR *d = opendir("/proc");
        if (!d) { perror("opendir /proc"); return 1; }

        struct dirent *entry;
        while ((entry = readdir(d)) != NULL) {
            if (!isdigit((unsigned char)entry->d_name[0])) continue;
            int pid = atoi(entry->d_name);

            char name[NAME_LEN] = {0};
            unsigned long long ut = 0, st = 0, stt = 0;
            if (read_stat(pid, name, &ut, &st, &stt) != 0) continue;
            long rss = read_rss_kb(pid);
            if (rss < 0) rss = 0;

            proc_info_t *p = find_or_create(pid, name);
            if (!p) continue;
            p->active = 1;
            p->last_seen = time(NULL);

            unsigned long long total_ticks = ut + st;
            if (p->utime + p->stime > 0) {
                unsigned long long delta_ticks = total_ticks - (p->utime + p->stime);
                double cpu_seconds = (double)delta_ticks / (double)clk_tck;
                p->cpu_pct = (cpu_seconds / interval) * 100.0;
                p->cpu_baseline = (p->cpu_baseline < 0)
                        ? p->cpu_pct
                        : (0.8 * p->cpu_baseline + 0.2 * p->cpu_pct); /* EMA */
            } else {
                p->cpu_pct = 0;
            }
            p->utime = ut; p->stime = st; p->starttime = stt;
            p->rss_kb = rss;

            if (p->rss_hist_count < HISTORY_LEN) {
                p->rss_history[p->rss_hist_count++] = rss;
            } else {
                memmove(p->rss_history, p->rss_history + 1,
                        (HISTORY_LEN - 1) * sizeof(long));
                p->rss_history[HISTORY_LEN - 1] = rss;
            }

            classify(p);

            if (taskstats_enabled) {
                taskstats_delays_t d;
                if (taskstats_get_delays(taskstats_fd, pid, &d) == 0) {
                    p->cpu_delay_ns = d.cpu_delay_ns;
                    p->blkio_delay_ns = d.blkio_delay_ns;
                    p->swapin_delay_ns = d.swapin_delay_ns;
                }
                /* on failure (process gone, permission), leave last-known values */
            }

            /* Log only on transition (new alert or recovery), not every sample */
            if (strcmp(p->verdict, p->last_verdict) != 0) {
                if (p->verdict[0]) {
                    log_audit_event("alert", p->pid, p->name, p->verdict);

                    if (contain_enabled && cgroups_ok && !p->contained &&
                        strncmp(p->verdict, "CPU spike", 9) == 0) {
                        if (cgroup_contain_process(p->pid, p->name, CONTAIN_CPU_PCT) == 0) {
                            p->contained = 1;
                            char detail[96];
                            snprintf(detail, sizeof(detail), "capped to %.0f%% of one core",
                                     CONTAIN_CPU_PCT);
                            log_audit_event("contained", p->pid, p->name, detail);
                        }
                    }
                } else {
                    log_audit_event("recovered", p->pid, p->name, p->last_verdict);

                    if (p->contained) {
                        cgroup_release_process(p->pid);
                        p->contained = 0;
                        log_audit_event("released", p->pid, p->name, "containment lifted");
                    }
                }
                strncpy(p->last_verdict, p->verdict, sizeof(p->last_verdict) - 1);
            }
        }
        closedir(d);

        write_json(out_path, interval);
        sleep((unsigned int)interval);
    }
    return 0;
}
