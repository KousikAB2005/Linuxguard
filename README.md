# LinuxGuard

**Real-Time Process Health & Root-Cause Watchdog for Embedded Linux**

Embedded Linux systems run several processes under tight resource budgets,
but there's no lightweight tool that watches app health continuously and
tells you *why* something is degrading. LinuxGuard is a small C daemon
that samples `/proc`, builds a per-process baseline, flags abnormal
CPU/memory behaviour, and shows it on a live web dashboard.

## How it works

```
 /proc, /sys  --->  watchdog.c (C daemon)  --->  metrics.json
                     samples every N sec          (atomic write)
                     tracks per-PID baseline
                     classifies root cause
                                                        |
                                                        v
                                          server.py (Python stdlib)
                                                        |
                                                        v
                                          index.html dashboard (browser)
```

- **`src/watchdog.c`** — reads `/proc/[pid]/stat` and `/proc/[pid]/status`
  for every running process, computes CPU% from jiffies deltas, tracks
  RSS history, keeps an exponential-moving-average baseline per process,
  and flags:
  - **CPU spikes** — current CPU% far above that process's own baseline
  - **Possible memory leaks** — RSS growing every sample in a row beyond
    a growth threshold
  - **Crash loops** — a process name reappearing repeatedly within a
    short window after dying
  Writes a JSON snapshot to `/tmp/linuxguard_metrics.json` (atomic
  write-then-rename so the dashboard never reads a half-written file).

- **`dashboard/server.py`** — zero-dependency Python server. Serves the
  static dashboard and exposes `/metrics.json` by reading the daemon's
  output file, so the browser never needs direct filesystem or CORS
  access.

- **`dashboard/index.html`** — live table of top processes by CPU, a
  root-cause alert panel, and a CPU trend chart (Chart.js), polling
  `/metrics.json` every 2 seconds.

## Build & run

```bash
# 1. Build the daemon
cd src
make

# 2. Run it (interval_seconds, output_path)
./watchdog 2 /tmp/linuxguard_metrics.json

# 3. In a second terminal, start the dashboard server
cd ../dashboard
python3 server.py 8080 /tmp/linuxguard_metrics.json

# 4. Open http://localhost:8080 in a browser
```

No external libraries required on the target beyond a C compiler and
Python 3 — this was a deliberate choice to keep it deployable on
resource-constrained boards (Raspberry Pi class and similar).

## Tech stack

- **Daemon:** C (`/proc`, `/sys/fs/cgroup` polling, no external deps)
- **Backend:** Python 3 standard library `http.server`
- **Frontend:** HTML/JS + Chart.js (via CDN)
- **Target:** any mainline embedded Linux board (tested on WSL2/Ubuntu)

## Project status

Hackathon prototype — root-cause classification is currently
rules/heuristics-based (EMA baseline + growth-rate detection), tuned to
be explainable and fast to build/demo rather than a trained ML model.

## Roadmap / stretch goals

- eBPF tracepoints for I/O wait and scheduler latency instead of pure
  `/proc` polling
- MQTT push for remote/headless monitoring
- cgroup-level aggregation for containerized workloads
