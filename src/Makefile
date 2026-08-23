CC = gcc
CFLAGS = -O2 -Wall -Wextra
TARGET = watchdog
OBJS = watchdog.o cgroups.o mqtt_client.o taskstats_client.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
