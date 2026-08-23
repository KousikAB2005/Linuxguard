CC = gcc
CFLAGS = -O2 -Wall -Wextra
TARGET = watchdog

all: $(TARGET)

$(TARGET): watchdog.c
	$(CC) $(CFLAGS) -o $(TARGET) watchdog.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
