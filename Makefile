CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude -D_GNU_SOURCE

TARGET  = packet-sniffer
SRCS    = src/main.c src/capture.c src/parser.c src/dns.c \
          src/http_detect.c src/stats.c src/utils.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean install debug

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

debug: CFLAGS += -g -O0 -fsanitize=address,undefined
debug: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
