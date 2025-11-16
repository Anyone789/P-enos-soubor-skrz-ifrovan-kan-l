CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude
LDFLAGS = -lssl -lcrypto -lpthread
SRCS = src/main.c src/client.c src/server.c src/crypto.c src/protocol.c src/utils.c
OBJS = $(SRCS:.c=.o)
TARGET = secret

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
