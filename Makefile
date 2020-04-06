CFLAGS=-O2 -Wall -Wextra
TARGETS=s5tunnel
OBJS=main.o s5tunnel.o
CC=cc

.PHONY: all clean
all: $(TARGETS)

s5tunnel: $(OBJS)
	$(CC) -o s5tunnel $(OBJS) -lpthread

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(TARGETS) $(OBJS)