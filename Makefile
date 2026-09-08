CC ?= cc
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -Wpedantic

all: garble

garble: FORCE garble.c
	$(CC) $(CFLAGS) -o $@ garble.c

check: garble
	./test.sh

clean:
	rm -f garble

FORCE:

.PHONY: all check clean FORCE
