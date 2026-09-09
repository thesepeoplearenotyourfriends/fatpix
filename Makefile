CC ?= cc
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -Wpedantic

all: garble fatpix-c

garble: FORCE garble.c
	$(CC) $(CFLAGS) -o $@ garble.c

fatpix-c: FORCE fatpix.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ fatpix.c -lm

check: garble fatpix-c
	./test.sh

clean:
	rm -f garble fatpix-c

FORCE:

.PHONY: all check clean FORCE
