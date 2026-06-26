CC ?= cc
CFLAGS ?= -Wall -Wextra -g

all: toy-parser

toy-parser: src/main.c
	$(CC) $(CFLAGS) -o toy-parser src/main.c

clean:
	rm -f toy-parser
