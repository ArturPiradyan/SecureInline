CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS += -lcrypto

.PHONY: all clean
all: secure_inline

secure_inline: secure_inline.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f secure_inline
