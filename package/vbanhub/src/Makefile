CC ?= gcc
CFLAGS ?= -Os
CFLAGS += -Wall -Wextra -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

vbanhub: vbanhub.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f vbanhub
