CC ?= gcc
CFLAGS ?= -Os
override CFLAGS += -Wall -Wextra -ffunction-sections -fdata-sections -Isecure -Isecure/monocypher
override LDFLAGS += -Wl,--gc-sections

SRCS = vbanhub.c vbanhub_cert.c secure/vban_secure.c secure/vban_noise.c
# Monocypher is vendored unmodified: no warning flags of ours on it
MONO = secure/monocypher/monocypher.c

vbanhub: $(SRCS) $(MONO) secure/vban/*.h vbanhub_bpf.h
	$(CC) $(CFLAGS) -c -w -o monocypher.o $(MONO)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) monocypher.o

clean:
	rm -f vbanhub monocypher.o
