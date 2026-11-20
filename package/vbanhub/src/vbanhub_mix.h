/* vbanhub mixer: several VBAN audio inputs summed into ONE stream per receiver.
 *
 * A receiver marked "mix" gets a single outgoing stream (48 kHz, 2 ch, s16, MIX_FRAMES frames per
 * packet, one frame counter) instead of one forwarded stream per transmitter. Receivers that play
 * one stream at a time (sotto play, Voicemeeter) otherwise garble when two transmitters feed them.
 *
 * Each input has a small jitter buffer. The output is clocked by the hub (monotonic clock): every
 * tick takes MIX_FRAMES frames from each running input, sums them with saturation and sends one
 * packet. An input that underruns drops back to priming (its share is silence meanwhile); one that
 * runs ahead (sender clock faster) is trimmed back to the target fill. Inputs silent for
 * MIX_IDLE_MS are forgotten. While no input exists nothing is sent.
 *
 * Accepted inputs: PCM audio at 48 kHz, 1 or 2 channels, s16/s24/s32/f32. Anything else is
 * counted ("unsupported") and not mixed.
 */
#ifndef VBANHUB_MIX_H
#define VBANHUB_MIX_H

#include <stdint.h>
#include <netinet/in.h>

#define MIX_MAX_OUT   4
#define MIX_MAX_IN    6
#define MIX_FRAMES    128                    /* frames per output packet (2.67 ms at 48 kHz) */
#define MIX_RING      2048                   /* frames per input buffer (power of two) */
#define MIX_TARGET    960                    /* start playing at this fill (20 ms) */
#define MIX_HIGH      1472                   /* trim back to MIX_TARGET above this */
#define MIX_IDLE_MS   500
#define MIX_NAME      16

struct mix_dst {                             /* one mixed receiver, from the config */
	uint32_t ip;                         /* network order */
	uint16_t port;                       /* network order */
	char name[MIX_NAME];                 /* stream name of the mixed output */
};

struct mix_stats {
	uint32_t ip;
	uint16_t port;
	char name[MIX_NAME];
	int inputs, running;
	uint64_t pkts, under, over, unsupported;
};

/* Replace the set of mixed receivers. Existing ones (same ip, port, name) keep their inputs and
 * clock so a volume change or reload does not click. Returns the number kept. */
int mix_sync(const struct mix_dst *d, int n);

/* Index of the mixed receiver for (ip, port), or -1. */
int mix_find(uint32_t ip, uint16_t port);

/* Feed one VBAN packet (header h, payload of plen bytes) from source ip into output o.
 * gain = percent (100 = unchanged). Returns 1 if mixed, 0 if unsupported (counted). */
int mix_feed(int o, uint32_t ip, const uint8_t *h, const uint8_t *payload, unsigned plen, unsigned gain, uint64_t now_ns);

/* Emit every packet that is due. send(ctx, dst, buf, len) transmits one datagram. */
typedef void (*mix_send_fn)(void *ctx, const struct sockaddr_in *dst, const uint8_t *buf, unsigned len);
void mix_tick(uint64_t now_ns, mix_send_fn send, void *ctx);

/* Monotonic ns of the next packet that is due, or 0 when nothing is being mixed. */
uint64_t mix_deadline(void);

int mix_count(void);
int mix_get_stats(int o, struct mix_stats *s);

#endif
