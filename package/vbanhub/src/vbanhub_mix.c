/* vbanhub mixer, see vbanhub_mix.h */
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "vbanhub_mix.h"

#define HDR 28
#define PERIOD_NS(ticks) (((uint64_t)(ticks) * MIX_FRAMES * 1000000000ull) / 48000ull)
#define REBASE_TICKS (1u << 20)
#define MAX_CATCHUP 8

struct in_slot {
	int used, running;
	uint32_t ip;
	char name[MIX_NAME];
	unsigned gain;
	uint32_t rd, cnt;                    /* read position and fill, in frames */
	uint64_t last_ns;
	int16_t ring[MIX_RING * 2];
};

struct out_slot {
	int used, clocked;
	struct mix_dst d;
	struct sockaddr_in sa;
	uint32_t fc;
	uint64_t base_ns;
	uint32_t ticks;
	uint64_t pkts, under, over, unsupported;
	struct in_slot in[MIX_MAX_IN];
};

static struct out_slot outs[MIX_MAX_OUT];

static int same_dst(const struct mix_dst *a, const struct mix_dst *b)
{
	return a->ip == b->ip && a->port == b->port && !memcmp(a->name, b->name, MIX_NAME);
}

int mix_sync(const struct mix_dst *d, int n)
{
	int i, j, kept = 0;

	if (n > MIX_MAX_OUT)
		n = MIX_MAX_OUT;
	for (i = 0; i < MIX_MAX_OUT; i++) {
		if (!outs[i].used)
			continue;
		for (j = 0; j < n && !same_dst(&outs[i].d, &d[j]); j++)
			;
		if (j == n)
			memset(&outs[i], 0, sizeof(outs[i]));
	}
	for (j = 0; j < n; j++) {
		for (i = 0; i < MIX_MAX_OUT && !(outs[i].used && same_dst(&outs[i].d, &d[j])); i++)
			;
		if (i < MIX_MAX_OUT) {
			kept++;
			continue;
		}
		for (i = 0; i < MIX_MAX_OUT && outs[i].used; i++)
			;
		if (i == MIX_MAX_OUT)
			break;
		memset(&outs[i], 0, sizeof(outs[i]));
		outs[i].used = 1;
		outs[i].d = d[j];
		outs[i].sa.sin_family = AF_INET;
		outs[i].sa.sin_addr.s_addr = d[j].ip;
		outs[i].sa.sin_port = d[j].port;
	}
	return kept;
}

int mix_find(uint32_t ip, uint16_t port)
{
	int i;

	for (i = 0; i < MIX_MAX_OUT; i++)
		if (outs[i].used && outs[i].d.ip == ip && outs[i].d.port == port)
			return i;
	return -1;
}

static int16_t clamp16(int32_t v)
{
	return (int16_t)(v > 32767 ? 32767 : (v < -32768 ? -32768 : v));
}

/* One sample of the packet as s16. fmt: 1 s16, 2 s24, 3 s32, 4 f32 (all little endian). */
static int16_t sample16(const uint8_t *b, unsigned fmt)
{
	switch (fmt) {
	case 1:
		return (int16_t)(b[0] | b[1] << 8);
	case 2:
		return (int16_t)(((int32_t)((uint32_t)b[0] << 8 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 24)) >> 16);
	case 3:
		return (int16_t)(((int32_t)((uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24)) >> 16);
	default: {
		uint32_t u = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
		float x;
		memcpy(&x, &u, 4);
		if (!(x == x))
			return 0;
		return clamp16((int32_t)(x * 32767.0f));
	}
	}
}

int mix_feed(int o, uint32_t ip, const uint8_t *h, const uint8_t *payload, unsigned plen, unsigned gain, uint64_t now_ns)
{
	static const unsigned bps_of[5] = { 0, 2, 3, 4, 4 };
	struct out_slot *os;
	struct in_slot *s = NULL;
	unsigned fmt, ch, bps, frames, f, i;
	uint32_t pos;

	if (o < 0 || o >= MIX_MAX_OUT || !outs[o].used)
		return 0;
	os = &outs[o];
	fmt = h[7] & 0x07;
	ch = (unsigned)h[6] + 1;
	/* audio sub-protocol, 48 kHz, PCM codec, s16/s24/s32/f32, mono or stereo */
	if ((h[4] & 0xFF) != 0x03 || (h[7] & 0xF0) || fmt < 1 || fmt > 4 || ch > 2) {
		os->unsupported++;
		return 0;
	}
	bps = bps_of[fmt];
	frames = (unsigned)h[5] + 1;
	if (frames * ch * bps > plen)
		frames = plen / (ch * bps);
	if (!frames) {
		os->unsupported++;
		return 0;
	}
	for (i = 0; i < MIX_MAX_IN; i++)
		if (os->in[i].used && os->in[i].ip == ip && !memcmp(os->in[i].name, h + 8, MIX_NAME)) {
			s = &os->in[i];
			break;
		}
	if (!s) {
		for (i = 0; i < MIX_MAX_IN && os->in[i].used; i++)
			;
		if (i == MIX_MAX_IN) {
			os->unsupported++;           /* more inputs than slots */
			return 0;
		}
		s = &os->in[i];
		memset(s, 0, sizeof(*s));
		s->used = 1;
		s->ip = ip;
		memcpy(s->name, h + 8, MIX_NAME);
	}
	s->gain = gain;
	s->last_ns = now_ns;
	if (frames > MIX_RING)
		frames = MIX_RING;
	if (s->cnt + frames > MIX_RING) {        /* overrun: drop the oldest */
		uint32_t d = s->cnt + frames - MIX_RING;
		s->rd = (s->rd + d) & (MIX_RING - 1);
		s->cnt -= d;
		os->over++;
	}
	pos = (s->rd + s->cnt) & (MIX_RING - 1);
	for (f = 0; f < frames; f++) {
		const uint8_t *b = payload + (size_t)f * ch * bps;
		int16_t l = sample16(b, fmt), r = ch == 2 ? sample16(b + bps, fmt) : l;
		s->ring[pos * 2] = l;
		s->ring[pos * 2 + 1] = r;
		pos = (pos + 1) & (MIX_RING - 1);
	}
	s->cnt += frames;
	return 1;
}

static int live_inputs(struct out_slot *o, uint64_t now_ns)
{
	int i, n = 0;

	for (i = 0; i < MIX_MAX_IN; i++) {
		struct in_slot *s = &o->in[i];
		if (!s->used)
			continue;
		if (now_ns > s->last_ns && now_ns - s->last_ns > (uint64_t)MIX_IDLE_MS * 1000000ull)
			s->used = 0;
		else
			n++;
	}
	return n;
}

static void emit(struct out_slot *o, mix_send_fn send, void *ctx)
{
	int32_t acc[MIX_FRAMES * 2];
	uint8_t pkt[HDR + MIX_FRAMES * 4];
	uint32_t fc;
	int i;
	unsigned k;

	memset(acc, 0, sizeof(acc));
	for (i = 0; i < MIX_MAX_IN; i++) {
		struct in_slot *s = &o->in[i];
		int64_t g;
		unsigned f;

		if (!s->used)
			continue;
		if (!s->running) {
			if (s->cnt < MIX_TARGET)
				continue;
			s->running = 1;
		}
		if (s->cnt > MIX_HIGH) {             /* sender clock ahead of ours: back to the target fill */
			uint32_t d = s->cnt - MIX_TARGET;
			s->rd = (s->rd + d) & (MIX_RING - 1);
			s->cnt -= d;
			o->over++;
		}
		if (s->cnt < MIX_FRAMES) {           /* underrun: prime again, this input is silent meanwhile */
			s->running = 0;
			o->under++;
			continue;
		}
		g = (int64_t)s->gain * 16384 / 100;
		for (f = 0; f < MIX_FRAMES; f++) {
			uint32_t p = ((s->rd + f) & (MIX_RING - 1)) * 2;
			acc[f * 2] += (int32_t)(((int64_t)s->ring[p] * g) >> 14);
			acc[f * 2 + 1] += (int32_t)(((int64_t)s->ring[p + 1] * g) >> 14);
		}
		s->rd = (s->rd + MIX_FRAMES) & (MIX_RING - 1);
		s->cnt -= MIX_FRAMES;
	}
	memcpy(pkt, "VBAN", 4);
	pkt[4] = 0x03;                               /* audio, 48 kHz */
	pkt[5] = MIX_FRAMES - 1;
	pkt[6] = 1;                                  /* 2 channels */
	pkt[7] = 1;                                  /* s16 PCM */
	memcpy(pkt + 8, o->d.name, MIX_NAME);
	fc = o->fc++;
	pkt[24] = fc & 0xFF; pkt[25] = (fc >> 8) & 0xFF; pkt[26] = (fc >> 16) & 0xFF; pkt[27] = (fc >> 24) & 0xFF;
	for (k = 0; k < MIX_FRAMES * 2; k++) {
		int16_t v = clamp16(acc[k]);
		pkt[HDR + k * 2] = (uint8_t)(v & 0xFF);
		pkt[HDR + k * 2 + 1] = (uint8_t)((uint16_t)v >> 8);
	}
	send(ctx, &o->sa, pkt, sizeof(pkt));
	o->pkts++;
}

void mix_tick(uint64_t now_ns, mix_send_fn send, void *ctx)
{
	int i, n;

	for (i = 0; i < MIX_MAX_OUT; i++) {
		struct out_slot *o = &outs[i];

		if (!o->used)
			continue;
		if (!live_inputs(o, now_ns)) {
			o->clocked = 0;
			continue;
		}
		if (!o->clocked) {
			o->clocked = 1;
			o->base_ns = now_ns;
			o->ticks = 0;
		}
		for (n = 0; n < MAX_CATCHUP && o->base_ns + PERIOD_NS(o->ticks) <= now_ns; n++) {
			emit(o, send, ctx);
			o->ticks++;
		}
		if (o->base_ns + PERIOD_NS(o->ticks) + 100000000ull < now_ns) {   /* fell far behind: resync */
			o->base_ns = now_ns;
			o->ticks = 0;
		} else if (o->ticks >= REBASE_TICKS) {
			o->base_ns += PERIOD_NS(o->ticks);
			o->ticks = 0;
		}
	}
}

uint64_t mix_deadline(void)
{
	uint64_t best = 0;
	int i;

	for (i = 0; i < MIX_MAX_OUT; i++) {
		uint64_t d;
		if (!outs[i].used || !outs[i].clocked)
			continue;
		d = outs[i].base_ns + PERIOD_NS(outs[i].ticks);
		if (!best || d < best)
			best = d;
	}
	return best;
}

int mix_count(void)
{
	int i, n = 0;

	for (i = 0; i < MIX_MAX_OUT; i++)
		n += outs[i].used;
	return n;
}

int mix_get_stats(int o, struct mix_stats *st)
{
	int i;

	if (o < 0 || o >= MIX_MAX_OUT || !outs[o].used)
		return 0;
	memset(st, 0, sizeof(*st));
	st->ip = outs[o].d.ip;
	st->port = outs[o].d.port;
	memcpy(st->name, outs[o].d.name, MIX_NAME);
	for (i = 0; i < MIX_MAX_IN; i++) {
		st->inputs += outs[o].in[i].used;
		st->running += outs[o].in[i].used && outs[o].in[i].running;
	}
	st->pkts = outs[o].pkts;
	st->under = outs[o].under;
	st->over = outs[o].over;
	st->unsupported = outs[o].unsupported;
	return 1;
}
