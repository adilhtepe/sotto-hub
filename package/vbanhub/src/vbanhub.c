/*
 * vbanhub - tiny VBAN UDP fan-out / stream-name-rewriting hub.
 *
 * Never decodes audio. For each received packet it looks up the routes
 * bound to (source ip, stream name) and sends a copy to every destination
 * with the 16-byte stream name rewritten. Payload is shared via iovec
 * (no payload copy).
 *
 * Config file (generated from UCI by the init script), one route per line:
 *   route <src_ip|*> <src_stream|*> <dst_ip> <dst_port> <dst_stream>
 * Lines starting with '#' are ignored.
 *
 * Signals: SIGHUP reload config, SIGTERM/SIGINT quit.
 * Status JSON is written atomically every 2 s to the status path.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define VBAN_HDR 28
#define VBAN_MAX 1436
#define NAME_LEN 16
#define MAX_ROUTES 256
#define MAX_STREAMS 64
#define BATCH 16
#define MAX_FANOUT 32

struct route {
	uint32_t src_ip;     /* network order, 0 = any */
	char src_name[NAME_LEN];
	int src_any_name;
	struct sockaddr_in dst;
	char dst_name[NAME_LEN];
	uint64_t pkts, bytes, lost;
	uint32_t last_fc;
	int have_fc;
	time_t last_seen;
	unsigned gain;       /* effective route volume in percent (route x input x output), 100 = unchanged, 0 = mute */
};

static unsigned master_gain = 100;   /* master volume in percent, applied on top of every route */

/* Every VBAN stream heard (routed or not), keyed by (source ip, 16-byte stream name). */
struct stream {
	uint32_t ip;
	uint16_t port;               /* last source port (host order) */
	char name[NAME_LEN];         /* raw, not NUL-terminated if 16 long */
	uint8_t sr, nbs, nbc, bit;   /* raw header bytes 4..7 */
	uint8_t kind;                /* 0 unicast, 1 broadcast, 2 multicast */
	uint8_t routed;              /* matched at least one route on the last packet */
	uint64_t pkts, bytes, snap_pkts;
	time_t first_seen, last_seen, snap_ts;
	unsigned rate;               /* packets/s, refreshed with the status dump */
};

static struct route routes[MAX_ROUTES];
static int nroutes;
static struct stream streams[MAX_STREAMS];
static int nstreams;
static uint64_t st_rx, st_bad, st_unknown, st_tx, st_txerr;
static volatile sig_atomic_t want_reload, want_quit, want_scan;
static const char *cfg_path = "/var/etc/vbanhub.conf";
static const char *stat_path = "/var/run/vbanhub/status.json";
#define MAX_IFACES 8
static const char *ifaces[MAX_IFACES]; /* listen only on these (ingress filter); none = all */
static unsigned ifidx[MAX_IFACES];     /* resolved ifindex, 0 = not present (yet) */
static int nifaces;
static uint64_t st_filtered;

static int iface_selected(const char *name)
{
	int i;
	if (!nifaces)
		return 1;
	for (i = 0; i < nifaces; i++)
		if (!strcmp(ifaces[i], name))
			return 1;
	return 0;
}

static void resolve_ifaces(void)
{
	int i;
	for (i = 0; i < nifaces; i++)
		ifidx[i] = if_nametoindex(ifaces[i]);
}

/* Fail closed: with a selection, a packet is accepted only from a present, selected interface. */
static int if_allowed(int idx)
{
	int i;
	if (!nifaces)
		return 1;
	for (i = 0; i < nifaces; i++)
		if (ifidx[i] && ifidx[i] == (unsigned)idx)
			return 1;
	return 0;
}

/* Ingress ifindex (0 if unknown) and the datagram's destination address. */
static int ingress_info(struct msghdr *m, uint32_t *dst)
{
	struct cmsghdr *c;
	*dst = 0;
	for (c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c))
		if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo pi;
			memcpy(&pi, CMSG_DATA(c), sizeof(pi));
			*dst = pi.ipi_addr.s_addr;
			return pi.ipi_ifindex;
		}
	return 0;
}
static int listen_port = 6980;
static time_t started;

static void on_sig(int s)
{
	if (s == SIGHUP)
		want_reload = 1;
	else if (s == SIGUSR1)
		want_scan = 1;
	else
		want_quit = 1;
}

static void set_name(char *dst, const char *s)
{
	memset(dst, 0, NAME_LEN);
	strncpy(dst, s, NAME_LEN);
}

static int load_config(void)
{
	FILE *f = fopen(cfg_path, "r");
	char line[256];
	int n = 0;

	master_gain = 100;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f) && n < MAX_ROUTES) {
		/* TAB-separated so stream names may contain spaces:
		 * route \t src_ip|* \t src_stream|* \t dst_ip \t dst_port \t dst_stream [\t gain_percent]
		 * master \t gain_percent */
		char *fld[7], *t = line, *sip, *sname, *dip, *dname;
		int dport, nf = 0;
		struct route *r;
		struct in_addr a;

		if (line[0] == '#')
			continue;
		line[strcspn(line, "\r\n")] = 0;
		if (!strncmp(line, "master\t", 7)) {
			int g = atoi(line + 7);
			master_gain = g < 0 ? 0 : (g > 200 ? 200 : g);
			continue;
		}
		while (nf < 7) {
			fld[nf++] = t;
			t = strchr(t, '\t');
			if (!t)
				break;
			*t++ = 0;
		}
		if ((nf != 6 && nf != 7) || strcmp(fld[0], "route") || !fld[2][0] || !fld[5][0])
			continue;
		sip = fld[1]; sname = fld[2]; dip = fld[3]; dname = fld[5];
		dport = atoi(fld[4]);
		if (dport < 1 || dport > 65535)
			continue;
		r = &routes[n];
		memset(r, 0, sizeof(*r));
		if (strcmp(sip, "*")) {
			if (!inet_aton(sip, &a))
				continue;
			r->src_ip = a.s_addr;
		}
		if (!inet_aton(dip, &a))
			continue;
		{ /* refuse destinations that could loop back into the hub or
		   * reflect to broadcast/multicast/reserved space */
			uint32_t h = ntohl(a.s_addr);
			if ((h >> 24) == 0 || h >= 0xE0000000u ||
			    ((h >> 24) == 127 && dport == listen_port)) {
				fprintf(stderr, "vbanhub: refusing destination %s:%d\n", dip, dport);
				continue;
			}
		}
		r->dst.sin_family = AF_INET;
		r->dst.sin_addr = a;
		r->dst.sin_port = htons(dport);
		if (!strcmp(sname, "*"))
			r->src_any_name = 1;
		else
			set_name(r->src_name, sname);
		set_name(r->dst_name, dname);
		r->gain = 100;
		if (nf == 7) {
			int g = atoi(fld[6]);
			r->gain = g < 0 ? 0 : (g > 400 ? 400 : g);   /* route x input x output */
		}
		n++;
	}
	fclose(f);
	nroutes = n;
	return n;
}



/* ---- LAN discovery via VBAN PING0 (service identification), spec rev 13 ----
 * Request/reply = 28-byte header (sub-protocol 0x60, nbc=0 service, nbs=0 ping /
 * 0x80 reply, frame counter = request id) + 676-byte tagVBAN_PING0 struct. */
#define SVC_LEN 676
#define SVC_PKT (VBAN_HDR + SVC_LEN)
#define MAX_DISC 64
#define MAX_DEST 24
#define MAX_PORTS 8
/* bitType (spec rev 13): the hub receives from any number of transmitters and sends to any number of
 * receivers, so it presents itself as a SPOT receptor (several streams) and a SPOT transmitter. */
#define PING_TYPE_RECEPTOR         0x00000001u
#define PING_TYPE_TRANSMITTER      0x00000002u
#define PING_TYPE_RECEPTORSPOT     0x00000004u
#define PING_TYPE_TRANSMITTERSPOT  0x00000008u
#define PING_TYPE_HUB (PING_TYPE_RECEPTOR | PING_TYPE_TRANSMITTER | PING_TYPE_RECEPTORSPOT | PING_TYPE_TRANSMITTERSPOT)
static const char *hub_name;      /* shown to VBAN apps (-N); default: OpenWrt VBAN hub */

struct disc {
	uint32_t ip;
	uint16_t port;           /* host order, reply source port */
	uint32_t type, feat;
	char device[64], app[64], host[64], user[64];
	time_t last_seen;
};

static struct disc disc[MAX_DISC];
static int ndisc;
static uint32_t scan_id;
static time_t scan_until, last_scan, scan_interval;
static uint32_t extra_dest[8];
static int nextra;
static int scan_ports[MAX_PORTS] = { 6980 };
static int nports = 1;
static uint32_t local_ip[16], bcast_ip[8];
static int nlocal, nbcast;

static int is_local(uint32_t ip)
{
	int i;
	for (i = 0; i < nlocal; i++)
		if (local_ip[i] == ip)
			return 1;
	return 0;
}

static void refresh_ifaces(void)
{
	struct ifaddrs *ifa, *q;

	nlocal = nbcast = 0;
	if (getifaddrs(&ifa))
		return;
	for (q = ifa; q; q = q->ifa_next) {
		if (!q->ifa_addr || q->ifa_addr->sa_family != AF_INET)
			continue;
		if (nlocal < 16)
			local_ip[nlocal++] = ((struct sockaddr_in *)q->ifa_addr)->sin_addr.s_addr;
		if ((q->ifa_flags & IFF_BROADCAST) && q->ifa_broadaddr && nbcast < 8 &&
		    iface_selected(q->ifa_name))
			bcast_ip[nbcast++] = ((struct sockaddr_in *)q->ifa_broadaddr)->sin_addr.s_addr;
	}
	freeifaddrs(ifa);
}

/* req_name: stream-name label to echo (16 bytes) from the request, or NULL for our own. */
static void fill_ping(uint8_t *pkt, int reply, uint32_t fc, const uint8_t *req_name)
{
	uint8_t *d = pkt + VBAN_HDR;
	const char *nm = hub_name && *hub_name ? hub_name : "OpenWrt VBAN hub";
	uint32_t v;

	memset(pkt, 0, SVC_PKT);
	memcpy(pkt, "VBAN", 4);
	pkt[4] = 0x60;                 /* SERVICE */
	pkt[5] = reply ? 0x80 : 0;     /* function PING0 (+ reply bit) */
	pkt[6] = 0;                    /* service IDENTIFICATION */
	if (req_name)
		memcpy(pkt + 8, req_name, NAME_LEN);
	else
		memcpy(pkt + 8, "VBAN SPOT PING", 14);
	v = htole32(fc);
	memcpy(pkt + 24, &v, 4);
	v = htole32(PING_TYPE_HUB);
	memcpy(d, &v, 4);
	v = htole32(0x00000001u | 0x00000100u | 0x00010000u); /* audio, serial, text */
	memcpy(d + 4, &v, 4);
	v = htole32(48000);                                     /* PreferedRate */
	memcpy(d + 12, &v, 4);
	v = htole32(6000);                                      /* MinRate: the hub passes any rate through */
	memcpy(d + 16, &v, 4);
	v = htole32(705600);                                    /* MaxRate */
	memcpy(d + 20, &v, 4);
	d[29] = 1;                                              /* nVersion 0.1.0.0 */
	strncpy((char *)d + 48, "EN", 7);                       /* LangCode */
	strncpy((char *)d + 164, nm, 63);                       /* DeviceName */
	strncpy((char *)d + 228, "OpenWrt", 63);                /* ManufacturerName */
	strncpy((char *)d + 292, "vbanhub", 63);                /* ApplicationName */
	gethostname((char *)d + 356, 63);                       /* HostName */
	strncpy((char *)d + 420, nm, 127);                      /* UserName */
	strncpy((char *)d + 548, "VBAN router: send streams here, receive them from here", 127); /* UserComment */
}

static void send_scan(int fd)
{
	uint8_t pkt[SVC_PKT];
	uint32_t dest[MAX_DEST];
	struct sockaddr_in to = { .sin_family = AF_INET };
	int nd = 0, i, j;
	time_t now = time(NULL);

	refresh_ifaces();
	if (!nifaces) /* never broadcast on the default-route (WAN) interface when a selection exists */
		dest[nd++] = htonl(INADDR_BROADCAST);
	for (i = 0; i < nbcast && nd < MAX_DEST; i++)
		dest[nd++] = bcast_ip[i];
	for (i = 0; i < nextra && nd < MAX_DEST; i++)
		dest[nd++] = extra_dest[i];
	scan_id = scan_id ? scan_id + 1 : (uint32_t)now;
	scan_until = now + 5;
	last_scan = now;
	fill_ping(pkt, 0, scan_id, NULL);
	for (i = 0; i < nd; i++)
		for (j = 0; j < nports; j++) {
			to.sin_addr.s_addr = dest[i];
			to.sin_port = htons(scan_ports[j]);
			sendto(fd, pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&to, sizeof(to));
		}
}

static void copy_str(char *dst, const uint8_t *src, size_t n)
{
	size_t i;
	for (i = 0; i < n - 1 && src[i]; i++)
		dst[i] = (src[i] >= 32 && src[i] < 127) ? src[i] : '?';
	dst[i] = 0;
}

static void record_disc(const struct sockaddr_in *from, const uint8_t *d, time_t now)
{
	int i, o = 0;
	uint32_t v;

	for (i = 0; i < ndisc; i++)
		if (disc[i].ip == from->sin_addr.s_addr && disc[i].port == ntohs(from->sin_port))
			goto fill;
	if (ndisc < MAX_DISC) {
		i = ndisc++;
	} else {
		for (i = 1; i < MAX_DISC; i++)
			if (disc[i].last_seen < disc[o].last_seen)
				o = i;
		i = o;
	}
fill:
	memset(&disc[i], 0, sizeof(disc[i]));
	disc[i].ip = from->sin_addr.s_addr;
	disc[i].port = ntohs(from->sin_port);
	memcpy(&v, d, 4);
	disc[i].type = le32toh(v);
	memcpy(&v, d + 4, 4);
	disc[i].feat = le32toh(v);
	copy_str(disc[i].device, d + 164, sizeof(disc[i].device));
	copy_str(disc[i].app, d + 292, sizeof(disc[i].app));
	copy_str(disc[i].host, d + 356, sizeof(disc[i].host));
	copy_str(disc[i].user, d + 420, sizeof(disc[i].user));
	disc[i].last_seen = now;
}

static void handle_service(int fd, const uint8_t *p, unsigned len, const struct sockaddr_in *from, time_t now)
{
	static time_t rl_sec;
	static int rl_cnt;
	uint8_t rep[SVC_PKT];
	uint32_t fc;

	if (p[6] != 0 || (p[5] & 0x7f) != 0)
		return;
	memcpy(&fc, p + 24, 4);
	fc = le32toh(fc);
	if (p[5] & 0x80) {                      /* reply to our scan: needs the full struct */
		if (len < SVC_PKT || fc != scan_id || now > scan_until)
			return;
		record_disc(from, p + VBAN_HDR, now);
		return;
	}
	/* Request: answer header-only pings too (some apps send just the header), so the hub shows up
	 * in their device lists. Bounded by the global limit below and by the ingress-interface filter. */
	/* request: ignore our own looped-back broadcast, rate-limit replies */
	if (is_local(from->sin_addr.s_addr) && ntohs(from->sin_port) == listen_port)
		return;
	if (len >= SVC_PKT)   /* a device announcing itself with a full PING0: remember it, no scan needed */
		record_disc(from, p + VBAN_HDR, now);
	if (rl_sec != now) {
		rl_sec = now;
		rl_cnt = 0;
	}
	if (++rl_cnt > 20)
		return;
	fill_ping(rep, 1, fc, p + 8);
	sendto(fd, rep, sizeof(rep), MSG_DONTWAIT, (const struct sockaddr *)from, sizeof(*from));
}

/* Scale PCM samples of an audio packet by gain/100 into dst (a private copy of the payload).
 * Supports uint8, int16, int24, int32, float32, float64 (VBAN little-endian); anything else
 * (other sub-protocol, non-PCM codec, 12/10-bit) is left untouched and returns 0. Fixed point (Q14)
 * for the integer formats so it is cheap on routers without an FPU; integer results saturate. */
static int apply_gain(uint8_t *dst, const uint8_t *src, unsigned n, const uint8_t *h, unsigned gain)
{
	unsigned fmt = h[7] & 0x07, bps, cnt, i;
	int64_t g = (int64_t)gain * 16384 / 100;

	if ((h[4] & 0xE0) || (h[7] & 0xF0))
		return 0;
	switch (fmt) {
	case 0: bps = 1; break;
	case 1: bps = 2; break;
	case 2: bps = 3; break;
	case 3: case 4: bps = 4; break;
	case 5: bps = 8; break;
	default: return 0;
	}
	cnt = (unsigned)(h[5] + 1) * (unsigned)(h[6] + 1);
	if (cnt * bps > n)
		cnt = n / bps;
	memcpy(dst, src, n);
	for (i = 0; i < cnt; i++) {
		uint8_t *b = dst + (size_t)i * bps;
		int64_t v;

		switch (fmt) {
		case 0:
			v = (((int64_t)b[0] - 128) * g) >> 14;
			b[0] = (uint8_t)((v > 127 ? 127 : (v < -128 ? -128 : v)) + 128);
			break;
		case 1:
			v = ((int64_t)(int16_t)(b[0] | b[1] << 8) * g) >> 14;
			v = v > 32767 ? 32767 : (v < -32768 ? -32768 : v);
			b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF;
			break;
		case 2:
			v = (int32_t)((uint32_t)b[0] << 8 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 24) >> 8;
			v = (v * g) >> 14;
			v = v > 8388607 ? 8388607 : (v < -8388608 ? -8388608 : v);
			b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF; b[2] = (v >> 16) & 0xFF;
			break;
		case 3:
			v = ((int64_t)(int32_t)((uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24) * g) >> 14;
			v = v > 2147483647LL ? 2147483647LL : (v < -2147483648LL ? -2147483648LL : v);
			b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF; b[2] = (v >> 16) & 0xFF; b[3] = (v >> 24) & 0xFF;
			break;
		case 4: {
			uint32_t u = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
			float x;
			memcpy(&x, &u, 4);
			x *= (float)gain / 100.0f;
			memcpy(&u, &x, 4);
			b[0] = u & 0xFF; b[1] = (u >> 8) & 0xFF; b[2] = (u >> 16) & 0xFF; b[3] = (u >> 24) & 0xFF;
			break;
		}
		case 5: {
			uint64_t u = 0;
			double x;
			int k;
			for (k = 7; k >= 0; k--)
				u = u << 8 | b[k];
			memcpy(&x, &u, 8);
			x *= (double)gain / 100.0;
			memcpy(&u, &x, 8);
			for (k = 0; k < 8; k++, u >>= 8)
				b[k] = u & 0xFF;
			break;
		}
		}
	}
	return 1;
}

/* 0 unicast, 1 broadcast, 2 multicast, from the datagram's destination address */
static int dst_kind(uint32_t a)
{
	int i;
	if ((ntohl(a) >> 28) == 0xE)
		return 2;
	if (a == htonl(INADDR_BROADCAST))
		return 1;
	for (i = 0; i < nbcast; i++)
		if (bcast_ip[i] == a)
			return 1;
	return 0;
}

/* Record/refresh a heard stream (routed or not). Fast path: same entry as the previous packet. */
static void note_stream(uint32_t ip, uint16_t port_be, const uint8_t *p, unsigned len, int kind, int routed, time_t now)
{
	static int last = -1;
	struct stream *s;
	int i;

	if (last >= 0 && last < nstreams && streams[last].ip == ip && !memcmp(streams[last].name, p + 8, NAME_LEN)) {
		i = last;
		goto hit;
	}
	for (i = 0; i < nstreams; i++)
		if (streams[i].ip == ip && !memcmp(streams[i].name, p + 8, NAME_LEN))
			goto found;
	if (nstreams < MAX_STREAMS) {
		i = nstreams++;
	} else { /* evict the least recently heard */
		int o = 0;
		for (i = 1; i < MAX_STREAMS; i++)
			if (streams[i].last_seen < streams[o].last_seen)
				o = i;
		i = o;
	}
	memset(&streams[i], 0, sizeof(streams[i]));
	streams[i].ip = ip;
	memcpy(streams[i].name, p + 8, NAME_LEN);
	streams[i].first_seen = streams[i].snap_ts = now;
found:
	last = i;
hit:
	s = &streams[i];
	s->port = ntohs(port_be);
	s->sr = p[4]; s->nbs = p[5]; s->nbc = p[6]; s->bit = p[7];
	s->kind = kind;
	s->routed = routed;
	s->pkts++;
	s->bytes += len;
	s->last_seen = now;
}

static const unsigned sr_hz[21] = { 6000, 12000, 24000, 48000, 96000, 192000, 384000, 8000, 16000, 32000,
	64000, 128000, 256000, 512000, 11025, 22050, 44100, 88200, 176400, 352800, 705600 };

static void json_name(FILE *f, const char *n, int len)
{
	int i;
	fputc('"', f);
	for (i = 0; i < len && n[i]; i++) {
		unsigned char c = n[i];
		if (c == '"' || c == '\\')
			fputc('\\', f);
		fputc(c >= 32 && c < 127 ? c : '?', f);
	}
	fputc('"', f);
}

static void dump_status(void)
{
	char tmp[128];
	char ip[INET_ADDRSTRLEN];
	FILE *f;
	int i;
	time_t now = time(NULL);

	snprintf(tmp, sizeof(tmp), "%s.tmp", stat_path);
	f = fopen(tmp, "w");
	if (!f)
		return;
	fprintf(f, "{\"uptime\":%ld,\"rx\":%llu,\"bad\":%llu,\"unknown\":%llu,\"tx\":%llu,\"txerr\":%llu,\"filtered\":%llu,\"master\":%u,\"listen\":[",
		(long)(now - started), (unsigned long long)st_rx, (unsigned long long)st_bad,
		(unsigned long long)st_unknown, (unsigned long long)st_tx, (unsigned long long)st_txerr,
		(unsigned long long)st_filtered, master_gain);
	for (i = 0; i < nifaces; i++) {
		fprintf(f, "%s{\"name\":", i ? "," : "");
		json_name(f, ifaces[i], 32);
		fprintf(f, ",\"up\":%d}", ifidx[i] ? 1 : 0);
	}
	fputs("],\"routes\":[", f);
	for (i = 0; i < nroutes; i++) {
		struct route *r = &routes[i];
		struct in_addr a = { r->src_ip };
		fprintf(f, "%s{\"src\":\"%s\",\"src_stream\":", i ? "," : "",
			r->src_ip ? inet_ntoa(a) : "*");
		if (r->src_any_name)
			fputs("\"*\"", f);
		else
			json_name(f, r->src_name, NAME_LEN);
		inet_ntop(AF_INET, &r->dst.sin_addr, ip, sizeof(ip));
		fprintf(f, ",\"dst\":\"%s\",\"dst_port\":%u,\"dst_stream\":", ip, ntohs(r->dst.sin_port));
		json_name(f, r->dst_name, NAME_LEN);
		fprintf(f, ",\"gain\":%u,\"pkts\":%llu,\"bytes\":%llu,\"lost\":%llu,\"age\":%ld}",
			r->gain, (unsigned long long)r->pkts, (unsigned long long)r->bytes,
			(unsigned long long)r->lost, r->last_seen ? (long)(now - r->last_seen) : -1L);
	}
	fputs("],\"streams\":[", f);
	for (i = 0; i < nstreams; i++) {
		struct stream *s = &streams[i];
		struct in_addr a = { s->ip };
		long dt = (long)(now - s->snap_ts);
		unsigned idx = s->sr & 0x1F;

		if (dt >= 1) {
			s->rate = (unsigned)((s->pkts - s->snap_pkts) / dt);
			s->snap_pkts = s->pkts;
			s->snap_ts = now;
		}
		fprintf(f, "%s{\"ip\":\"%s\",\"port\":%u,\"stream\":", i ? "," : "", inet_ntoa(a), s->port);
		json_name(f, s->name, NAME_LEN);
		fprintf(f, ",\"sub\":%u,\"hz\":%u,\"samples\":%u,\"channels\":%u,\"fmt\":%u,\"codec\":%u,"
			"\"kind\":%u,\"routed\":%u,\"pkts\":%llu,\"bytes\":%llu,\"rate\":%u,\"age\":%ld}",
			s->sr & 0xE0, idx < 21 ? sr_hz[idx] : 0, s->nbs + 1, s->nbc + 1, s->bit & 0x07, s->bit & 0xF0,
			s->kind, s->routed, (unsigned long long)s->pkts, (unsigned long long)s->bytes, s->rate,
			(long)(now - s->last_seen));
	}
	fputs("],\"discovered\":[", f);
	for (i = 0; i < ndisc; i++) {
		struct in_addr a = { disc[i].ip };
		fprintf(f, "%s{\"ip\":\"%s\",\"port\":%u,\"type\":%u,\"feat\":%u,\"device\":",
			i ? "," : "", inet_ntoa(a), disc[i].port, disc[i].type, disc[i].feat);
		json_name(f, disc[i].device, 64);
		fputs(",\"app\":", f);
		json_name(f, disc[i].app, 64);
		fputs(",\"host\":", f);
		json_name(f, disc[i].host, 64);
		fputs(",\"user\":", f);
		json_name(f, disc[i].user, 64);
		fprintf(f, ",\"age\":%ld}", (long)(now - disc[i].last_seen));
	}
	fprintf(f, "],\"scan\":{\"active\":%d,\"age\":%ld}}\n", now <= scan_until && last_scan,
		last_scan ? (long)(now - last_scan) : -1L);
	fclose(f);
	rename(tmp, stat_path);
}

int main(int argc, char **argv)
{
	static uint8_t bufs[BATCH][VBAN_MAX];
	static uint8_t hdrs[MAX_FANOUT][VBAN_HDR];
	static uint8_t scratch[MAX_FANOUT][VBAN_MAX];   /* gain-adjusted payload copies */
	static char cbuf[BATCH][64];
	struct sockaddr_in addrs[BATCH], me = { .sin_family = AF_INET };
	struct mmsghdr rx[BATCH], tx[MAX_FANOUT];
	struct iovec riov[BATCH], tiov[MAX_FANOUT][2];
	struct sigaction sa = { .sa_handler = on_sig }; /* no SA_RESTART */
	int port = 6980, tos = 0xB8, rcvbuf = 65536, prio = 6, c, fd, i;
	time_t last_dump = 0, last_resolve = 0;
	struct pollfd pfd;

	while ((c = getopt(argc, argv, "p:c:s:t:i:S:T:P:N:")) != -1) {
		switch (c) {
		case 'S': scan_interval = atoi(optarg); break;
		case 'N': hub_name = optarg; break;
		case 'T': {
			struct in_addr a;
			if (inet_aton(optarg, &a) && nextra < 8)
				extra_dest[nextra++] = a.s_addr;
			break;
		}
		case 'P': {
			char *tok, *sv;
			nports = 0;
			for (tok = strtok_r(optarg, ",", &sv); tok && nports < MAX_PORTS; tok = strtok_r(NULL, ",", &sv))
				if (atoi(tok) > 0 && atoi(tok) < 65536)
					scan_ports[nports++] = atoi(tok);
			if (!nports) {
				nports = 1;
				scan_ports[0] = 6980;
			}
			break;
		}
		case 'i':
			if (strcmp(optarg, "*") && nifaces < MAX_IFACES)
				ifaces[nifaces++] = optarg;
			break;
		case 'p': port = atoi(optarg); break;
		case 'c': cfg_path = optarg; break;
		case 's': stat_path = optarg; break;
		case 't': tos = atoi(optarg) << 2; break; /* DSCP value */
		default:
			fprintf(stderr, "usage: %s [-p port] [-c conf] [-s statusfile] [-t dscp]\n", argv[0]);
			return 1;
		}
	}
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	listen_port = port;
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &(int){ 1 }, sizeof(int));
	setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &(int){ 1 }, sizeof(int));
	resolve_ifaces();
	me.sin_addr.s_addr = htonl(INADDR_ANY);
	me.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&me, sizeof(me))) {
		perror("bind");
		return 1;
	}
	started = time(NULL);
	refresh_ifaces();
	if (load_config() < 0)
		fprintf(stderr, "vbanhub: cannot read %s, starting with no routes\n", cfg_path);
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!want_quit) {
		int n;
		time_t now = time(NULL);

		if (nifaces && now - last_resolve >= 3) {  /* interfaces may appear later (e.g. after ifup) */
			resolve_ifaces();
			last_resolve = now;
		}
		if (want_reload) {
			want_reload = 0;
			load_config();
		}
		/* A requested scan (button / SIGUSR1) is never dropped: within 3 s of the previous scan it is
		 * deferred to the next loop iteration (<= 1 s later) instead of being ignored. */
		if (want_scan && now - last_scan >= 3) {
			want_scan = 0;
			send_scan(fd);
		} else if (scan_interval && now - last_scan >= scan_interval) {
			send_scan(fd);
		}
		if (now - last_dump >= 2) {
			dump_status();
			last_dump = now;
		}
		if (poll(&pfd, 1, 1000) <= 0)
			continue;

		for (i = 0; i < BATCH; i++) {
			riov[i].iov_base = bufs[i];
			riov[i].iov_len = VBAN_MAX;
			memset(&rx[i], 0, sizeof(rx[i]));
			rx[i].msg_hdr.msg_iov = &riov[i];
			rx[i].msg_hdr.msg_iovlen = 1;
			rx[i].msg_hdr.msg_name = &addrs[i];
			rx[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
			rx[i].msg_hdr.msg_control = cbuf[i];
			rx[i].msg_hdr.msg_controllen = sizeof(cbuf[i]);
		}
		n = recvmmsg(fd, rx, BATCH, MSG_DONTWAIT, NULL);
		for (i = 0; i < n; i++) {
			uint8_t *p = bufs[i];
			unsigned len = rx[i].msg_len;
			uint32_t sip = addrs[i].sin_addr.s_addr, fc;
			int k, nt = 0, r;

			uint32_t dstaddr;

			if (!if_allowed(ingress_info(&rx[i].msg_hdr, &dstaddr))) {
				st_filtered++;
				continue;
			}
			st_rx++;
			if ((rx[i].msg_hdr.msg_flags & MSG_TRUNC) || len < VBAN_HDR ||
			    memcmp(p, "VBAN", 4)) {
				st_bad++;
				continue;
			}
			if ((p[4] & 0xE0) == 0x60) {      /* SERVICE: handled by the hub, never routed */
				handle_service(fd, p, len, &addrs[i], now);
				continue;
			}
			memcpy(&fc, p + 24, 4);
			fc = le32toh(fc);
			for (r = 0; r < nroutes && nt < MAX_FANOUT; r++) {
				struct route *rt = &routes[r];
				if (rt->src_ip && rt->src_ip != sip)
					continue;
				if (!rt->src_any_name && memcmp(rt->src_name, p + 8, NAME_LEN))
					continue;
				memcpy(hdrs[nt], p, VBAN_HDR);
				memcpy(hdrs[nt] + 8, rt->dst_name, NAME_LEN);
				tiov[nt][0].iov_base = hdrs[nt];
				tiov[nt][0].iov_len = VBAN_HDR;
				tiov[nt][1].iov_base = p + VBAN_HDR;
				tiov[nt][1].iov_len = len - VBAN_HDR;
				{
					unsigned eg = (rt->gain * master_gain + 50) / 100;   /* route x master, percent */
					if (eg != 100 && apply_gain(scratch[nt], p + VBAN_HDR, len - VBAN_HDR, p, eg))
						tiov[nt][1].iov_base = scratch[nt];
				}
				memset(&tx[nt], 0, sizeof(tx[nt]));
				tx[nt].msg_hdr.msg_iov = tiov[nt];
				tx[nt].msg_hdr.msg_iovlen = 2;
				tx[nt].msg_hdr.msg_name = &rt->dst;
				tx[nt].msg_hdr.msg_namelen = sizeof(rt->dst);
				if (rt->have_fc && fc > rt->last_fc + 1 && fc - rt->last_fc < 100000)
					rt->lost += fc - rt->last_fc - 1;
				rt->last_fc = fc;
				rt->have_fc = 1;
				rt->pkts++;
				rt->bytes += len;
				rt->last_seen = now;
				nt++;
			}
			note_stream(sip, addrs[i].sin_port, p, len, dst_kind(dstaddr), nt > 0, now);
			if (!nt) {
				st_unknown++;
				continue;
			}
			k = sendmmsg(fd, tx, nt, MSG_DONTWAIT);
			if (k < 0)
				st_txerr += nt;
			else {
				st_tx += k;
				st_txerr += nt - k;
			}
		}
	}
	unlink(stat_path);   /* no status file = not running (LuCI shows it) */
	return 0;
}
