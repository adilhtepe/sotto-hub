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
#define MAX_LEARN 32
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
};

struct learned {
	uint32_t ip;
	char name[NAME_LEN + 1];
	uint8_t sr, nbs, nbc, bit;
	uint64_t pkts;
	time_t last_seen;
};

static struct route routes[MAX_ROUTES];
static int nroutes;
static struct learned learn[MAX_LEARN];
static int nlearn;
static uint64_t st_rx, st_bad, st_unknown, st_tx, st_txerr;
static volatile sig_atomic_t want_reload, want_quit, want_scan;
static const char *cfg_path = "/var/etc/vbanhub.conf";
static const char *stat_path = "/var/run/vbanhub/status.json";
static const char *iface;       /* SO_BINDTODEVICE; NULL = all interfaces */
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

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f) && n < MAX_ROUTES) {
		char sip[32], sname[64], dip[32], dname[64];
		int dport;
		struct route *r;
		struct in_addr a;

		if (line[0] == '#')
			continue;
		if (sscanf(line, "route %31s %63s %31s %d %63s", sip, sname, dip, &dport, dname) != 5)
			continue;
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
		n++;
	}
	fclose(f);
	nroutes = n;
	return n;
}

static void note_unknown(uint32_t ip, const uint8_t *p)
{
	int i;
	time_t now = time(NULL);

	for (i = 0; i < nlearn; i++)
		if (learn[i].ip == ip && !memcmp(learn[i].name, p + 8, NAME_LEN))
			goto hit;
	if (nlearn < MAX_LEARN) {
		i = nlearn++;
	} else { /* evict oldest */
		int o = 0;
		for (i = 1; i < MAX_LEARN; i++)
			if (learn[i].last_seen < learn[o].last_seen)
				o = i;
		i = o;
	}
	memset(&learn[i], 0, sizeof(learn[i]));
	learn[i].ip = ip;
	memcpy(learn[i].name, p + 8, NAME_LEN);
hit:
	learn[i].sr = p[4];
	learn[i].nbs = p[5];
	learn[i].nbc = p[6];
	learn[i].bit = p[7];
	learn[i].pkts++;
	learn[i].last_seen = now;
}


/* ---- LAN discovery via VBAN PING0 (service identification), spec rev 13 ----
 * Request/reply = 28-byte header (sub-protocol 0x60, nbc=0 service, nbs=0 ping /
 * 0x80 reply, frame counter = request id) + 676-byte tagVBAN_PING0 struct. */
#define SVC_LEN 676
#define SVC_PKT (VBAN_HDR + SVC_LEN)
#define MAX_DISC 64
#define MAX_DEST 24
#define MAX_PORTS 8
#define PING_TYPE_SERVER 0x01000000u

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
		    (!iface || !strcmp(q->ifa_name, iface)))
			bcast_ip[nbcast++] = ((struct sockaddr_in *)q->ifa_broadaddr)->sin_addr.s_addr;
	}
	freeifaddrs(ifa);
}

static void fill_ping(uint8_t *pkt, int reply, uint32_t fc)
{
	uint8_t *d = pkt + VBAN_HDR;
	uint32_t v;

	memset(pkt, 0, SVC_PKT);
	memcpy(pkt, "VBAN", 4);
	pkt[4] = 0x60;                 /* SERVICE */
	pkt[5] = reply ? 0x80 : 0;     /* function PING0 (+ reply bit) */
	pkt[6] = 0;                    /* service IDENTIFICATION */
	memcpy(pkt + 8, "VBANHUB PING", 12);
	v = htole32(fc);
	memcpy(pkt + 24, &v, 4);
	v = htole32(PING_TYPE_SERVER);
	memcpy(d, &v, 4);
	v = htole32(0x00000001u | 0x00000100u | 0x00010000u); /* audio, serial, text */
	memcpy(d + 4, &v, 4);
	d[29] = 1;                                              /* nVersion 0.1.0.0 */
	strncpy((char *)d + 164, "OpenWrt VBAN hub", 63);       /* DeviceName */
	strncpy((char *)d + 292, "vbanhub", 63);                /* ApplicationName */
	gethostname((char *)d + 356, 63);                       /* HostName */
}

static void send_scan(int fd)
{
	uint8_t pkt[SVC_PKT];
	uint32_t dest[MAX_DEST];
	struct sockaddr_in to = { .sin_family = AF_INET };
	int nd = 0, i, j;
	time_t now = time(NULL);

	refresh_ifaces();
	dest[nd++] = htonl(INADDR_BROADCAST);
	for (i = 0; i < nbcast && nd < MAX_DEST; i++)
		dest[nd++] = bcast_ip[i];
	for (i = 0; i < nextra && nd < MAX_DEST; i++)
		dest[nd++] = extra_dest[i];
	scan_id = scan_id ? scan_id + 1 : (uint32_t)now;
	scan_until = now + 5;
	last_scan = now;
	fill_ping(pkt, 0, scan_id);
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

	/* Only full PING0 packets (header + struct); anything shorter is ignored,
	 * which also keeps replies from ever being larger than the request. */
	if (p[6] != 0 || (p[5] & 0x7f) != 0 || len < SVC_PKT)
		return;
	memcpy(&fc, p + 24, 4);
	fc = le32toh(fc);
	if (p[5] & 0x80) {                      /* reply to our scan */
		if (fc != scan_id || now > scan_until)
			return;
		record_disc(from, p + VBAN_HDR, now);
		return;
	}
	/* request: ignore our own looped-back broadcast, rate-limit replies */
	if (is_local(from->sin_addr.s_addr) && ntohs(from->sin_port) == listen_port)
		return;
	if (rl_sec != now) {
		rl_sec = now;
		rl_cnt = 0;
	}
	if (++rl_cnt > 20)
		return;
	fill_ping(rep, 1, fc);
	sendto(fd, rep, sizeof(rep), MSG_DONTWAIT, (const struct sockaddr *)from, sizeof(*from));
}

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
	fprintf(f, "{\"uptime\":%ld,\"rx\":%llu,\"bad\":%llu,\"unknown\":%llu,\"tx\":%llu,\"txerr\":%llu,\"routes\":[",
		(long)(now - started), (unsigned long long)st_rx, (unsigned long long)st_bad,
		(unsigned long long)st_unknown, (unsigned long long)st_tx, (unsigned long long)st_txerr);
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
		fprintf(f, ",\"pkts\":%llu,\"bytes\":%llu,\"lost\":%llu,\"age\":%ld}",
			(unsigned long long)r->pkts, (unsigned long long)r->bytes,
			(unsigned long long)r->lost, r->last_seen ? (long)(now - r->last_seen) : -1L);
	}
	fputs("],\"learned\":[", f);
	for (i = 0; i < nlearn; i++) {
		struct in_addr a = { learn[i].ip };
		fprintf(f, "%s{\"ip\":\"%s\",\"stream\":", i ? "," : "", inet_ntoa(a));
		json_name(f, learn[i].name, NAME_LEN);
		fprintf(f, ",\"sr\":%u,\"nbs\":%u,\"nbc\":%u,\"bit\":%u,\"pkts\":%llu,\"age\":%ld}",
			learn[i].sr, learn[i].nbs, learn[i].nbc, learn[i].bit,
			(unsigned long long)learn[i].pkts, (long)(now - learn[i].last_seen));
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
	struct sockaddr_in addrs[BATCH], me = { .sin_family = AF_INET };
	struct mmsghdr rx[BATCH], tx[MAX_FANOUT];
	struct iovec riov[BATCH], tiov[MAX_FANOUT][2];
	struct sigaction sa = { .sa_handler = on_sig }; /* no SA_RESTART */
	int port = 6980, tos = 0xB8, rcvbuf = 65536, prio = 6, c, fd, i;
	time_t last_dump = 0;
	struct pollfd pfd;

	while ((c = getopt(argc, argv, "p:c:s:t:i:S:T:P:")) != -1) {
		switch (c) {
		case 'S': scan_interval = atoi(optarg); break;
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
		case 'i': iface = strcmp(optarg, "*") ? optarg : NULL; break;
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
	if (iface && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1)) {
		perror("SO_BINDTODEVICE"); /* fail closed: never fall back to all interfaces */
		return 1;
	}
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

		if (want_reload) {
			want_reload = 0;
			load_config();
		}
		if ((want_scan && now - last_scan >= 3) || (scan_interval && now - last_scan >= scan_interval))
			send_scan(fd);
		want_scan = 0;
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
		}
		n = recvmmsg(fd, rx, BATCH, MSG_DONTWAIT, NULL);
		for (i = 0; i < n; i++) {
			uint8_t *p = bufs[i];
			unsigned len = rx[i].msg_len;
			uint32_t sip = addrs[i].sin_addr.s_addr, fc;
			int k, nt = 0, r;

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
			if (!nt) {
				st_unknown++;
				note_unknown(sip, p);
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
	dump_status();
	return 0;
}
