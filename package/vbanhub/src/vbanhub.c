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
static volatile sig_atomic_t want_reload, want_quit;
static const char *cfg_path = "/var/etc/vbanhub.conf";
static const char *stat_path = "/var/run/vbanhub/status.json";
static const char *iface;       /* SO_BINDTODEVICE; NULL = all interfaces */
static int listen_port = 6980;
static time_t started;

static void on_sig(int s)
{
	if (s == SIGHUP)
		want_reload = 1;
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
	fputs("]}\n", f);
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

	while ((c = getopt(argc, argv, "p:c:s:t:i:")) != -1) {
		switch (c) {
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
