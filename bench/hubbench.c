/*
 * hubbench - latency / throughput load generator for vbanhub.
 *
 *   hubbench tx <dst_ip> <dst_port> <streams> <pps_per_stream> <seconds> [payload_bytes]
 *       Sends <streams> VBAN audio streams named "Bench0".."BenchN" to the hub (one socket
 *       each, so each has its own source port). Each payload starts with the send time
 *       (CLOCK_MONOTONIC ns) and the stream index. Packets are paced evenly.
 *   hubbench rx <first_port> <nports> <seconds> [expect_name[,name_for_port2,...]]
 *       Receives on <nports> consecutive ports and prints one-way latency percentiles
 *       (sender and receiver must share CLOCK_MONOTONIC: same host / VM), packets, loss
 *       (per stream per port, from the VBAN frame counter) and name errors.
 *
 * Both run until <seconds> have elapsed. Build: cc -O2 -o hubbench hubbench.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAXS 256
#define MAXP 64
#define LAT_BINS 200000   /* 0.1 us bins up to 20 ms */

static uint64_t now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

static int do_tx(int argc, char **argv)
{
	const char *ip = argv[2];
	int port = atoi(argv[3]), ns = atoi(argv[4]), pps = atoi(argv[5]), secs = atoi(argv[6]);
	int plen = argc > 7 ? atoi(argv[7]) : 256;
	static int fd[MAXS];
	static uint32_t fc[MAXS];
	struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(port) };
	uint8_t pkt[1464];
	uint64_t t0, period, next, sent = 0, errs = 0;
	int i, tos = 0xB8;

	if (ns < 1 || ns > MAXS || pps < 1 || plen < 16 || plen > 1436 || !inet_aton(ip, &d.sin_addr))
		return fprintf(stderr, "bad args\n"), 1;
	for (i = 0; i < ns; i++) {
		fd[i] = socket(AF_INET, SOCK_DGRAM, 0);
		setsockopt(fd[i], IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	}
	memset(pkt, 0, sizeof(pkt));
	memcpy(pkt, "VBAN", 4);
	pkt[4] = 3;            /* 48 kHz, AUDIO */
	pkt[5] = 63;           /* 64 frames */
	pkt[6] = 1;            /* 2 channels */
	pkt[7] = 1;            /* int16 */
	period = 1000000000ull / ((uint64_t)pps * ns);   /* one packet of any stream per period */
	t0 = next = now_ns();
	while (now_ns() - t0 < (uint64_t)secs * 1000000000ull) {
		uint64_t t;
		int s = (int)(sent % ns);
		if (now_ns() < next) {   /* sleep, never spin: keeps the sender's CPU out of the measurement */
			struct timespec w = { (time_t)(next / 1000000000ull), (long)(next % 1000000000ull) };
			clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &w, NULL);
		}
		snprintf((char *)pkt + 8, 17, "Bench%d", s);
		memcpy(pkt + 24, &fc[s], 4);
		fc[s]++;
		t = now_ns();
		memcpy(pkt + 28, &t, 8);
		memcpy(pkt + 36, &s, 4);
		if (sendto(fd[s], pkt, 28 + plen, 0, (struct sockaddr *)&d, sizeof(d)) < 0 && errs++ == 0)
			perror("tx: sendto");
		sent++;
		next += period;
	}
	printf("tx: %llu packets (%llu send errors), %d streams x %d pps\n", (unsigned long long)sent, (unsigned long long)errs, ns, pps);
	return 0;
}

static int do_rx(int argc, char **argv)
{
	int first = atoi(argv[2]), np = atoi(argv[3]), secs = atoi(argv[4]);
	char *want[MAXP] = { 0 };
	static uint32_t hist[LAT_BINS + 1];
	static uint32_t last_fc[MAXP][MAXS];
	static uint8_t have[MAXP][MAXS];
	struct pollfd pfd[MAXP];
	uint64_t t0, pkts = 0, lost = 0, badname = 0, sum = 0, over = 0;
	uint8_t buf[2048];
	int i;

	if (np < 1 || np > MAXP)
		return fprintf(stderr, "bad args\n"), 1;
	if (argc > 5) {   /* one expected name per port; the last one repeats */
		char *sv, *tok = strtok_r(argv[5], ",", &sv);
		for (i = 0; i < np; i++) {
			want[i] = tok ? tok : want[i - 1];
			if (tok)
				tok = strtok_r(NULL, ",", &sv);
		}
	}
	for (i = 0; i < np; i++) {
		struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(first + i) };
		int rb = 4 << 20;
		pfd[i].fd = socket(AF_INET, SOCK_DGRAM, 0);
		pfd[i].events = POLLIN;
		setsockopt(pfd[i].fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
		if (bind(pfd[i].fd, (struct sockaddr *)&a, sizeof(a)))
			return perror("bind"), 1;
	}
	t0 = now_ns();
	while (now_ns() - t0 < (uint64_t)secs * 1000000000ull) {
		if (poll(pfd, np, 100) <= 0)
			continue;
		for (i = 0; i < np; i++) {
			ssize_t n;
			while (!!(pfd[i].revents & POLLIN) && (n = recv(pfd[i].fd, buf, sizeof(buf), MSG_DONTWAIT)) >= 40) {
				uint64_t ts, lat, t = now_ns();
				uint32_t fc;
				int s;
				memcpy(&ts, buf + 28, 8);
				memcpy(&s, buf + 36, 4);
				memcpy(&fc, buf + 24, 4);
				lat = t - ts;
				sum += lat;
				if (lat / 100 < LAT_BINS)
					hist[lat / 100]++;
				else
					over++;
				pkts++;
				if (want[i] && strncmp((char *)buf + 8, want[i], 16))
					badname++;
				if (s >= 0 && s < MAXS) {
					if (have[i][s] && fc > last_fc[i][s] + 1)
						lost += fc - last_fc[i][s] - 1;
					last_fc[i][s] = fc;
					have[i][s] = 1;
				}
			}
		}
	}
	if (!pkts)
		return printf("rx: no packets\n"), 1;
	{
		double pct[] = { 50, 90, 99, 99.9, 100 };
		uint64_t acc = 0;
		unsigned k = 0, b;
		printf("rx: %llu packets, lost %llu, bad name %llu, mean %.1f us,", (unsigned long long)pkts,
		       (unsigned long long)lost, (unsigned long long)badname, sum / 1000.0 / pkts);
		for (b = 0; b < LAT_BINS && k < 5; b++) {
			acc += hist[b];
			while (k < 5 && acc >= (uint64_t)(pct[k] / 100.0 * (pkts - over))) {
				printf(" p%g %.1f", pct[k], b / 10.0);
				k++;
			}
		}
		printf(" us%s\n", over ? " (some > 20 ms)" : "");
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc >= 7 && !strcmp(argv[1], "tx"))
		return do_tx(argc, argv);
	if (argc >= 5 && !strcmp(argv[1], "rx"))
		return do_rx(argc, argv);
	fprintf(stderr, "usage: hubbench tx <ip> <port> <streams> <pps> <secs> [bytes] | rx <port> <nports> <secs> [name]\n");
	return 2;
}
