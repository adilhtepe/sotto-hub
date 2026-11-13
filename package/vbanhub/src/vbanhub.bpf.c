// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * vbanhub tc fast path: fans VBAN packets out to their routes inside the kernel.
 *
 * Attached on tc ingress (clsact) of each listen interface. For a VBAN packet sent to
 * the hub (to one of its addresses or a broadcast address, on the hub port) whose
 * route keys are all "fast", it rewrites the packet once per destination (Ethernet,
 * IP, UDP ports and the 16-byte stream name, checksums updated) and sends a clone out
 * of the egress interface found by a FIB lookup. The original is then dropped.
 *
 * Everything else goes up to the daemon unchanged (TC_ACT_OK), which keeps handling:
 * SERVICE packets (PING0), unrouted senders (learning), routes with a gain other than
 * 100 %, destinations that are local or whose neighbour is not resolved yet, IP
 * options, fragments, VLAN tags, GRO-merged skbs, and all of it when IPv4 forwarding is off on the
 * ingress interface (the FIB lookup is a forwarding one). So the daemon alone is always a complete hub; this
 * program only takes work off it.
 *
 * Note: tc ingress runs before netfilter, so packets handled here skip the firewall's
 * INPUT/OUTPUT/FORWARD chains. Only (source, stream) pairs the daemon put in the
 * route map are forwarded, to the destinations it validated.
 *
 * Build: clang -O2 -g -target bpf -c vbanhub.bpf.c -o vbanhub.bpf.o
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include "vbanhub_bpf.h"

#define SEC(n) __attribute__((section(n), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define INL static __attribute__((always_inline)) inline

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define H16(x) __builtin_bswap16(x)
#else
#define H16(x) (x)
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
	(void *)BPF_FUNC_map_update_elem;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 off, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static long (*bpf_skb_store_bytes)(void *skb, __u32 off, const void *from, __u32 len, __u64 flags) =
	(void *)BPF_FUNC_skb_store_bytes;
static long (*bpf_l4_csum_replace)(void *skb, __u32 off, __u64 from, __u64 to, __u64 flags) =
	(void *)BPF_FUNC_l4_csum_replace;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) =
	(void *)BPF_FUNC_csum_diff;
static long (*bpf_clone_redirect)(void *skb, __u32 ifindex, __u64 flags) = (void *)BPF_FUNC_clone_redirect;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) =
	(void *)BPF_FUNC_fib_lookup;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

/* Pinned by name (LIBBPF_PIN_BY_NAME = 1) so tc and the daemon share them. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vh_cfg);
	__uint(pinning, 1);
} vbanhub_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VH_MAX_LOCAL);
	__type(key, __u32);             /* hub address or broadcast address, network order */
	__type(value, __u32);           /* 0 unicast, 1 broadcast */
	__uint(pinning, 1);
} vbanhub_local SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VH_MAX_IF);
	__type(key, __u32);             /* egress ifindex */
	__type(value, __u32);           /* source address to send from, network order */
	__uint(pinning, 1);
} vbanhub_ifaddr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, VH_MAX_KEYS);
	__type(key, struct vh_key);
	__type(value, struct vh_val);
	__uint(pinning, 1);
} vbanhub_routes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, VH_MAX_ROUTES);
	__type(key, __u32);
	__type(value, struct vh_rstat);
	__uint(pinning, 1);
} vbanhub_rstat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, VH_MAX_STREAMS);
	__type(key, struct vh_key);
	__type(value, struct vh_sstat);
	__uint(pinning, 1);
} vbanhub_sstat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, VH_G_N);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, 1);
} vbanhub_gstat SEC(".maps");

/* Per-CPU scratch: FIB results for every destination of one packet (too big for the stack). */
struct vh_hop {
	__u32 ifindex, saddr;
	__u8 mac[12];                   /* dst mac, src mac */
};
struct vh_scratch {
	struct vh_hop hop[VH_MAX_FO];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct vh_scratch);
} vbanhub_scratch SEC(".maps");

INL void gstat(__u32 k, __u64 n)
{
	__u64 *v = bpf_map_lookup_elem(&vbanhub_gstat, &k);
	if (v)
		*v += n;
}

#define ETH_LEN 14
#define IP_OFF ETH_LEN
#define UDP_OFF (ETH_LEN + 20)
#define VB_OFF (UDP_OFF + 8)
#define IPCSUM_OFF (IP_OFF + 10)
#define UDPCSUM_OFF (UDP_OFF + 6)

SEC("tc")
int vbanhub_ingress(struct __sk_buff *skb)
{
	struct { struct iphdr ip; struct udphdr udp; __u8 vb[28]; } h;
	struct vh_key k;
	struct vh_val *v;
	struct vh_cfg *cfg;
	struct vh_scratch *sc;
	__u32 zero = 0, *kind, n, i, len, fc;
	__u8 cur_name[VH_NAME_LEN];
	__u64 now;

	if (skb->protocol != H16(ETH_P_IP) || skb->len < VB_OFF + 28)
		return TC_ACT_OK;
	cfg = bpf_map_lookup_elem(&vbanhub_cfg, &zero);
	if (!cfg || !cfg->enabled)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, IP_OFF, &h, sizeof(h)))
		return TC_ACT_OK;
	if (h.ip.version != 4 || h.ip.ihl != 5 || h.ip.protocol != IPPROTO_UDP ||
	    (h.ip.frag_off & H16(0x3FFF)) || h.udp.dest != cfg->port)
		return TC_ACT_OK;
	kind = bpf_map_lookup_elem(&vbanhub_local, &h.ip.daddr);
	if (!kind)
		return TC_ACT_OK;                       /* not for the hub (e.g. routed traffic) */
	len = H16(h.ip.tot_len);
	if (len < 20 + 8 + 28 || H16(h.udp.len) != len - 20)
		return TC_ACT_OK;
	if (h.vb[0] != 'V' || h.vb[1] != 'B' || h.vb[2] != 'A' || h.vb[3] != 'N' || (h.vb[4] & 0xE0) == 0x60 ||
	    ((h.vb[4] & 0xE0) == 0xE0 && h.vb[6] == 'S'))
		return TC_ACT_OK;                       /* not VBAN, SERVICE (pings) or secure VBAN: the daemon's */

	/* One lookup, most specific first. The daemon stores in each key every route that
	 * matches it (including wildcard ones), so the first hit is the complete answer. */
	__builtin_memcpy(k.name, h.vb + 8, VH_NAME_LEN);
	k.src_ip = h.ip.saddr; k.any_name = 0;
	v = bpf_map_lookup_elem(&vbanhub_routes, &k);
	if (!v) {
		k.src_ip = 0;
		v = bpf_map_lookup_elem(&vbanhub_routes, &k);
	}
	if (!v) {
		k.any_name = 1; __builtin_memset(k.name, 0, VH_NAME_LEN);
		k.src_ip = h.ip.saddr;
		v = bpf_map_lookup_elem(&vbanhub_routes, &k);
		if (!v) {
			k.src_ip = 0;
			v = bpf_map_lookup_elem(&vbanhub_routes, &k);
		}
	}
	if (!v || !v->n)
		return TC_ACT_OK;                       /* unrouted: the daemon lists it */
	if (v->slow) {
		gstat(VH_G_SLOW, 1);
		return TC_ACT_OK;
	}
	/* One datagram per skb only. GRO (e.g. rx-gro-list on the switch port) can merge several
	 * into one skb whose other segments this program cannot rewrite: the daemon gets those. */
	if (skb->gso_segs > 1 || len != skb->len - ETH_LEN) {
		gstat(VH_G_GSO, 1);
		return TC_ACT_OK;
	}
	sc = bpf_map_lookup_elem(&vbanhub_scratch, &zero);
	if (!sc)
		return TC_ACT_OK;
	n = v->n;

	/* Pass 1: resolve every destination. Any miss (neighbour not resolved yet, local
	 * destination, no route) hands the whole packet to the daemon: nothing is sent twice. */
	for (i = 0; i < VH_MAX_FO; i++) {
		struct bpf_fib_lookup f = {};
		__u32 *src;
		if (i >= n)
			break;
		f.family = 2;                           /* AF_INET */
		f.l4_protocol = IPPROTO_UDP;
		f.tot_len = len;
		f.ipv4_dst = v->d[i].daddr;
		f.ifindex = skb->ingress_ifindex;       /* forwarding-style lookup: needs ip forwarding on */
		if (bpf_fib_lookup(skb, &f, sizeof(f), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
		    !(src = bpf_map_lookup_elem(&vbanhub_ifaddr, &f.ifindex))) {
			gstat(VH_G_NOFIB, 1);
			return TC_ACT_OK;
		}
		sc->hop[i].ifindex = f.ifindex;
		sc->hop[i].saddr = *src;
		__builtin_memcpy(sc->hop[i].mac, f.dmac, 6);
		__builtin_memcpy(sc->hop[i].mac + 6, f.smac, 6);
	}

	now = bpf_ktime_get_ns();
	gstat(VH_G_RX, 1);
	{ /* the stream as heard (for the daemon's "Streams heard" list) */
		struct vh_sstat *s, ns = {};
		k.src_ip = h.ip.saddr; k.any_name = 0;
		__builtin_memcpy(k.name, h.vb + 8, VH_NAME_LEN);
		s = bpf_map_lookup_elem(&vbanhub_sstat, &k);
		if (!s) {
			ns.first_ns = now;
			bpf_map_update_elem(&vbanhub_sstat, &k, &ns, BPF_NOEXIST);
			s = bpf_map_lookup_elem(&vbanhub_sstat, &k);
		}
		if (s) {
			s->pkts++;
			s->bytes += len - 28;
			s->last_ns = now;
			s->port = h.udp.source;
			__builtin_memcpy(s->hdr, h.vb + 4, 4);
			s->kind = (__u8)*kind;
		}
	}
	__builtin_memcpy(&fc, h.vb + 24, 4);             /* little endian on the wire */
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	fc = __builtin_bswap32(fc);
#endif
	__builtin_memcpy(cur_name, h.vb + 8, VH_NAME_LEN);

	/* Pass 2: rewrite in place for each destination and send a clone. Checksums are
	 * updated incrementally from what the packet holds now, through the helpers, so
	 * CHECKSUM_PARTIAL / COMPLETE skbs stay right. The daemon orders "keep the
	 * sender's name" destinations first, so the name only ever changes forward. */
	for (i = 0; i < VH_MAX_FO; i++) {
		const struct vh_dst *d;
		struct vh_hop *hop;
		struct vh_rstat *rs;
		struct iphdr ip;
		__u16 nsport = cfg->port;
		__u32 r, c;

		if (i >= n)
			break;
		d = &v->d[i];
		hop = &sc->hop[i];
		ip = h.ip;
		ip.saddr = hop->saddr;
		ip.daddr = d->daddr;
		ip.tos = cfg->tos;
		ip.ttl = 64;
		ip.check = 0;
		c = (__u32)bpf_csum_diff(0, 0, (__be32 *)&ip, 20, 0);
		c = (c & 0xFFFF) + (c >> 16);
		c = (c & 0xFFFF) + (c >> 16);
		ip.check = (__u16)~c;
		if (h.udp.check) {                      /* 0 = sender sent no UDP checksum: keep 0 */
			bpf_l4_csum_replace(skb, UDPCSUM_OFF, h.ip.saddr, ip.saddr, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4);
			bpf_l4_csum_replace(skb, UDPCSUM_OFF, h.ip.daddr, ip.daddr, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4);
			bpf_l4_csum_replace(skb, UDPCSUM_OFF, h.udp.source, nsport, BPF_F_MARK_MANGLED_0 | 2);
			bpf_l4_csum_replace(skb, UDPCSUM_OFF, h.udp.dest, d->dport, BPF_F_MARK_MANGLED_0 | 2);
			if (!d->keep)
				bpf_l4_csum_replace(skb, UDPCSUM_OFF, 0,
						    (__u32)bpf_csum_diff((__be32 *)cur_name, VH_NAME_LEN,
									 (__be32 *)d->name, VH_NAME_LEN, 0),
						    BPF_F_MARK_MANGLED_0);
		}
		if (bpf_skb_store_bytes(skb, 0, hop->mac, 12, 0) ||
		    bpf_skb_store_bytes(skb, IP_OFF, &ip, 20, BPF_F_RECOMPUTE_CSUM) ||
		    bpf_skb_store_bytes(skb, UDP_OFF, &nsport, 2, BPF_F_RECOMPUTE_CSUM) ||
		    bpf_skb_store_bytes(skb, UDP_OFF + 2, &d->dport, 2, BPF_F_RECOMPUTE_CSUM))
			break;
		if (!d->keep) {
			if (bpf_skb_store_bytes(skb, VB_OFF + 8, d->name, VH_NAME_LEN, BPF_F_RECOMPUTE_CSUM))
				break;
			__builtin_memcpy(cur_name, d->name, VH_NAME_LEN);
		}
		/* the next destination's deltas start from what this one wrote */
		h.ip.saddr = ip.saddr;
		h.ip.daddr = ip.daddr;
		h.udp.source = nsport;
		h.udp.dest = d->dport;

		gstat(bpf_clone_redirect(skb, hop->ifindex, 0) ? VH_G_TXERR : VH_G_TX, 1);
		r = d->route;
		rs = bpf_map_lookup_elem(&vbanhub_rstat, &r);
		if (rs) {
			if (rs->have_fc && fc > rs->last_fc + 1 && fc - rs->last_fc < 100000)
				rs->lost += fc - rs->last_fc - 1;
			rs->last_fc = fc;
			rs->have_fc = 1;
			rs->pkts++;
			rs->bytes += len - 28;
			rs->last_ns = now;
		}
	}
	return TC_ACT_SHOT;                             /* every copy is out; the original is done */
}

char _license[] SEC("license") = "Dual MIT/GPL";
