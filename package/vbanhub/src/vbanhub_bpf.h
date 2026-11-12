/*
 * Shared between the tc eBPF fast path (vbanhub.bpf.c) and the daemon (vbanhub.c).
 * Maps are pinned by tc under /sys/fs/bpf/tc/globals/<name>; the daemon fills them.
 */
#ifndef VBANHUB_BPF_H
#define VBANHUB_BPF_H

#define VH_NAME_LEN 16
#define VH_MAX_FO 32          /* destinations per route key (the daemon's MAX_FANOUT) */
#define VH_MAX_ROUTES 256
#define VH_MAX_KEYS 256
#define VH_MAX_STREAMS 64
#define VH_MAX_LOCAL 32
#define VH_MAX_IF 64

/* Route key: (source ip | 0 = any, stream name | any). All fields in packet byte order. */
struct vh_key {
	__u32 src_ip;
	__u32 any_name;
	__u8 name[VH_NAME_LEN];
};

struct vh_dst {
	__u32 daddr;          /* network order */
	__u16 dport;          /* network order */
	__u8 keep;            /* 1 = forward the sender's stream name */
	__u8 pad;
	__u32 route;          /* daemon route index, for vh_rstat */
	__u8 name[VH_NAME_LEN];
};

struct vh_val {
	__u32 n;              /* destinations used */
	__u32 slow;           /* 1 = this key needs the daemon (gain != 100 %, too many destinations) */
	struct vh_dst d[VH_MAX_FO];
};

struct vh_cfg {
	__u16 port;           /* hub UDP port, network order */
	__u8 tos;             /* outgoing TOS byte (DSCP << 2) */
	__u8 enabled;         /* 0 = everything goes to the daemon */
};

struct vh_rstat {         /* per route (array index = daemon route index) */
	__u64 pkts, bytes, lost, last_ns;
	__u32 last_fc, have_fc;
};

struct vh_sstat {         /* per heard stream (key: vh_key with any_name = 0) */
	__u64 pkts, bytes, first_ns, last_ns;
	__u16 port;           /* source port, network order */
	__u8 hdr[4];          /* VBAN header bytes 4..7 */
	__u8 kind;            /* 0 unicast, 1 broadcast */
	__u8 pad;
};

enum { VH_G_RX, VH_G_TX, VH_G_SLOW, VH_G_NOFIB, VH_G_TXERR, VH_G_GSO, VH_G_N };

#endif
