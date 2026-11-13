/*
 * VBAN SDK - wire protocol (VB-Audio VBAN specification, revision 13, Sep 2025).
 *
 * Pure functions on byte buffers: no OS, no allocation, no global state.
 * Everything is encoded/decoded byte by byte in little-endian order, so the
 * code is correct on big-endian CPUs and needs no packed structs or aligned
 * buffers.
 */
#ifndef VBAN_PROTO_H
#define VBAN_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include "vban_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Sizes and limits                                                     */
/* ------------------------------------------------------------------ */
#define VBAN_DEFAULT_PORT        6980
#define VBAN_HEADER_SIZE         28
#define VBAN_DATA_MAX_SIZE       1436                       /* Voicemeeter limit */
#define VBAN_PACKET_MAX_SIZE     (VBAN_HEADER_SIZE + VBAN_DATA_MAX_SIZE) /* 1464 */
#define VBAN_STREAM_NAME_SIZE    16
#define VBAN_SAMPLES_MAX         256
#define VBAN_CHANNELS_MAX        256
#define VBAN_PING0_SIZE          676
#define VBAN_PING0_PACKET_SIZE   (VBAN_HEADER_SIZE + VBAN_PING0_SIZE) /* 704 */

/* ------------------------------------------------------------------ */
/* Header bit fields                                                    */
/* ------------------------------------------------------------------ */
#define VBAN_SR_MASK             0x1F
#define VBAN_PROTOCOL_MASK       0xE0
#define VBAN_DATATYPE_MASK       0x07
#define VBAN_RESERVED_MASK       0x08
#define VBAN_CODEC_MASK          0xF0

/* Sub protocols (format_SR bits 5..7). */
enum {
    VBAN_PROTOCOL_AUDIO   = 0x00,
    VBAN_PROTOCOL_SERIAL  = 0x20,
    VBAN_PROTOCOL_TXT     = 0x40,
    VBAN_PROTOCOL_SERVICE = 0x60,
    VBAN_PROTOCOL_FRAME   = 0x80,   /* rev 13 (was UNDEFINED_1) */
    VBAN_PROTOCOL_UNDEFINED_2 = 0xA0,
    VBAN_PROTOCOL_UNDEFINED_3 = 0xC0,
    VBAN_PROTOCOL_USER    = 0xE0
};

/* Audio data types (format_bit bits 0..2). */
enum {
    VBAN_DATATYPE_U8    = 0,  /* 8-bit unsigned, 128 = 0 */
    VBAN_DATATYPE_S16   = 1,
    VBAN_DATATYPE_S24   = 2,
    VBAN_DATATYPE_S32   = 3,
    VBAN_DATATYPE_F32   = 4,
    VBAN_DATATYPE_F64   = 5,
    VBAN_DATATYPE_S12   = 6,  /* storage layout not defined by the spec */
    VBAN_DATATYPE_S10   = 7   /* storage layout not defined by the spec */
};

/* Audio codecs (format_bit bits 4..7). */
enum {
    VBAN_CODEC_PCM  = 0x00,
    VBAN_CODEC_VBCA = 0x10,   /* VB-Audio AOIP codec (proprietary) */
    VBAN_CODEC_VBCV = 0x20,   /* VB-Audio VOIP codec (proprietary) */
    VBAN_CODEC_USER = 0xF0
};

/* SERIAL stream types (format_bit bits 4..7). */
enum { VBAN_SERIAL_GENERIC = 0x00, VBAN_SERIAL_MIDI = 0x10, VBAN_SERIAL_USER = 0xF0 };

/* SERIAL bitmode (format_nbs). */
enum {
    VBAN_SERIAL_STOP_1      = 0x00,
    VBAN_SERIAL_STOP_1_5    = 0x01,
    VBAN_SERIAL_STOP_2      = 0x02,
    VBAN_SERIAL_START       = 0x04,
    VBAN_SERIAL_PARITY      = 0x08,
    VBAN_SERIAL_MULTIPART   = 0x80
};

/* TEXT formats (format_bit bits 4..7). */
enum { VBAN_TXT_ASCII = 0x00, VBAN_TXT_UTF8 = 0x10, VBAN_TXT_WCHAR = 0x20, VBAN_TXT_USER = 0xF0 };

/* FRAME packet types (format_bit bits 0..2) and stream types (bits 4..7). */
enum {
    VBAN_FRAME_START = 0x01, VBAN_FRAME_CONTINUE = 0x02, VBAN_FRAME_END = 0x04,
    VBAN_FRAME_DEFAULT = 0x00, VBAN_FRAME_USER = 0xF0
};

/* SERVICE: type (format_nbc) and function (format_nbs). */
enum {
    VBAN_SERVICE_IDENTIFICATION   = 0,
    VBAN_SERVICE_CHATUTF8         = 1,
    VBAN_SERVICE_REQUESTREPLY     = 2,  /* used by Voicemeeter Matrix for TEXT query answers */
    VBAN_SERVICE_RTPACKETREGISTER = 32,
    VBAN_SERVICE_RTPACKET         = 33
};
#define VBAN_SERVICE_FNCT_PING0  0x00
#define VBAN_SERVICE_FNCT_REPLY  0x80

/* RT-Packet register reply codes (format_bit of the reply). */
enum { VBAN_RTREG_NONE = 0, VBAN_RTREG_OK = 1, VBAN_RTREG_BUSY = 2 };

/* PING0 bitType. */
#define VBAN_PING_TYPE_RECEPTOR         0x00000001u
#define VBAN_PING_TYPE_TRANSMITTER      0x00000002u
#define VBAN_PING_TYPE_RECEPTORSPOT     0x00000004u
#define VBAN_PING_TYPE_TRANSMITTERSPOT  0x00000008u
#define VBAN_PING_TYPE_VIRTUALDEVICE    0x00000010u
#define VBAN_PING_TYPE_VIRTUALMIXER     0x00000020u
#define VBAN_PING_TYPE_MATRIX           0x00000040u
#define VBAN_PING_TYPE_DAW              0x00000080u
#define VBAN_PING_TYPE_SERVER           0x01000000u

/* PING0 bitfeature. */
#define VBAN_PING_FEATURE_AUDIO   0x00000001u
#define VBAN_PING_FEATURE_AOIP    0x00000002u
#define VBAN_PING_FEATURE_VOIP    0x00000004u
#define VBAN_PING_FEATURE_SERIAL  0x00000100u
#define VBAN_PING_FEATURE_MIDI    0x00000300u
#define VBAN_PING_FEATURE_FRAME   0x00001000u
#define VBAN_PING_FEATURE_TXT     0x00010000u

/* ------------------------------------------------------------------ */
/* Endpoint address and transport hook                                  */
/* ------------------------------------------------------------------ */
/* IPv4 endpoint (the VBAN ecosystem is IPv4-only); ip in host byte order. */
typedef struct vban_addr {
    uint32_t ip;     /* e.g. VBAN_IP(192,168,0,1) */
    uint16_t port;
} vban_addr_t;

#define VBAN_IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
#define VBAN_IP_ANY        0u
#define VBAN_IP_BROADCAST  0xFFFFFFFFu

static inline int vban_addr_eq(const vban_addr_t *a, const vban_addr_t *b)
{ return a->ip == b->ip && a->port == b->port; }

/* 1 if `a` can be a real unicast sender worth replying to: port != 0 and the IP
 * is not 0.0.0.0, limited broadcast, multicast (224/4) or reserved (240/4).
 * Replying to anything else is how reflection attacks fan out. Subnet-directed
 * broadcasts (x.y.z.255) cannot be told apart without the netmask. */
static inline int vban_addr_is_unicast(const vban_addr_t *a)
{ return a->port != 0 && a->ip != 0 && (a->ip >> 28) < 0xE; }

/* 1 for loopback, RFC 1918, link-local and CGNAT (100.64/10) addresses. */
static inline int vban_addr_is_private(uint32_t ip)
{
    return (ip >> 24) == 10 || (ip >> 24) == 127 || (ip >> 20) == 0xAC1 /* 172.16/12 */ ||
           (ip >> 16) == 0xC0A8 /* 192.168/16 */ || (ip >> 16) == 0xA9FE /* 169.254/16 */ ||
           (ip >> 22) == 0x191 /* 100.64/10 */;
}

/* Transport hook used by senders/responders: send `len` bytes to `to`.
 * Return >= 0 on success. vban_udp_sink() (vban_net.h) adapts a socket. */
typedef int (*vban_send_fn)(void *ctx, const uint8_t *pkt, size_t len, const vban_addr_t *to);

/* ------------------------------------------------------------------ */
/* Error codes                                                          */
/* ------------------------------------------------------------------ */
/* Error codes. Functions return them as plain `int` (VBAN_OK = 0, negative =
 * error) so the same values can carry counts and lengths; vban_err_t only names
 * the set. */
typedef enum vban_err {
    VBAN_OK              =  0,
    VBAN_E_ARG           = -1,  /* bad argument */
    VBAN_E_SHORT         = -2,  /* packet shorter than header */
    VBAN_E_MAGIC         = -3,  /* not 'VBAN' */
    VBAN_E_SIZE          = -4,  /* payload size inconsistent with header */
    VBAN_E_FORMAT        = -5,  /* invalid / reserved field value */
    VBAN_E_UNSUPPORTED   = -6,  /* valid but not decodable here (codec, 10/12-bit) */
    VBAN_E_NOSPACE       = -7,  /* destination buffer / table full */
    VBAN_E_NET           = -8,  /* socket error */
    VBAN_E_TIMEOUT       = -9,  /* nothing received */
    VBAN_E_OVERSIZE      = -10, /* exceeds 1464 bytes / 256 samples */
    VBAN_E_NOTFOUND      = -11,
    VBAN_E_AUTH          = -12, /* secure: does not authenticate (tag / handshake) */
    VBAN_E_CERT          = -13, /* secure: certificate invalid, expired, wrong CA or refused */
    VBAN_E_REPLAY        = -14, /* secure: counter already seen or too old */
    VBAN_E_STATE         = -15  /* secure: message not expected in this session state */
} vban_err_t;

const char *vban_strerror(int err);

/* ------------------------------------------------------------------ */
/* Lookup tables                                                        */
/* ------------------------------------------------------------------ */
#define VBAN_SR_COUNT    21
#define VBAN_BPS_COUNT   25
#define VBAN_MBPS_COUNT  25

extern const uint32_t vban_sr_table[VBAN_SR_COUNT];
extern const uint32_t vban_bps_table[VBAN_BPS_COUNT];
extern const uint16_t vban_mbps_table[VBAN_MBPS_COUNT];
/* Bytes per sample for each datatype; 0 for 10/12-bit (undefined layout). */
extern const uint8_t  vban_datatype_size[8];

/* Index -> rate (0 if index is undefined). */
uint32_t vban_sr_from_index(unsigned index);
/* Rate -> index, or -1 if the rate is not representable. */
int      vban_sr_to_index(uint32_t rate);
uint32_t vban_bps_from_index(unsigned index);
int      vban_bps_to_index(uint32_t bps);

/* ------------------------------------------------------------------ */
/* Stream names                                                         */
/* ------------------------------------------------------------------ */
/* A stream name as it appears on the wire: 16 bytes, NUL padded. Comparing two
 * of these is two 64-bit compares. */
typedef struct vban_name { uint8_t b[VBAN_STREAM_NAME_SIZE]; } vban_name_t;

/* Build a wire name from a C string (truncated to 16 bytes, NUL padded). */
void vban_name_set(vban_name_t *n, const char *s);
/* Copy a wire name into a C string buffer of at least 17 bytes. */
void vban_name_get(const vban_name_t *n, char out[VBAN_STREAM_NAME_SIZE + 1]);
/* Exact compare of two wire names (bytes after the first NUL are ignored). */
int  vban_name_eq(const vban_name_t *a, const uint8_t wire[VBAN_STREAM_NAME_SIZE]);
/* ASCII case-insensitive variant. */
int  vban_name_eq_nocase(const vban_name_t *a, const uint8_t wire[VBAN_STREAM_NAME_SIZE]);

/* ------------------------------------------------------------------ */
/* Little-endian helpers (inline, alignment-free)                       */
/* ------------------------------------------------------------------ */
static inline uint16_t vban_rd16(const uint8_t *p) { return (uint16_t)((unsigned)p[0] | ((unsigned)p[1] << 8)); }
static inline uint32_t vban_rd32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline void vban_wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static inline void vban_wr32(uint8_t *p, uint32_t v)
{ p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

/* Fast single-compare magic check, as recommended by the spec. */
static inline int vban_is_vban(const uint8_t *p, size_t len)
{ return len >= VBAN_HEADER_SIZE && p[0] == 'V' && p[1] == 'B' && p[2] == 'A' && p[3] == 'N'; }

/* ------------------------------------------------------------------ */
/* Raw header                                                           */
/* ------------------------------------------------------------------ */
/* Decoded 28-byte header. Field names follow the spec. */
typedef struct vban_header {
    uint8_t     format_SR;   /* index (bits 0..4) | sub protocol (bits 5..7) */
    uint8_t     format_nbs;
    uint8_t     format_nbc;
    uint8_t     format_bit;
    vban_name_t name;
    uint32_t    nu_frame;
} vban_header_t;

void vban_header_write(uint8_t dst[VBAN_HEADER_SIZE], const vban_header_t *h);
void vban_header_read(const uint8_t src[VBAN_HEADER_SIZE], vban_header_t *h);
/* Patch only the frame counter / nbs of an already written header. */
static inline void vban_header_set_frame(uint8_t *pkt, uint32_t f) { vban_wr32(pkt + 24, f); }
static inline void vban_header_set_nbs(uint8_t *pkt, uint8_t nbs) { pkt[5] = nbs; }

/* ------------------------------------------------------------------ */
/* Packet parsing                                                       */
/* ------------------------------------------------------------------ */
/* Zero-copy view of a received packet. Pointers reference the caller's buffer. */
typedef struct vban_packet {
    const uint8_t *raw;          /* whole packet */
    const uint8_t *name;         /* 16 bytes, not NUL terminated */
    const uint8_t *data;         /* payload */
    uint16_t       data_len;
    uint8_t        protocol;     /* VBAN_PROTOCOL_* */
    uint8_t        sr_index;     /* format_SR & 0x1F */
    uint8_t        format_nbs, format_nbc, format_bit;
    uint32_t       nu_frame;
    /* Audio (protocol == AUDIO) */
    uint32_t       sample_rate;  /* 0 if the index is undefined */
    uint16_t       samples;      /* nbs + 1 */
    uint16_t       channels;     /* nbc + 1 */
    uint8_t        datatype;     /* VBAN_DATATYPE_* */
    uint8_t        codec;        /* VBAN_CODEC_* */
    uint8_t        sample_size;  /* bytes per sample (0 = unknown layout) */
    uint8_t        valid;        /* 1 only when vban_parse() returned VBAN_OK: for AUDIO this
                                    guarantees data_len == samples * channels * sample_size.
                                    Callbacks also see VBAN_E_UNSUPPORTED packets (valid == 0)
                                    and must not decode their payload as PCM. */
} vban_packet_t;

#define VBAN_PARSE_STRICT          0x01  /* also reject spec violations that are harmless */
#define VBAN_PARSE_ALLOW_OVERSIZE  0x02  /* accept packets larger than 1464 bytes */

/*
 * Validate and decode a packet. Lenient by default: only rejects what would
 * make processing unsafe (bad magic, truncated, PCM size mismatch, undefined
 * sample rate, reserved bit set). Returns VBAN_OK, VBAN_E_UNSUPPORTED for
 * well-formed audio this SDK cannot decode (non-PCM codec, 10/12-bit) with
 * the view still filled in, or another negative error.
 */
int vban_parse(const uint8_t *buf, size_t len, vban_packet_t *out, unsigned flags);

/* Bytes needed for a PCM payload. */
static inline size_t vban_pcm_bytes(unsigned samples, unsigned channels, unsigned datatype)
{ return (size_t)samples * channels * vban_datatype_size[datatype & 7]; }

/* Largest sample count (<=256) whose payload fits in 1436 bytes, 0 if even 1 does not fit. */
unsigned vban_max_samples(unsigned channels, unsigned datatype);

/* ------------------------------------------------------------------ */
/* Frame-counter sequencing                                             */
/* ------------------------------------------------------------------ */
typedef enum vban_seq_result {
    VBAN_SEQ_FIRST = 0,  /* first packet seen */
    VBAN_SEQ_OK,         /* in order */
    VBAN_SEQ_GAP,        /* `lost` packets missing before this one */
    VBAN_SEQ_LATE,       /* older than expected (reordered or duplicate) */
    VBAN_SEQ_RESET,      /* confirmed jump: sender restarted, or resynced to the real stream */
    VBAN_SEQ_SUSPECT     /* big jump not yet confirmed by a following packet: drop it */
} vban_seq_result_t;

/* Jumps larger than this many packets must be confirmed by the next packet
 * (counter + 1) before they are accepted. Real streams confirm on the very
 * next packet; a single spoofed counter value never does. */
#define VBAN_SEQ_CONFIRM_GAP 4

typedef struct vban_seq {
    uint32_t expected;
    uint8_t  started;
    uint8_t  has_cand, has_prev, prev_hit;
    uint32_t max_gap;   /* gaps larger than this are treated as a restart */
    uint32_t cand;      /* most recent unconfirmed jump target */
    uint32_t hist[4];   /* recent unconfirmed counters (interleaved copies / reordering) */
    uint8_t  n_hist;
    uint32_t prev;      /* expected value before the last accepted big jump */
    uint32_t since_jump;
    uint32_t prev_last; /* last old-sequence counter seen after a reset-type jump */
} vban_seq_t;

void vban_seq_init(vban_seq_t *s, uint32_t max_gap);
/*
 * `lost` (may be NULL) receives the number of missing packets on GAP.
 * Hardened against spoofed counters (anyone can send a packet with the
 * stream's name):
 *  - a jump > VBAN_SEQ_CONFIRM_GAP returns SUSPECT until another packet
 *    lands within VBAN_SEQ_CONFIRM_GAP of one of the last 4 suspects (so
 *    reordering and redundant copies sent D packets later confirm it too,
 *    for any D);
 *  - if, after an accepted restart-size jump (> max_gap), the previous
 *    sequence continues with two consecutive packets, the jump was not
 *    genuine and the tracker resyncs back (returns RESET).
 * An attacker can still disrupt a stream by injecting continuously; only
 * authentication (secure mode) prevents that.
 */
vban_seq_result_t vban_seq_update(vban_seq_t *s, uint32_t nu_frame, uint32_t *lost);

/* ------------------------------------------------------------------ */
/* Packet builders (return total packet length or a negative error)     */
/* ------------------------------------------------------------------ */
/* AUDIO header for PCM. sample_rate must be in vban_sr_table. */
int vban_build_audio_header(uint8_t dst[VBAN_HEADER_SIZE], const vban_name_t *name,
                            uint32_t sample_rate, unsigned samples, unsigned channels,
                            unsigned datatype, uint32_t nu_frame);

/* TEXT packet. bps_index 0..24 (Voicemeeter uses 18 = 256000), channel 0..255. */
int vban_build_text(uint8_t *dst, size_t cap, const vban_name_t *name, uint32_t nu_frame,
                    unsigned bps_index, unsigned channel, unsigned txt_format,
                    const void *text, size_t len);

/* SERIAL packet. bitmode = VBAN_SERIAL_* flags, type = VBAN_SERIAL_GENERIC/MIDI. */
int vban_build_serial(uint8_t *dst, size_t cap, const vban_name_t *name, uint32_t nu_frame,
                      unsigned bps_index, unsigned channel, unsigned bitmode, unsigned type,
                      const void *data, size_t len);

/* One FRAME packet. packet_index is the index inside the frame (wraps at 65536). */
int vban_build_frame_packet(uint8_t *dst, size_t cap, const vban_name_t *name, uint32_t nu_frame,
                            unsigned mbps_index, uint16_t packet_index, unsigned packet_type,
                            unsigned stream_type, const void *data, size_t len);

/* ------------------------------------------------------------------ */
/* SERVICE / PING0                                                      */
/* ------------------------------------------------------------------ */
typedef struct vban_ping0 {
    uint32_t bit_type;
    uint32_t bit_feature;
    uint32_t bit_feature_ex;
    uint32_t prefered_rate;
    uint32_t min_rate;
    uint32_t max_rate;
    uint32_t color_rgb;
    uint8_t  version[4];
    char     gps_position[8];
    char     user_position[8];
    char     lang_code[8];
    char     distant_ip[32];
    uint16_t distant_port;
    char     device_name[64];
    char     manufacturer_name[64];
    char     application_name[64];
    char     host_name[64];
    char     user_name[128];        /* UTF-8 */
    char     user_comment[128];     /* UTF-8 */
} vban_ping0_t;

/* Serialize to the 676-byte wire structure (reserved fields zeroed, strings
 * truncated/NUL padded). */
void vban_ping0_encode(const vban_ping0_t *p, uint8_t out[VBAN_PING0_SIZE]);
/* Deserialize; strings are always NUL terminated in `out`. len may be < 676
 * (missing tail fields are zeroed). */
int  vban_ping0_decode(const uint8_t *in, size_t len, vban_ping0_t *out);

/* PING0 request (reply == 0) or reply (reply != 0). The request id must be
 * echoed in the reply. `label` may be NULL ("VBAN SPOT PING"). ping may be
 * NULL to send a header-only request. Returns 28 or 704. */
int vban_build_ping(uint8_t *dst, size_t cap, uint32_t request_id, int reply,
                    const vban_name_t *label, const vban_ping0_t *ping);

/* RT-Packet registration request for `packet_id` (0..127, carried in the
 * function field as Voicemeeter clients do). timeout_s 0..255. An optional
 * list of extra packet ids may be appended as payload (spec "Packet ID List");
 * pass NULL/0 for none. Voicemeeter: id 0, timeout 15 s, re-register every 10 s. */
int vban_build_rt_register(uint8_t *dst, size_t cap, const vban_name_t *label, uint32_t nu_frame,
                           unsigned packet_id, uint8_t timeout_s, const uint8_t *ids, size_t n_ids);
/* RT-Packet registration reply (code = VBAN_RTREG_*). */
int vban_build_rt_register_reply(uint8_t *dst, size_t cap, const vban_name_t *label,
                                 uint32_t nu_frame, unsigned packet_id, unsigned code);
/* RT-Packet carrying `len` bytes of server-defined data. */
int vban_build_rt_packet(uint8_t *dst, size_t cap, const vban_name_t *label, uint32_t nu_frame,
                         unsigned packet_id, const void *data, size_t len);

/* Service accessors on a parsed packet. */
static inline unsigned vban_service_type(const vban_packet_t *p)     { return p->format_nbc; }
static inline unsigned vban_service_function(const vban_packet_t *p) { return p->format_nbs & 0x7F; }
static inline int      vban_service_is_reply(const vban_packet_t *p) { return (p->format_nbs & 0x80) != 0; }

#ifdef __cplusplus
}
#endif
#endif /* VBAN_PROTO_H */
