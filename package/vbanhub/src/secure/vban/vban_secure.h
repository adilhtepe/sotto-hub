/*
 * VBAN SDK - secure VBAN (optional, VBAN_ENABLE_SECURE). See .10x/adrs/003.
 *
 * Certificates
 *   A network CA (EdDSA key) signs device certificates. A device keeps its
 *   X25519 private key; it hands out a request (name, role, public key) and
 *   gets back a 168-byte certificate. Text form: base64 between
 *   "-----BEGIN VBAN CERT-----" lines (also REQUEST / PRIVATE KEY / CA KEY).
 *
 * Sessions
 *   Noise_XX_25519_ChaChaPoly_BLAKE2b handshake (3 messages, mutual
 *   authentication with the certificates, forward secrecy), then each VBAN
 *   packet travels encrypted inside a VBAN USER (0xE0) packet:
 *
 *     outer header (28, sent in clear, authenticated):
 *       "VBAN" | 0xE0 | type | 'S' | version | sender idx u32 | receiver idx u32 |
 *       counter u64 | counter low 32
 *     DATA body: ChaCha20-Poly1305(inner VBAN packet) | tag 16
 *
 *   The inner packet is any VBAN packet up to VBAN_SEC_INNER_MAX (1420) bytes,
 *   i.e. an audio payload up to 1392 bytes.
 *
 *   One vban_sec_session_t is one direction-pair with one peer. An initiator
 *   (device) calls connect(); a responder (hub, receiver) answers with
 *   accept(). Both feed every USER packet to handle(). vban_sec_link_t adds
 *   retransmission and rekeying on top for the initiator side.
 *
 * Nothing allocates. Time is passed in by the caller (milliseconds, any
 * monotonic origin) and, for certificate validity, as Unix seconds (0 = the
 * device has no clock: dates are not checked).
 */
#ifndef VBAN_SECURE_H
#define VBAN_SECURE_H
#include <stddef.h>
#include <stdint.h>
#include "vban_proto.h"
#include "vban_noise.h"
#ifdef __cplusplus
extern "C" {
#endif

#define VBAN_CERT_SIZE        168
#define VBAN_CERT_REQ_SIZE    72
#define VBAN_CERT_NAME_MAX    32
#define VBAN_SEC_HDR          VBAN_HEADER_SIZE
#define VBAN_SEC_OVERHEAD     (VBAN_SEC_HDR + VBAN_NOISE_TAGLEN)               /* 44 */
#define VBAN_SEC_INNER_MAX    (VBAN_PACKET_MAX_SIZE - VBAN_SEC_OVERHEAD)       /* 1420 */
#define VBAN_SEC_HS_MAX       (VBAN_SEC_HDR + 32 + 48 + 4 + VBAN_CERT_SIZE + 16) /* 296: HS2 */

/* Certificate roles (bit flags). */
#define VBAN_CERT_ROLE_TX   0x01   /* transmitter */
#define VBAN_CERT_ROLE_RX   0x02   /* receiver */
#define VBAN_CERT_ROLE_HUB  0x04
#define VBAN_CERT_ROLE_CA   0x80

/* Secure message types (outer header byte 5). */
enum { VBAN_SEC_HS1 = 1, VBAN_SEC_HS2 = 2, VBAN_SEC_HS3 = 3, VBAN_SEC_DATA = 4, VBAN_SEC_COOKIE = 5 };
#define VBAN_SEC_COOKIE_LEN 16

/* Session timing (ms). */
#define VBAN_SEC_REKEY_MS     120000u   /* initiator re-handshakes after this */
#define VBAN_SEC_EXPIRE_MS    180000u   /* keys refused after this */
#define VBAN_SEC_PREV_MS      10000u    /* previous receive key kept after a rekey */
#define VBAN_SEC_RETRY_MS     1000u     /* handshake initiation resent after this */
#define VBAN_SEC_KEEPALIVE_MS 15000u    /* an idle link sends an empty DATA packet, so that NAT
                                           mappings stay open and the responder can still reach
                                           a device that only receives (over the internet) */

typedef struct vban_cert {
    uint8_t  role;                      /* VBAN_CERT_ROLE_* */
    uint64_t not_before, not_after;     /* Unix seconds */
    uint64_t serial;
    uint8_t  key[32];                   /* X25519 (devices) / EdDSA (CA) public key */
    char     name[VBAN_CERT_NAME_MAX + 1];
    uint8_t  issuer[8];                 /* BLAKE2b(CA key)[0..7] */
    uint8_t  sig[64];
} vban_cert_t;

/* ---- keys ---- */
/* Random bytes from the OS (getrandom / /dev/urandom / BCryptGenRandom / esp_fill_random).
 * Override with vban_sec_set_rng() on other platforms. Returns 0 or VBAN_E_UNSUPPORTED. */
int  vban_sec_random(void *buf, size_t len);
void vban_sec_set_rng(int (*rng)(void *ctx, void *buf, size_t len), void *ctx);

int  vban_sec_keygen(uint8_t sk[32], uint8_t pk[32]);                 /* X25519 device key */
void vban_sec_pubkey(const uint8_t sk[32], uint8_t pk[32]);
int  vban_ca_keygen(uint8_t ca_sk[64], uint8_t ca_pk[32]);            /* EdDSA CA key */
void vban_ca_id(const uint8_t ca_pk[32], uint8_t id[8]);

/* ---- certificates ---- */
int  vban_cert_encode(const vban_cert_t *c, uint8_t out[VBAN_CERT_SIZE]);
int  vban_cert_decode(const uint8_t *in, size_t len, vban_cert_t *c);   /* format only, no checks */
/* Sign: fills issuer and sig from the CA key. */
int  vban_cert_sign(vban_cert_t *c, const uint8_t ca_sk[64], const uint8_t ca_pk[32]);
/* Self-signed CA certificate. */
int  vban_ca_cert(vban_cert_t *c, const char *name, const uint8_t ca_sk[64], const uint8_t ca_pk[32],
                  uint64_t not_before, uint64_t not_after, uint64_t serial);
/* Check signature by the CA (and dates if now_unix != 0). VBAN_OK or VBAN_E_CERT. */
int  vban_cert_verify(const vban_cert_t *c, const uint8_t ca_pk[32], uint64_t now_unix);

/* Requests: what a device sends to the CA. */
int  vban_cert_req_encode(const char *name, uint8_t role, const uint8_t pk[32], uint8_t out[VBAN_CERT_REQ_SIZE]);
int  vban_cert_req_decode(const uint8_t *in, size_t len, char name[VBAN_CERT_NAME_MAX + 1], uint8_t *role,
                          uint8_t pk[32]);

/* PEM-like text. label e.g. "VBAN CERT". encode returns the text length (NUL
 * terminated) or VBAN_E_NOSPACE; decode returns the byte length or < 0. */
int  vban_pem_encode(const char *label, const uint8_t *in, size_t len, char *out, size_t cap);
int  vban_pem_decode(const char *label, const char *in, size_t inlen, uint8_t *out, size_t cap);

/* ---- identity ---- */
typedef struct vban_sec_id {
    uint8_t     sk[32], pk[32];
    uint8_t     cert_bytes[VBAN_CERT_SIZE];
    vban_cert_t cert;
    uint8_t     ca_pk[32];
    uint64_t    now_unix;               /* set by the application; 0 = unknown */
    /* Optional: refuse a verified peer (revocation, role). Return 0 to accept. */
    int       (*authorize)(void *ctx, const vban_cert_t *peer);
    void       *authorize_ctx;
} vban_sec_id_t;

/* Load an identity: own secret key, own certificate, CA certificate (all binary).
 * Checks that the certificate is the CA's and matches the key. */
int vban_sec_id_init(vban_sec_id_t *id, const uint8_t sk[32], const uint8_t *cert, size_t cert_len,
                     const uint8_t *ca_cert, size_t ca_len);

/* ---- sessions ---- */
enum { VBAN_SEC_IDLE = 0, VBAN_SEC_WAIT_HS2, VBAN_SEC_WAIT_HS3, VBAN_SEC_UP, VBAN_SEC_DEAD };

typedef struct vban_sec_session {
    uint8_t  state, initiator;
    uint32_t local_idx, remote_idx;
    vban_noise_hs_t hs;
    uint8_t  tx_key[32], rx_key[32];
    uint64_t tx_ctr;
    uint64_t rx_top, rx_bits;           /* replay window: highest counter + 64-bit bitmap */
    uint8_t  rx_any;
    uint64_t up_ms, hs_ms;              /* when established / when the handshake started */
    vban_cert_t peer;
} vban_sec_session_t;

/* Events returned through *event by vban_sec_handle(). */
enum { VBAN_SEC_EV_NONE = 0, VBAN_SEC_EV_SEND, VBAN_SEC_EV_UP, VBAN_SEC_EV_DATA };

/* Initiator: start a handshake; writes HS1 into out. Returns its length. */
int vban_sec_connect(vban_sec_session_t *s, const vban_sec_id_t *id, uint32_t local_idx, uint64_t now_ms,
                     uint8_t *out, size_t cap);
/* Responder: answer an HS1 (fresh session); writes HS2 into out. Returns its length. */
int vban_sec_accept(vban_sec_session_t *s, const vban_sec_id_t *id, uint32_t local_idx, const uint8_t *in,
                    size_t len, uint64_t now_ms, uint8_t *out, size_t cap);
/* Any later packet of this session (HS2, HS3, DATA). Returns a length:
 *   EV_SEND: out holds a packet to send back (HS3)        EV_UP: session established
 *   EV_DATA: out holds the decrypted inner VBAN packet
 * or a negative VBAN_E_* (AUTH, CERT, REPLAY, STATE...). Errors in the handshake
 * kill the session; a bad DATA packet is just dropped. */
int vban_sec_handle(vban_sec_session_t *s, const vban_sec_id_t *id, const uint8_t *in, size_t len,
                    uint64_t now_ms, uint8_t *out, size_t cap, int *event);
/* Encrypt one inner VBAN packet. Returns the outer packet length. */
int vban_sec_seal(vban_sec_session_t *s, const uint8_t *inner, size_t len, uint64_t now_ms, uint8_t *out,
                  size_t cap);

/* Parse the outer header: type, sender index, receiver index. VBAN_OK or < 0. */
int vban_sec_peek(const uint8_t *in, size_t len, int *type, uint32_t *sender_idx, uint32_t *receiver_idx);
void vban_sec_wipe(vban_sec_session_t *s);

/* ---- initiator link: connect, retry, rekey, keep the old key briefly ---- */
typedef struct vban_sec_link {
    vban_sec_session_t cur, next;       /* next = handshake in progress */
    uint64_t prev_until_ms;
    uint8_t  prev_rx_key[32];
    uint32_t prev_idx;
    uint64_t prev_top, prev_bits;
    uint64_t last_try_ms;
    uint8_t  tried;
    uint8_t  hs1[VBAN_SEC_HDR + 32 + VBAN_SEC_COOKIE_LEN];   /* last HS1, resent with a cookie */
    uint8_t  cookie_used;
    uint64_t last_tx_ms;                 /* last packet this link sent (keepalive timer) */
} vban_sec_link_t;

void vban_sec_link_init(vban_sec_link_t *l);
/* Call regularly (e.g. every 100 ms) and after each send: returns a packet to send
 * (> 0: a handshake, or a keepalive after VBAN_SEC_KEEPALIVE_MS without traffic),
 * 0 if nothing to do. A keepalive arrives at the other side as a DATA packet with an
 * empty inner packet: handle() returns 0 with no event. */
int  vban_sec_link_tick(vban_sec_link_t *l, const vban_sec_id_t *id, uint64_t now_ms, uint8_t *out, size_t cap);
/* Feed a received USER packet. Same return / event convention as vban_sec_handle(). */
int  vban_sec_link_handle(vban_sec_link_t *l, const vban_sec_id_t *id, const uint8_t *in, size_t len,
                          uint64_t now_ms, uint8_t *out, size_t cap, int *event);
/* Encrypt with the current session; VBAN_E_STATE while not established. */
int  vban_sec_link_seal(vban_sec_link_t *l, const uint8_t *inner, size_t len, uint64_t now_ms, uint8_t *out,
                        size_t cap);
int  vban_sec_link_up(const vban_sec_link_t *l, uint64_t now_ms);

/* ---- responder: many peers in a caller-provided table ---- */
typedef struct vban_sec_peer {
    vban_sec_session_t s;
    vban_addr_t        addr;            /* where the peer's last authenticated packet came from */
} vban_sec_peer_t;

typedef struct vban_sec_server {
    vban_sec_peer_t *peers;
    unsigned         n;
    unsigned         hs_per_sec;        /* handshake initiations accepted per second (CPU bound) */
    unsigned         hs_tokens;
    uint64_t         hs_refill_ms;
    uint32_t         hs_refused;        /* stats: rate-limited or no free slot */
    uint32_t         hs_evicted;        /* stats: unfinished handshakes pushed out when full */
    /* Under load (the per-second budget is used up), an HS1 gets a COOKIE reply instead of
     * work: a MAC of its source address. Only an initiator that really is at that address can
     * send it back, so floods from spoofed addresses cannot use up the second budget below. */
    uint8_t          cookie_key[32], cookie_prev[32];
    uint64_t         cookie_ms;
    unsigned         cookie_tokens;
    uint32_t         hs_cookies;        /* stats: cookie replies sent */
} vban_sec_server_t;

void vban_sec_server_init(vban_sec_server_t *srv, vban_sec_peer_t *peers, unsigned n, unsigned hs_per_sec);
/* Feed any USER packet. When the handshake budget of this second is used up, an HS1
 * without a valid cookie is answered with a COOKIE packet (EV_SEND, 44 bytes, no state).
 * HS1 takes a free (or expired / stale) slot, else the oldest
 * unfinished handshake (never an established session), and answers
 * (EV_SEND: send out back to from). Other packets go to the slot their receiver
 * index names. *peer is set for EV_SEND / EV_UP / EV_DATA. Same return
 * convention as vban_sec_handle(). A peer's address follows its authenticated
 * packets (roaming). */
int  vban_sec_server_handle(vban_sec_server_t *srv, const vban_sec_id_t *id, const uint8_t *in, size_t len,
                            const vban_addr_t *from, uint64_t now_ms, uint8_t *out, size_t cap, int *event,
                            vban_sec_peer_t **peer);

#ifdef __cplusplus
}
#endif
#endif
