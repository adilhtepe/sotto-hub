/*
 * VBAN SDK - secure VBAN: certificates, Noise XX sessions, AEAD envelope.
 * See vban/vban_secure.h and .10x/adrs/003-secure-vban.md.
 */
#include "vban/vban_secure.h"
#include "monocypher.h"
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(ESP_PLATFORM)
#include <esp_random.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

/* ------------------------------------------------------------------ */
/* little-endian helpers                                               */
/* ------------------------------------------------------------------ */
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put64(uint8_t *p, uint64_t v)
{
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32);
}

/* ------------------------------------------------------------------ */
/* randomness                                                          */
/* ------------------------------------------------------------------ */
static int (*g_rng)(void *, void *, size_t);
static void *g_rng_ctx;

void vban_sec_set_rng(int (*rng)(void *ctx, void *buf, size_t len), void *ctx)
{
    g_rng = rng;
    g_rng_ctx = ctx;
}

int vban_sec_random(void *buf, size_t len)
{
    if (g_rng)
        return g_rng(g_rng_ctx, buf, len) ? VBAN_E_UNSUPPORTED : VBAN_OK;
#if defined(_WIN32)
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? VBAN_OK
                                                                                                : VBAN_E_UNSUPPORTED;
#elif defined(ESP_PLATFORM)
    esp_fill_random(buf, len);
    return VBAN_OK;
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    {
        uint8_t *p = (uint8_t *)buf;
        size_t got = 0;
#if defined(__linux__)
        while (got < len) {
            ssize_t r = getrandom(p + got, len - got, 0);
            if (r <= 0)
                break;
            got += (size_t)r;
        }
        if (got == len)
            return VBAN_OK;
#endif
        {
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd < 0)
                return VBAN_E_UNSUPPORTED;
            while (got < len) {
                ssize_t r = read(fd, p + got, len - got);
                if (r <= 0) {
                    close(fd);
                    return VBAN_E_UNSUPPORTED;
                }
                got += (size_t)r;
            }
            close(fd);
            return VBAN_OK;
        }
    }
#else
    (void)buf;
    (void)len;
    return VBAN_E_UNSUPPORTED;   /* call vban_sec_set_rng() */
#endif
}

/* ------------------------------------------------------------------ */
/* keys                                                                */
/* ------------------------------------------------------------------ */
int vban_sec_keygen(uint8_t sk[32], uint8_t pk[32])
{
    int r = vban_sec_random(sk, 32);
    if (r)
        return r;
    crypto_x25519_public_key(pk, sk);
    return VBAN_OK;
}

void vban_sec_pubkey(const uint8_t sk[32], uint8_t pk[32])
{
    crypto_x25519_public_key(pk, sk);
}

int vban_ca_keygen(uint8_t ca_sk[64], uint8_t ca_pk[32])
{
    uint8_t seed[32];
    int r = vban_sec_random(seed, 32);
    if (r)
        return r;
    crypto_eddsa_key_pair(ca_sk, ca_pk, seed);   /* wipes seed */
    return VBAN_OK;
}

void vban_ca_id(const uint8_t ca_pk[32], uint8_t id[8])
{
    crypto_blake2b(id, 8, ca_pk, 32);
}

/* ------------------------------------------------------------------ */
/* certificates                                                        */
/* ------------------------------------------------------------------ */
#define CERT_SIGNED_LEN 104
static const uint8_t k_cert_domain[] = "VBAN-CERT-v1";   /* 13 bytes with the NUL */

static int name_ok(const char *name, size_t *len)
{
    size_t n = 0;
    if (!name)
        return 0;
    while (n <= VBAN_CERT_NAME_MAX && name[n]) {
        if ((unsigned char)name[n] < 0x20 || name[n] == 0x7F)
            return 0;
        ++n;
    }
    if (n == 0 || n > VBAN_CERT_NAME_MAX)
        return 0;
    *len = n;
    return 1;
}

int vban_cert_encode(const vban_cert_t *c, uint8_t out[VBAN_CERT_SIZE])
{
    size_t nl;
    if (!c || !out || !name_ok(c->name, &nl))
        return VBAN_E_ARG;
    memset(out, 0, VBAN_CERT_SIZE);
    memcpy(out, "VBC1", 4);
    out[4] = c->role;
    put64(out + 8, c->not_before);
    put64(out + 16, c->not_after);
    put64(out + 24, c->serial);
    memcpy(out + 32, c->key, 32);
    memcpy(out + 64, c->name, nl);
    memcpy(out + 96, c->issuer, 8);
    memcpy(out + 104, c->sig, 64);
    return VBAN_OK;
}

int vban_cert_decode(const uint8_t *in, size_t len, vban_cert_t *c)
{
    size_t i, nl;
    if (!in || !c)
        return VBAN_E_ARG;
    if (len != VBAN_CERT_SIZE)
        return VBAN_E_SIZE;
    if (memcmp(in, "VBC1", 4) || in[5] || in[6] || in[7])
        return VBAN_E_FORMAT;
    memset(c, 0, sizeof(*c));
    for (nl = 0; nl < VBAN_CERT_NAME_MAX && in[64 + nl]; ++nl)
        c->name[nl] = (char)in[64 + nl];
    for (i = nl; i < VBAN_CERT_NAME_MAX; ++i)
        if (in[64 + i])
            return VBAN_E_FORMAT;          /* padding must be zero: one encoding per name */
    if (!name_ok(c->name, &nl))
        return VBAN_E_FORMAT;
    c->role = in[4];
    c->not_before = get64(in + 8);
    c->not_after = get64(in + 16);
    c->serial = get64(in + 24);
    memcpy(c->key, in + 32, 32);
    memcpy(c->issuer, in + 96, 8);
    memcpy(c->sig, in + 104, 64);
    return VBAN_OK;
}

static void cert_message(const uint8_t enc[VBAN_CERT_SIZE], uint8_t msg[sizeof(k_cert_domain) + CERT_SIGNED_LEN])
{
    memcpy(msg, k_cert_domain, sizeof(k_cert_domain));
    memcpy(msg + sizeof(k_cert_domain), enc, CERT_SIGNED_LEN);
}

int vban_cert_sign(vban_cert_t *c, const uint8_t ca_sk[64], const uint8_t ca_pk[32])
{
    uint8_t enc[VBAN_CERT_SIZE], msg[sizeof(k_cert_domain) + CERT_SIGNED_LEN];
    int r;
    if (!c || !ca_sk || !ca_pk)
        return VBAN_E_ARG;
    vban_ca_id(ca_pk, c->issuer);
    memset(c->sig, 0, 64);
    r = vban_cert_encode(c, enc);
    if (r)
        return r;
    cert_message(enc, msg);
    crypto_eddsa_sign(c->sig, ca_sk, msg, sizeof(msg));
    return VBAN_OK;
}

int vban_ca_cert(vban_cert_t *c, const char *name, const uint8_t ca_sk[64], const uint8_t ca_pk[32],
                 uint64_t not_before, uint64_t not_after, uint64_t serial)
{
    size_t nl;
    if (!c || !name_ok(name, &nl))
        return VBAN_E_ARG;
    memset(c, 0, sizeof(*c));
    memcpy(c->name, name, nl);
    c->role = VBAN_CERT_ROLE_CA;
    c->not_before = not_before;
    c->not_after = not_after;
    c->serial = serial;
    memcpy(c->key, ca_pk, 32);
    return vban_cert_sign(c, ca_sk, ca_pk);
}

int vban_cert_verify(const vban_cert_t *c, const uint8_t ca_pk[32], uint64_t now_unix)
{
    uint8_t enc[VBAN_CERT_SIZE], msg[sizeof(k_cert_domain) + CERT_SIGNED_LEN], id[8];
    if (!c || !ca_pk)
        return VBAN_E_ARG;
    vban_ca_id(ca_pk, id);
    if (memcmp(id, c->issuer, 8))
        return VBAN_E_CERT;
    if (vban_cert_encode(c, enc))
        return VBAN_E_CERT;
    cert_message(enc, msg);
    if (crypto_eddsa_check(c->sig, ca_pk, msg, sizeof(msg)))
        return VBAN_E_CERT;
    if (now_unix && (now_unix < c->not_before || now_unix > c->not_after))
        return VBAN_E_CERT;
    return VBAN_OK;
}

int vban_cert_req_encode(const char *name, uint8_t role, const uint8_t pk[32], uint8_t out[VBAN_CERT_REQ_SIZE])
{
    size_t nl;
    if (!pk || !out || !name_ok(name, &nl))
        return VBAN_E_ARG;
    memset(out, 0, VBAN_CERT_REQ_SIZE);
    memcpy(out, "VBR1", 4);
    out[4] = role;
    memcpy(out + 8, pk, 32);
    memcpy(out + 40, name, nl);
    return VBAN_OK;
}

int vban_cert_req_decode(const uint8_t *in, size_t len, char name[VBAN_CERT_NAME_MAX + 1], uint8_t *role,
                         uint8_t pk[32])
{
    size_t i, nl;
    if (!in || !name || !role || !pk)
        return VBAN_E_ARG;
    if (len != VBAN_CERT_REQ_SIZE)
        return VBAN_E_SIZE;
    if (memcmp(in, "VBR1", 4) || in[5] || in[6] || in[7])
        return VBAN_E_FORMAT;
    memset(name, 0, VBAN_CERT_NAME_MAX + 1);
    for (nl = 0; nl < VBAN_CERT_NAME_MAX && in[40 + nl]; ++nl)
        name[nl] = (char)in[40 + nl];
    for (i = nl; i < VBAN_CERT_NAME_MAX; ++i)
        if (in[40 + i])
            return VBAN_E_FORMAT;
    if (!name_ok(name, &nl))
        return VBAN_E_FORMAT;
    *role = in[4];
    memcpy(pk, in + 8, 32);
    return VBAN_OK;
}

/* ------------------------------------------------------------------ */
/* PEM-like text                                                       */
/* ------------------------------------------------------------------ */
static const char k_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int vban_pem_encode(const char *label, const uint8_t *in, size_t len, char *out, size_t cap)
{
    size_t o = 0, i, col = 0, ll;
    if (!label || !in || !out)
        return VBAN_E_ARG;
    ll = strlen(label);
    /* begin/end lines + base64 + newline per 64 chars + NUL */
    if (cap < 2 * (ll + 17) + (len + 2) / 3 * 4 + len / 48 + 3)
        return VBAN_E_NOSPACE;
#define PUTS(s, n) (memcpy(out + o, (s), (n)), o += (n))
    PUTS("-----BEGIN ", 11); PUTS(label, ll); PUTS("-----\n", 6);
    for (i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        size_t rem = len - i;
        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        out[o++] = k_b64[(v >> 18) & 63];
        out[o++] = k_b64[(v >> 12) & 63];
        out[o++] = rem > 1 ? k_b64[(v >> 6) & 63] : '=';
        out[o++] = rem > 2 ? k_b64[v & 63] : '=';
        if ((col += 4) == 64 && i + 3 < len) {
            out[o++] = '\n';
            col = 0;
        }
    }
    out[o++] = '\n';
    PUTS("-----END ", 9); PUTS(label, ll); PUTS("-----\n", 6);
#undef PUTS
    out[o] = 0;
    return (int)o;
}

static int b64v(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static const char *find(const char *h, size_t hl, const char *n, size_t nl)
{
    size_t i;
    if (nl > hl)
        return NULL;
    for (i = 0; i + nl <= hl; ++i)
        if (!memcmp(h + i, n, nl))
            return h + i;
    return NULL;
}

int vban_pem_decode(const char *label, const char *in, size_t inlen, uint8_t *out, size_t cap)
{
    char begin[96], end[96];
    const char *b, *e, *p;
    uint32_t acc = 0;
    int bits = 0, pad = 0;
    size_t o = 0, bl, el;
    if (!label || !in || !out || strlen(label) > 64)
        return VBAN_E_ARG;
    {
        size_t ll = strlen(label);
        memcpy(begin, "-----BEGIN ", 11); memcpy(begin + 11, label, ll); memcpy(begin + 11 + ll, "-----", 5);
        memcpy(end, "-----END ", 9); memcpy(end + 9, label, ll); memcpy(end + 9 + ll, "-----", 5);
        bl = 16 + ll;
        el = 14 + ll;
    }
    b = find(in, inlen, begin, bl);
    if (!b)
        return VBAN_E_NOTFOUND;
    b += bl;
    e = find(b, inlen - (size_t)(b - in), end, el);
    if (!e)
        return VBAN_E_FORMAT;
    for (p = b; p < e; ++p) {
        int v;
        if (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
            continue;
        if (*p == '=') {
            ++pad;
            continue;
        }
        if (pad || (v = b64v(*p)) < 0)
            return VBAN_E_FORMAT;      /* data after padding, or a bad character */
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap)
                return VBAN_E_NOSPACE;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    if (pad > 2 || bits >= 6 || (acc & ((1u << bits) - 1)))
        return VBAN_E_FORMAT;          /* non-canonical tail */
    return (int)o;
}

/* ------------------------------------------------------------------ */
/* identity                                                            */
/* ------------------------------------------------------------------ */
int vban_sec_id_init(vban_sec_id_t *id, const uint8_t sk[32], const uint8_t *cert, size_t cert_len,
                     const uint8_t *ca_cert, size_t ca_len)
{
    vban_cert_t ca;
    if (!id || !sk || !cert || !ca_cert)
        return VBAN_E_ARG;
    memset(id, 0, sizeof(*id));
    if (vban_cert_decode(ca_cert, ca_len, &ca) || !(ca.role & VBAN_CERT_ROLE_CA) ||
        vban_cert_verify(&ca, ca.key, 0))
        return VBAN_E_CERT;
    if (vban_cert_decode(cert, cert_len, &id->cert) || (id->cert.role & VBAN_CERT_ROLE_CA) ||
        vban_cert_verify(&id->cert, ca.key, 0))
        return VBAN_E_CERT;
    memcpy(id->sk, sk, 32);
    crypto_x25519_public_key(id->pk, sk);
    if (crypto_verify32(id->pk, id->cert.key)) {
        crypto_wipe(id, sizeof(*id));
        return VBAN_E_CERT;                /* the certificate is for another key */
    }
    memcpy(id->cert_bytes, cert, VBAN_CERT_SIZE);
    memcpy(id->ca_pk, ca.key, 32);
    return VBAN_OK;
}

/* ------------------------------------------------------------------ */
/* sessions                                                            */
/* ------------------------------------------------------------------ */
static const uint8_t k_prologue[] = "VBAN secure v1";

static void hdr(uint8_t *p, int type, uint32_t from, uint32_t to, uint64_t ctr)
{
    memcpy(p, "VBAN", 4);
    p[4] = VBAN_PROTOCOL_USER;
    p[5] = (uint8_t)type;
    p[6] = 'S';
    p[7] = 1;
    put32(p + 8, from);
    put32(p + 12, to);
    put64(p + 16, ctr);
    put32(p + 24, (uint32_t)ctr);
}

int vban_sec_peek(const uint8_t *in, size_t len, int *type, uint32_t *sender_idx, uint32_t *receiver_idx)
{
    if (!in || len < VBAN_SEC_HDR)
        return VBAN_E_SHORT;
    if (memcmp(in, "VBAN", 4) || in[4] != VBAN_PROTOCOL_USER || in[6] != 'S' || in[7] != 1 ||
        in[5] < VBAN_SEC_HS1 || in[5] > VBAN_SEC_COOKIE)
        return VBAN_E_FORMAT;
    if (type) *type = in[5];
    if (sender_idx) *sender_idx = get32(in + 8);
    if (receiver_idx) *receiver_idx = get32(in + 12);
    return VBAN_OK;
}

void vban_sec_wipe(vban_sec_session_t *s)
{
    crypto_wipe(s, sizeof(*s));
}

static void kill(vban_sec_session_t *s)
{
    vban_sec_wipe(s);
    s->state = VBAN_SEC_DEAD;
}

/* Prologue = constant || the HS1 outer header: binds the initiator's index. */
static void hs_init(vban_sec_session_t *s, const vban_sec_id_t *id, int initiator, const uint8_t e[32],
                    const uint8_t hs1_hdr[VBAN_SEC_HDR])
{
    uint8_t pro[sizeof(k_prologue) + VBAN_SEC_HDR];
    memcpy(pro, k_prologue, sizeof(k_prologue));
    memcpy(pro + sizeof(k_prologue), hs1_hdr, VBAN_SEC_HDR);
    vban_noise_init(&s->hs, initiator, id->sk, e, pro, sizeof(pro));
}

static int check_peer(const vban_sec_id_t *id, const uint8_t *cert, size_t len, const uint8_t rs[32],
                      vban_cert_t *out)
{
    if (vban_cert_decode(cert, len, out) || (out->role & VBAN_CERT_ROLE_CA) ||
        vban_cert_verify(out, id->ca_pk, id->now_unix) || crypto_verify32(out->key, rs))
        return VBAN_E_CERT;
    if (id->authorize && id->authorize(id->authorize_ctx, out))
        return VBAN_E_CERT;
    return VBAN_OK;
}

static int go_up(vban_sec_session_t *s, uint64_t now_ms)
{
    if (vban_noise_split(&s->hs, s->tx_key, s->rx_key, NULL))
        return VBAN_E_STATE;
    s->state = VBAN_SEC_UP;
    s->up_ms = now_ms;
    s->tx_ctr = 0;
    s->rx_any = 0;
    s->rx_top = s->rx_bits = 0;
    return VBAN_OK;
}

int vban_sec_connect(vban_sec_session_t *s, const vban_sec_id_t *id, uint32_t local_idx, uint64_t now_ms,
                     uint8_t *out, size_t cap)
{
    uint8_t e[32];
    int n;
    if (!s || !id || !out || !local_idx)
        return VBAN_E_ARG;
    if (cap < VBAN_SEC_HDR + 32)
        return VBAN_E_NOSPACE;
    vban_sec_wipe(s);
    if (vban_sec_random(e, 32))
        return VBAN_E_UNSUPPORTED;
    hdr(out, VBAN_SEC_HS1, local_idx, 0, 0);
    hs_init(s, id, 1, e, out);
    crypto_wipe(e, sizeof(e));
    n = vban_noise_write(&s->hs, NULL, 0, out + VBAN_SEC_HDR, cap - VBAN_SEC_HDR);
    if (n < 0) {
        kill(s);
        return n;
    }
    s->initiator = 1;
    s->local_idx = local_idx;
    s->state = VBAN_SEC_WAIT_HS2;
    s->hs_ms = now_ms;
    return VBAN_SEC_HDR + n;
}

int vban_sec_accept(vban_sec_session_t *s, const vban_sec_id_t *id, uint32_t local_idx, const uint8_t *in,
                    size_t len, uint64_t now_ms, uint8_t *out, size_t cap)
{
    uint8_t e[32], payload[4 + VBAN_CERT_SIZE];
    int type, n;
    uint32_t from, to;
    if (!s || !id || !in || !out || !local_idx)
        return VBAN_E_ARG;
    if (vban_sec_peek(in, len, &type, &from, &to) || type != VBAN_SEC_HS1 || to != 0 || !from ||
        (len != VBAN_SEC_HDR + 32 && len != VBAN_SEC_HDR + 32 + VBAN_SEC_COOKIE_LEN))
        return VBAN_E_FORMAT;
    if (cap < VBAN_SEC_HS_MAX)
        return VBAN_E_NOSPACE;
    vban_sec_wipe(s);
    if (vban_sec_random(e, 32))
        return VBAN_E_UNSUPPORTED;
    hs_init(s, id, 0, e, in);
    crypto_wipe(e, sizeof(e));
    n = vban_noise_read(&s->hs, in + VBAN_SEC_HDR, 32, payload, 0);   /* a cookie may follow: not Noise */
    if (n < 0) {
        kill(s);
        return n;
    }
    /* HS2 payload: our index (authenticated, unlike the outer header) + our certificate */
    put32(payload, local_idx);
    memcpy(payload + 4, id->cert_bytes, VBAN_CERT_SIZE);
    hdr(out, VBAN_SEC_HS2, local_idx, from, 0);
    n = vban_noise_write(&s->hs, payload, sizeof(payload), out + VBAN_SEC_HDR, cap - VBAN_SEC_HDR);
    if (n < 0) {
        kill(s);
        return n;
    }
    s->initiator = 0;
    s->local_idx = local_idx;
    s->remote_idx = from;
    s->state = VBAN_SEC_WAIT_HS3;
    s->hs_ms = now_ms;
    return VBAN_SEC_HDR + n;
}

/* Replay window: may counter c be accepted? */
static int window_ok(uint64_t top, uint64_t bits, uint8_t any, uint64_t c)
{
    if (!any || c > top)
        return 1;
    if (top - c >= 64)
        return 0;
    return !((bits >> (top - c)) & 1);
}

static void window_mark(uint64_t *top, uint64_t *bits, uint8_t *any, uint64_t c)
{
    if (!*any || c > *top) {
        uint64_t shift = *any ? c - *top : 64;
        *bits = shift >= 64 ? 0 : *bits << shift;
        *bits |= 1;
        *top = c;
        *any = 1;
    } else {
        *bits |= (uint64_t)1 << (*top - c);
    }
}

/* Decrypt a DATA packet with a given key / window. */
static int open_data(const uint8_t key[32], uint64_t *top, uint64_t *bits, uint8_t *any, const uint8_t *in,
                     size_t len, uint8_t *out, size_t cap)
{
    uint64_t c;
    size_t plen;
    if (len < VBAN_SEC_OVERHEAD)
        return VBAN_E_SHORT;
    plen = len - VBAN_SEC_OVERHEAD;
    if (plen > cap)
        return VBAN_E_NOSPACE;
    c = get64(in + 16);
    if ((uint32_t)c != get32(in + 24))
        return VBAN_E_FORMAT;
    if (!window_ok(*top, *bits, *any, c))
        return VBAN_E_REPLAY;
    if (vban_noise_decrypt(key, c, in, VBAN_SEC_HDR, in + VBAN_SEC_HDR, plen, out))
        return VBAN_E_AUTH;
    window_mark(top, bits, any, c);
    return (int)plen;
}

int vban_sec_handle(vban_sec_session_t *s, const vban_sec_id_t *id, const uint8_t *in, size_t len,
                    uint64_t now_ms, uint8_t *out, size_t cap, int *event)
{
    uint8_t payload[4 + VBAN_CERT_SIZE];
    int type, n, r;
    uint32_t from, to;

    if (!s || !id || !in || !out || !event)
        return VBAN_E_ARG;
    *event = VBAN_SEC_EV_NONE;
    if ((r = vban_sec_peek(in, len, &type, &from, &to)) != VBAN_OK)
        return r;
    if (to != s->local_idx)
        return VBAN_E_STATE;

    if (type == VBAN_SEC_DATA) {
        if (s->state != VBAN_SEC_UP || from != s->remote_idx)
            return VBAN_E_STATE;
        if (now_ms - s->up_ms > VBAN_SEC_EXPIRE_MS)
            return VBAN_E_STATE;       /* expired: the initiator must rekey */
        n = open_data(s->rx_key, &s->rx_top, &s->rx_bits, &s->rx_any, in, len, out, cap);
        if (n > 0)
            *event = VBAN_SEC_EV_DATA;         /* n == 0: keepalive, nothing to deliver */
        return n;
    }

    if (type == VBAN_SEC_HS2 && s->state == VBAN_SEC_WAIT_HS2 && s->initiator) {
        vban_cert_t peer;
        n = vban_noise_read(&s->hs, in + VBAN_SEC_HDR, len - VBAN_SEC_HDR, payload, sizeof(payload));
        if (n != (int)sizeof(payload) || get32(payload) != from || !from) {
            kill(s);
            return n < 0 ? n : VBAN_E_AUTH;
        }
        if ((r = check_peer(id, payload + 4, VBAN_CERT_SIZE, s->hs.rs, &peer)) != VBAN_OK) {
            kill(s);
            return r;
        }
        if (cap < VBAN_SEC_HS_MAX) {
            kill(s);
            return VBAN_E_NOSPACE;
        }
        s->remote_idx = from;
        hdr(out, VBAN_SEC_HS3, s->local_idx, from, 0);
        n = vban_noise_write(&s->hs, id->cert_bytes, VBAN_CERT_SIZE, out + VBAN_SEC_HDR, cap - VBAN_SEC_HDR);
        if (n < 0 || go_up(s, now_ms)) {
            kill(s);
            return n < 0 ? n : VBAN_E_STATE;
        }
        s->peer = peer;
        *event = VBAN_SEC_EV_SEND;     /* send HS3; the session is up */
        return VBAN_SEC_HDR + n;
    }

    if (type == VBAN_SEC_HS3 && s->state == VBAN_SEC_WAIT_HS3 && !s->initiator) {
        vban_cert_t peer;
        if (from != s->remote_idx)
            return VBAN_E_STATE;
        n = vban_noise_read(&s->hs, in + VBAN_SEC_HDR, len - VBAN_SEC_HDR, payload, VBAN_CERT_SIZE);
        if (n != VBAN_CERT_SIZE) {
            kill(s);
            return n < 0 ? n : VBAN_E_AUTH;
        }
        if ((r = check_peer(id, payload, VBAN_CERT_SIZE, s->hs.rs, &peer)) != VBAN_OK || go_up(s, now_ms)) {
            kill(s);
            return r ? r : VBAN_E_STATE;
        }
        s->peer = peer;
        *event = VBAN_SEC_EV_UP;
        return 0;
    }
    return VBAN_E_STATE;
}

int vban_sec_seal(vban_sec_session_t *s, const uint8_t *inner, size_t len, uint64_t now_ms, uint8_t *out,
                  size_t cap)
{
    if (!s || (!inner && len) || !out)
        return VBAN_E_ARG;
    if (s->state != VBAN_SEC_UP || now_ms - s->up_ms > VBAN_SEC_EXPIRE_MS || s->tx_ctr >> 60)
        return VBAN_E_STATE;
    if (len > VBAN_SEC_INNER_MAX)
        return VBAN_E_OVERSIZE;
    if (cap < len + VBAN_SEC_OVERHEAD)
        return VBAN_E_NOSPACE;
    hdr(out, VBAN_SEC_DATA, s->local_idx, s->remote_idx, s->tx_ctr);
    vban_noise_encrypt(s->tx_key, s->tx_ctr, out, VBAN_SEC_HDR, len ? inner : out, len, out + VBAN_SEC_HDR);
    s->tx_ctr++;
    return (int)(len + VBAN_SEC_OVERHEAD);
}

/* ------------------------------------------------------------------ */
/* initiator link                                                      */
/* ------------------------------------------------------------------ */
void vban_sec_link_init(vban_sec_link_t *l)
{
    crypto_wipe(l, sizeof(*l));
}

static uint32_t new_idx(const vban_sec_link_t *l)
{
    uint32_t v = 0;
    while (!v || v == l->cur.local_idx || v == l->prev_idx) {
        uint8_t b[4];
        if (vban_sec_random(b, 4))
            return 0;
        v = get32(b);
    }
    return v;
}

int vban_sec_link_up(const vban_sec_link_t *l, uint64_t now_ms)
{
    return l->cur.state == VBAN_SEC_UP && now_ms - l->cur.up_ms <= VBAN_SEC_EXPIRE_MS;
}

int vban_sec_link_tick(vban_sec_link_t *l, const vban_sec_id_t *id, uint64_t now_ms, uint8_t *out, size_t cap)
{
    int need;
    if (l->prev_idx && now_ms >= l->prev_until_ms) {
        crypto_wipe(l->prev_rx_key, 32);
        l->prev_idx = 0;
    }
    if (l->next.state == VBAN_SEC_WAIT_HS2)
        need = now_ms - l->next.hs_ms >= VBAN_SEC_RETRY_MS;      /* no answer: start over */
    else
        need = (!vban_sec_link_up(l, now_ms) || now_ms - l->cur.up_ms >= VBAN_SEC_REKEY_MS) &&
               (!l->tried || now_ms - l->last_try_ms >= VBAN_SEC_RETRY_MS);   /* also after a refusal */
    if (!need) {
        if (vban_sec_link_up(l, now_ms) && now_ms - l->last_tx_ms >= VBAN_SEC_KEEPALIVE_MS)
            return vban_sec_link_seal(l, NULL, 0, now_ms, out, cap);   /* keepalive */
        return 0;
    }
    {
        uint32_t idx = new_idx(l);
        int n;
        if (!idx)
            return VBAN_E_UNSUPPORTED;
        l->tried = 1;
        l->last_try_ms = now_ms;
        l->last_tx_ms = now_ms;
        n = vban_sec_connect(&l->next, id, idx, now_ms, out, cap);
        if (n == VBAN_SEC_HDR + 32) {
            memcpy(l->hs1, out, (size_t)n);
            l->cookie_used = 0;
        }
        return n;
    }
}

int vban_sec_link_handle(vban_sec_link_t *l, const vban_sec_id_t *id, const uint8_t *in, size_t len,
                         uint64_t now_ms, uint8_t *out, size_t cap, int *event)
{
    uint32_t from, to;
    int type, r;
    if (!event)
        return VBAN_E_ARG;
    *event = VBAN_SEC_EV_NONE;
    if ((r = vban_sec_peek(in, len, &type, &from, &to)) != VBAN_OK)
        return r;
    if (type == VBAN_SEC_COOKIE) {         /* the responder is busy: resend HS1 with its cookie, once */
        if (l->next.state != VBAN_SEC_WAIT_HS2 || to != l->next.local_idx || l->cookie_used ||
            len != VBAN_SEC_HDR + VBAN_SEC_COOKIE_LEN || cap < sizeof(l->hs1))
            return VBAN_E_STATE;
        memcpy(out, l->hs1, VBAN_SEC_HDR + 32);
        memcpy(out + VBAN_SEC_HDR + 32, in + VBAN_SEC_HDR, VBAN_SEC_COOKIE_LEN);
        l->cookie_used = 1;
        l->last_tx_ms = now_ms;
        *event = VBAN_SEC_EV_SEND;
        return (int)sizeof(l->hs1);
    }
    if (l->next.state == VBAN_SEC_WAIT_HS2 && to == l->next.local_idx) {
        r = vban_sec_handle(&l->next, id, in, len, now_ms, out, cap, event);
        if (r >= 0 && l->next.state == VBAN_SEC_UP) {
            if (l->cur.state == VBAN_SEC_UP) {         /* keep the old receive key a little */
                memcpy(l->prev_rx_key, l->cur.rx_key, 32);
                l->prev_idx = l->cur.local_idx;
                l->prev_top = l->cur.rx_top;
                l->prev_bits = l->cur.rx_bits;
                l->prev_until_ms = now_ms + VBAN_SEC_PREV_MS;
            }
            l->cur = l->next;
            vban_sec_wipe(&l->next);
        }
        return r;
    }
    if (to == l->cur.local_idx && l->cur.state == VBAN_SEC_UP)
        return vban_sec_handle(&l->cur, id, in, len, now_ms, out, cap, event);
    if (l->prev_idx && to == l->prev_idx && type == VBAN_SEC_DATA && now_ms < l->prev_until_ms) {
        uint8_t any = 1;
        r = open_data(l->prev_rx_key, &l->prev_top, &l->prev_bits, &any, in, len, out, cap);
        if (r > 0)
            *event = VBAN_SEC_EV_DATA;
        return r;
    }
    return VBAN_E_STATE;
}

int vban_sec_link_seal(vban_sec_link_t *l, const uint8_t *inner, size_t len, uint64_t now_ms, uint8_t *out,
                       size_t cap)
{
    int n = vban_sec_seal(&l->cur, inner, len, now_ms, out, cap);
    if (n > 0)
        l->last_tx_ms = now_ms;
    return n;
}

/* ------------------------------------------------------------------ */
/* responder table                                                     */
/* ------------------------------------------------------------------ */
#define STALE_HS_MS 5000u

void vban_sec_server_init(vban_sec_server_t *srv, vban_sec_peer_t *peers, unsigned n, unsigned hs_per_sec)
{
    memset(srv, 0, sizeof(*srv));
    crypto_wipe(peers, sizeof(*peers) * n);
    srv->peers = peers;
    srv->n = n;
    srv->hs_per_sec = hs_per_sec ? hs_per_sec : 20;
    srv->hs_tokens = srv->hs_per_sec;
    srv->cookie_tokens = srv->hs_per_sec;
    vban_sec_random(srv->cookie_key, 32);
    memcpy(srv->cookie_prev, srv->cookie_key, 32);
}

/* MAC of the initiator's address and index under a key that rotates every 2 minutes. */
static void make_cookie(const uint8_t key[32], const vban_addr_t *from, uint32_t sidx, uint8_t out[VBAN_SEC_COOKIE_LEN])
{
    uint8_t m[10];
    put32(m, from->ip);
    m[4] = (uint8_t)from->port;
    m[5] = (uint8_t)(from->port >> 8);
    put32(m + 6, sidx);
    crypto_blake2b_keyed(out, VBAN_SEC_COOKIE_LEN, key, 32, m, sizeof(m));
}

static int cookie_ok(const vban_sec_server_t *srv, const uint8_t *in, size_t len, const vban_addr_t *from, uint32_t sidx)
{
    uint8_t c[VBAN_SEC_COOKIE_LEN];
    if (len != VBAN_SEC_HDR + 32 + VBAN_SEC_COOKIE_LEN)
        return 0;
    make_cookie(srv->cookie_key, from, sidx, c);
    if (!crypto_verify16(c, in + VBAN_SEC_HDR + 32))
        return 1;
    make_cookie(srv->cookie_prev, from, sidx, c);
    return !crypto_verify16(c, in + VBAN_SEC_HDR + 32);
}

static int slot_free(const vban_sec_session_t *s, uint64_t now_ms)
{
    return s->state == VBAN_SEC_IDLE || s->state == VBAN_SEC_DEAD ||
           (s->state == VBAN_SEC_WAIT_HS3 && now_ms - s->hs_ms > STALE_HS_MS) ||
           (s->state == VBAN_SEC_UP && now_ms - s->up_ms > VBAN_SEC_EXPIRE_MS);
}

int vban_sec_server_handle(vban_sec_server_t *srv, const vban_sec_id_t *id, const uint8_t *in, size_t len,
                           const vban_addr_t *from, uint64_t now_ms, uint8_t *out, size_t cap, int *event,
                           vban_sec_peer_t **peer)
{
    uint32_t sidx, ridx;
    unsigned i;
    int type, r;
    if (!srv || !from || !event || !peer)
        return VBAN_E_ARG;
    *event = VBAN_SEC_EV_NONE;
    *peer = NULL;
    if ((r = vban_sec_peek(in, len, &type, &sidx, &ridx)) != VBAN_OK)
        return r;
    if (type == VBAN_SEC_HS1) {
        vban_sec_peer_t *p = NULL;
        uint32_t idx = 0;
        int with_cookie = 0;
        if (now_ms - srv->hs_refill_ms >= 1000) {
            srv->hs_tokens = srv->hs_per_sec;
            srv->cookie_tokens = srv->hs_per_sec;
            srv->hs_refill_ms = now_ms;
        }
        if (now_ms - srv->cookie_ms >= 120000) {
            memcpy(srv->cookie_prev, srv->cookie_key, 32);
            vban_sec_random(srv->cookie_key, 32);
            srv->cookie_ms = now_ms;
        }
        if (!srv->hs_tokens) {
            if (!cookie_ok(srv, in, len, from, sidx)) {
                if (cap < VBAN_SEC_HDR + VBAN_SEC_COOKIE_LEN)
                    return VBAN_E_NOSPACE;
                hdr(out, VBAN_SEC_COOKIE, 0, sidx, 0);   /* smaller than the HS1: no amplification */
                make_cookie(srv->cookie_key, from, sidx, out + VBAN_SEC_HDR);
                srv->hs_cookies++;
                *event = VBAN_SEC_EV_SEND;
                return VBAN_SEC_HDR + VBAN_SEC_COOKIE_LEN;
            }
            if (!srv->cookie_tokens) {
                srv->hs_refused++;
                return VBAN_E_NOSPACE;
            }
            with_cookie = 1;
        }
        for (i = 0; i < srv->n && !p; ++i)
            if (slot_free(&srv->peers[i].s, now_ms))
                p = &srv->peers[i];
        /* Full: take the oldest unfinished handshake. Half-open slots from a flood then
         * churn instead of locking new peers out for 5 s; a real peer completes in one
         * round trip, long before a flood at the rate limit reaches its slot again.
         * Established sessions are never evicted. */
        for (i = 0; i < srv->n && !p; ++i) {
            vban_sec_peer_t *q = &srv->peers[i];
            unsigned k;
            if (q->s.state != VBAN_SEC_WAIT_HS3)
                continue;
            p = q;
            for (k = i + 1; k < srv->n; ++k)
                if (srv->peers[k].s.state == VBAN_SEC_WAIT_HS3 && srv->peers[k].s.hs_ms < p->s.hs_ms)
                    p = &srv->peers[k];
            srv->hs_evicted++;
        }
        if (!p) {
            srv->hs_refused++;
            return VBAN_E_NOSPACE;
        }
        if (with_cookie)
            srv->cookie_tokens--;
        else
            srv->hs_tokens--;
        while (!idx) {                     /* random, unique among live slots */
            uint8_t b[4];
            if (vban_sec_random(b, 4))
                return VBAN_E_UNSUPPORTED;
            idx = get32(b);
            for (i = 0; i < srv->n && idx; ++i)
                if (srv->peers[i].s.local_idx == idx)
                    idx = 0;
        }
        r = vban_sec_accept(&p->s, id, idx, in, len, now_ms, out, cap);
        if (r > 0) {
            p->addr = *from;
            *event = VBAN_SEC_EV_SEND;
            *peer = p;
        }
        return r;
    }
    for (i = 0; i < srv->n; ++i) {
        vban_sec_peer_t *p = &srv->peers[i];
        if (p->s.local_idx != ridx || !ridx || p->s.state == VBAN_SEC_IDLE || p->s.state == VBAN_SEC_DEAD)
            continue;
        r = vban_sec_handle(&p->s, id, in, len, now_ms, out, cap, event);
        if (r >= 0) {
            p->addr = *from;               /* authenticated: follow the peer */
            *peer = p;
        }
        return r;
    }
    return VBAN_E_STATE;
}
