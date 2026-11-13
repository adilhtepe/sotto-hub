/*
 * VBAN SDK - Noise_XX_25519_ChaChaPoly_BLAKE2b, see vban/vban_noise.h.
 * Follows the Noise specification rev 34, sections 4 (crypto functions),
 * 5 (processing rules) and 7.5 (XX pattern). Checked against the cacophony
 * test vectors in tests/test_secure.c.
 */
#include "vban/vban_noise.h"
#include "vban/vban_proto.h"
#include "monocypher.h"
#include <string.h>

static const char k_protocol[] = "Noise_XX_25519_ChaChaPoly_BLAKE2b";

/* ---- crypto functions (spec section 4) ---- */

void vban_noise_encrypt(const uint8_t key[32], uint64_t n, const uint8_t *ad, size_t adlen,
                        const uint8_t *in, size_t len, uint8_t *out)
{
    crypto_aead_ctx ctx;
    uint8_t nonce[12] = { 0 };
    unsigned i;
    for (i = 0; i < 8; ++i)
        nonce[4 + i] = (uint8_t)(n >> (8 * i));
    /* One message per freshly initialised context = RFC 8439 ChaCha20-Poly1305
     * (Monocypher's stream interface would ratchet the key after each message). */
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, out, out + len, ad, adlen, in, len);
    crypto_wipe(&ctx, sizeof(ctx));
}

int vban_noise_decrypt(const uint8_t key[32], uint64_t n, const uint8_t *ad, size_t adlen,
                       const uint8_t *in, size_t len, uint8_t *out)
{
    crypto_aead_ctx ctx;
    uint8_t nonce[12] = { 0 };
    unsigned i;
    int r;
    for (i = 0; i < 8; ++i)
        nonce[4 + i] = (uint8_t)(n >> (8 * i));
    crypto_aead_init_ietf(&ctx, key, nonce);
    r = crypto_aead_read(&ctx, out, in + len, ad, adlen, in, len);
    crypto_wipe(&ctx, sizeof(ctx));
    if (r) {
        memset(out, 0, len);
        return VBAN_E_AUTH;
    }
    return 0;
}

/* HMAC-BLAKE2b-512 (RFC 2104 construction, block 128 bytes, as Noise requires). */
static void hmac(uint8_t out[64], const uint8_t *key, size_t klen, const uint8_t *d1, size_t l1,
                 const uint8_t *d2, size_t l2)
{
    uint8_t k[128], pad[128], inner[64];
    crypto_blake2b_ctx c;
    unsigned i;

    memset(k, 0, sizeof(k));
    if (klen > 128)
        crypto_blake2b(k, 64, key, klen);
    else
        memcpy(k, key, klen);
    for (i = 0; i < 128; ++i)
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    crypto_blake2b_init(&c, 64);
    crypto_blake2b_update(&c, pad, 128);
    crypto_blake2b_update(&c, d1, l1);
    if (l2)
        crypto_blake2b_update(&c, d2, l2);
    crypto_blake2b_final(&c, inner);
    for (i = 0; i < 128; ++i)
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    crypto_blake2b_init(&c, 64);
    crypto_blake2b_update(&c, pad, 128);
    crypto_blake2b_update(&c, inner, 64);
    crypto_blake2b_final(&c, out);
    crypto_wipe(k, sizeof(k));
    crypto_wipe(pad, sizeof(pad));
    crypto_wipe(inner, sizeof(inner));
}

/* HKDF(ck, ikm) with two outputs. */
static void hkdf2(const uint8_t ck[64], const uint8_t *ikm, size_t ilen, uint8_t o1[64], uint8_t o2[64])
{
    uint8_t temp[64], one = 1, two = 2;
    hmac(temp, ck, 64, ikm, ilen, NULL, 0);
    hmac(o1, temp, 64, &one, 1, NULL, 0);
    hmac(o2, temp, 64, o1, 64, &two, 1);
    crypto_wipe(temp, sizeof(temp));
}

/* DH; refuses an all-zero result (low-order peer key). */
static int dh(uint8_t out[32], const uint8_t sk[32], const uint8_t pk[32])
{
    uint8_t acc = 0;
    unsigned i;
    crypto_x25519(out, sk, pk);
    for (i = 0; i < 32; ++i)
        acc |= out[i];
    return acc ? 0 : VBAN_E_AUTH;
}

/* ---- symmetric state (spec 5.2) ---- */

static void mix_hash(vban_noise_hs_t *hs, const uint8_t *d, size_t len)
{
    crypto_blake2b_ctx c;
    crypto_blake2b_init(&c, 64);
    crypto_blake2b_update(&c, hs->h, 64);
    crypto_blake2b_update(&c, d, len);
    crypto_blake2b_final(&c, hs->h);
}

static void mix_key(vban_noise_hs_t *hs, const uint8_t ikm[32])
{
    uint8_t temp_k[64];
    hkdf2(hs->ck, ikm, 32, hs->ck, temp_k);
    memcpy(hs->cs.k, temp_k, 32);       /* HASHLEN 64: truncate to 32 */
    hs->cs.n = 0;
    hs->cs.has_key = 1;
    crypto_wipe(temp_k, sizeof(temp_k));
}

static int mix_dh(vban_noise_hs_t *hs, const uint8_t sk[32], const uint8_t pk[32])
{
    uint8_t shared[32];
    int r = dh(shared, sk, pk);
    if (!r)
        mix_key(hs, shared);
    crypto_wipe(shared, sizeof(shared));
    return r;
}

/* EncryptAndHash: out gets len (+16 if keyed) bytes. */
static size_t encrypt_and_hash(vban_noise_hs_t *hs, const uint8_t *in, size_t len, uint8_t *out)
{
    size_t olen = len;
    if (hs->cs.has_key) {
        vban_noise_encrypt(hs->cs.k, hs->cs.n++, hs->h, 64, in, len, out);
        olen += VBAN_NOISE_TAGLEN;
    } else if (len) {
        memmove(out, in, len);
    }
    mix_hash(hs, out, olen);
    return olen;
}

/* DecryptAndHash: in has len bytes (including the tag if keyed). Returns plaintext length. */
static int decrypt_and_hash(vban_noise_hs_t *hs, const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t hprev[64];
    int r;
    if (!hs->cs.has_key) {
        if (len)
            memmove(out, in, len);
        mix_hash(hs, in, len);
        return (int)len;
    }
    if (len < VBAN_NOISE_TAGLEN)
        return VBAN_E_SHORT;
    memcpy(hprev, hs->h, 64);
    mix_hash(hs, in, len);                     /* h covers the ciphertext */
    r = vban_noise_decrypt(hs->cs.k, hs->cs.n, hprev, 64, in, len - VBAN_NOISE_TAGLEN, out);
    if (r)
        return r;
    hs->cs.n++;
    return (int)(len - VBAN_NOISE_TAGLEN);
}

/* ---- handshake state (spec 5.3, pattern XX) ---- */

void vban_noise_init(vban_noise_hs_t *hs, int initiator, const uint8_t s_sk[32], const uint8_t e_sk[32],
                     const uint8_t *prologue, size_t prologue_len)
{
    memset(hs, 0, sizeof(*hs));
    /* protocol name (33 bytes) <= HASHLEN: h = name padded with zeros */
    memcpy(hs->h, k_protocol, sizeof(k_protocol) - 1);
    memcpy(hs->ck, hs->h, 64);
    mix_hash(hs, prologue, prologue_len);
    memcpy(hs->s_sk, s_sk, 32);
    crypto_x25519_public_key(hs->s_pk, s_sk);
    memcpy(hs->e_sk, e_sk, 32);
    crypto_x25519_public_key(hs->e_pk, e_sk);
    hs->initiator = (uint8_t)(initiator != 0);
    hs->step = 1;
}

static int my_turn(const vban_noise_hs_t *hs)
{
    /* initiator writes 1 and 3, responder writes 2 */
    return hs->initiator ? (hs->step == 1 || hs->step == 3) : hs->step == 2;
}

int vban_noise_write(vban_noise_hs_t *hs, const uint8_t *payload, size_t plen, uint8_t *out, size_t cap)
{
    size_t off = 0, need;
    int r = 0;

    if (hs->failed || hs->step > 3 || !my_turn(hs))
        return VBAN_E_STATE;
    need = (hs->step == 1 ? 32 : hs->step == 2 ? 32 + 48 : 48) + plen + (hs->step == 1 ? 0 : 16);
    if (cap < need)
        return VBAN_E_NOSPACE;
    switch (hs->step) {
    case 1:                                    /* -> e */
        memcpy(out, hs->e_pk, 32);
        mix_hash(hs, hs->e_pk, 32);
        off = 32;
        break;
    case 2:                                    /* <- e, ee, s, es */
        memcpy(out, hs->e_pk, 32);
        mix_hash(hs, hs->e_pk, 32);
        off = 32;
        r = mix_dh(hs, hs->e_sk, hs->re);      /* ee */
        if (!r) {
            off += encrypt_and_hash(hs, hs->s_pk, 32, out + off);   /* s */
            r = mix_dh(hs, hs->s_sk, hs->re);  /* es (responder: s, re) */
        }
        break;
    case 3:                                    /* -> s, se */
        off = encrypt_and_hash(hs, hs->s_pk, 32, out);              /* s */
        r = mix_dh(hs, hs->s_sk, hs->re);      /* se (initiator: s, re) */
        break;
    }
    if (r) {
        hs->failed = 1;
        return r;
    }
    off += encrypt_and_hash(hs, payload, plen, out + off);
    hs->step++;
    return (int)off;
}

int vban_noise_read(vban_noise_hs_t *hs, const uint8_t *msg, size_t len, uint8_t *payload_out, size_t cap)
{
    size_t off = 0;
    int r = 0;

    if (hs->failed || hs->step > 3 || my_turn(hs))
        return VBAN_E_STATE;
    switch (hs->step) {
    case 1:                                    /* responder reads: e */
        if (len < 32)
            return VBAN_E_SHORT;
        memcpy(hs->re, msg, 32);
        mix_hash(hs, hs->re, 32);
        off = 32;
        break;
    case 2:                                    /* initiator reads: e, ee, s, es */
        if (len < 32 + 48 + 16)
            return VBAN_E_SHORT;
        memcpy(hs->re, msg, 32);
        mix_hash(hs, hs->re, 32);
        off = 32;
        r = mix_dh(hs, hs->e_sk, hs->re);      /* ee */
        if (!r)
            r = decrypt_and_hash(hs, msg + off, 48, hs->rs) == 32 ? 0 : VBAN_E_AUTH;
        off += 48;
        if (!r)
            r = mix_dh(hs, hs->e_sk, hs->rs);  /* es (initiator: e, rs) */
        break;
    case 3:                                    /* responder reads: s, se */
        if (len < 48 + 16)
            return VBAN_E_SHORT;
        r = decrypt_and_hash(hs, msg, 48, hs->rs) == 32 ? 0 : VBAN_E_AUTH;
        off = 48;
        if (!r)
            r = mix_dh(hs, hs->e_sk, hs->rs);  /* se (responder: e, rs) */
        break;
    }
    if (!r) {
        size_t clen = len - off;
        size_t plen = hs->cs.has_key ? clen - VBAN_NOISE_TAGLEN : clen;
        if (plen > cap)
            r = VBAN_E_NOSPACE;
        else
            r = decrypt_and_hash(hs, msg + off, clen, payload_out);
    }
    if (r < 0) {
        hs->failed = 1;
        vban_noise_wipe(hs);
        hs->failed = 1;
        return r;
    }
    hs->step++;
    return r;
}

int vban_noise_split(vban_noise_hs_t *hs, uint8_t send_key[32], uint8_t recv_key[32], uint8_t hash[64])
{
    uint8_t k1[64], k2[64], none = 0;
    if (hs->failed || hs->step != 4)
        return VBAN_E_STATE;
    hkdf2(hs->ck, &none, 0, k1, k2);
    memcpy(hs->initiator ? send_key : recv_key, k1, 32);
    memcpy(hs->initiator ? recv_key : send_key, k2, 32);
    if (hash)
        memcpy(hash, hs->h, 64);
    crypto_wipe(k1, sizeof(k1));
    crypto_wipe(k2, sizeof(k2));
    vban_noise_wipe(hs);
    hs->step = 4;
    return 0;
}

void vban_noise_wipe(vban_noise_hs_t *hs)
{
    uint8_t rs[32];
    memcpy(rs, hs->rs, 32);                    /* the peer's static key is public: keep it */
    crypto_wipe(hs, sizeof(*hs));
    memcpy(hs->rs, rs, 32);
}
