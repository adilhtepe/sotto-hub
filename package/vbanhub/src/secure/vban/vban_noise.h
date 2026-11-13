/*
 * VBAN SDK - Noise_XX_25519_ChaChaPoly_BLAKE2b (Noise Protocol Framework rev 34).
 *
 * Internal building block of the secure layer (vban_secure.h); exposed so the
 * tests can check it against the published Noise test vectors. Primitives come
 * from Monocypher. No allocation; a handshake state is ~500 bytes.
 *
 *   initiator                     responder
 *   -> e                          (message 1)
 *   <- e, ee, s, es   + payload   (message 2)
 *   -> s, se          + payload   (message 3)
 *   split() -> one key per direction
 */
#ifndef VBAN_NOISE_H
#define VBAN_NOISE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define VBAN_NOISE_HASHLEN 64
#define VBAN_NOISE_DHLEN   32
#define VBAN_NOISE_TAGLEN  16

typedef struct vban_noise_cipher {
    uint8_t  k[32];
    uint64_t n;
    uint8_t  has_key;
} vban_noise_cipher_t;

typedef struct vban_noise_hs {
    uint8_t ck[VBAN_NOISE_HASHLEN];
    uint8_t h[VBAN_NOISE_HASHLEN];
    vban_noise_cipher_t cs;
    uint8_t s_sk[32], s_pk[32];      /* own static */
    uint8_t e_sk[32], e_pk[32];      /* own ephemeral */
    uint8_t rs[32], re[32];          /* remote static / ephemeral */
    uint8_t initiator;
    uint8_t step;                    /* next message number, 1..3; 4 = done */
    uint8_t failed;
} vban_noise_hs_t;

/* Start a handshake. s_sk = own static X25519 secret. e_sk = ephemeral secret
 * (random; tests pass fixed ones). The prologue is mixed into the transcript. */
void vban_noise_init(vban_noise_hs_t *hs, int initiator, const uint8_t s_sk[32], const uint8_t e_sk[32],
                     const uint8_t *prologue, size_t prologue_len);

/* Write the next handshake message (with payload) into out. Returns its length,
 * or a negative VBAN_E_* code (wrong turn, buffer too small). */
int vban_noise_write(vban_noise_hs_t *hs, const uint8_t *payload, size_t plen, uint8_t *out, size_t cap);

/* Read the next handshake message; the decrypted payload goes to payload_out.
 * Returns the payload length or a negative VBAN_E_* code (VBAN_E_AUTH if it
 * does not authenticate). Any failure poisons the state for good. */
int vban_noise_read(vban_noise_hs_t *hs, const uint8_t *msg, size_t len, uint8_t *payload_out, size_t cap);

/* After message 3: the two transport keys (send / receive for this side) and
 * the handshake hash (channel binding). Wipes the handshake secrets. */
int vban_noise_split(vban_noise_hs_t *hs, uint8_t send_key[32], uint8_t recv_key[32], uint8_t hash[64]);

/* Wipe all secrets. */
void vban_noise_wipe(vban_noise_hs_t *hs);

/* ChaCha20-Poly1305 (RFC 8439) with the Noise nonce layout: 4 zero bytes then the
 * 64-bit counter, little endian. out = ciphertext || 16-byte tag. */
void vban_noise_encrypt(const uint8_t key[32], uint64_t n, const uint8_t *ad, size_t adlen,
                        const uint8_t *in, size_t len, uint8_t *out);
/* Returns 0, or VBAN_E_AUTH if the tag does not match (out is then zeroed). */
int vban_noise_decrypt(const uint8_t key[32], uint64_t n, const uint8_t *ad, size_t adlen,
                       const uint8_t *in, size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif
#endif
