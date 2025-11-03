/* =========================================================================
 * sha512.h — SHA‑512, HMAC‑SHA‑512, HKDF‑SHA‑512 (RFC 6234 / RFC 4231 / RFC 5869)
 * C99 순수 구현 (동적 할당 없음). 라이선스: 퍼블릭 도메인/CC0 유사.
 * ------------------------------------------------------------------------- */
#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_DIGEST_LEN 64u
#define SHA512_BLOCK_LEN  128u

typedef struct {
    uint64_t h[8];
    uint64_t tot_len_hi;
    uint64_t tot_len_lo;
    uint8_t  buf[SHA512_BLOCK_LEN];
    size_t   buf_len;
} SHA512_CTX;

void sha512_init(SHA512_CTX* c);
void sha512_update(SHA512_CTX* c, const void* data, size_t len);
void sha512_final(SHA512_CTX* c, uint8_t out[SHA512_DIGEST_LEN]);
void sha512(const void* data, size_t len, uint8_t out[SHA512_DIGEST_LEN]);

#define HMAC_SHA512_LEN 64u
void hmac_sha512(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[HMAC_SHA512_LEN]);
int hmac_sha512_verify(const uint8_t* key, size_t key_len,
                       const uint8_t* msg, size_t msg_len,
                       const uint8_t* tag, size_t tag_len);

#define HKDF_SHA512_PRK_LEN 64u
#define HKDF_SHA512_OK   0
#define HKDF_SHA512_ERR -1

void hkdf_sha512_extract(const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm,  size_t ikm_len,
                         uint8_t prk[HKDF_SHA512_PRK_LEN]);
int hkdf_sha512_expand(const uint8_t* prk,
                       const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len);
int hkdf_sha512(const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm,  size_t ikm_len,
                const uint8_t* info, size_t info_len,
                uint8_t* okm, size_t okm_len);

void secure_zero(void* p, size_t n);
int  ct_memcmp(const void* a, const void* b, size_t n);

int sha512_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* SHA512_H */
