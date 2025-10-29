#include "aes2_secure.h"
#include <string.h>
#include <stdlib.h>

// Internal constants
#define AES2_TAG_MAX 32

// ─────────────────────────────────────────────────────────────────────────────
// Secure memory wipe (portable)
// ─────────────────────────────────────────────────────────────────────────────
void AES2_secure_zero(void* p, size_t n) {
    if (!p || n==0) return;
    volatile unsigned char* vp = (volatile unsigned char*)p;
    while (n--) { *vp++ = 0; }
}

int AES2_ct_memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    unsigned int diff = 0;
    for (size_t i=0; i<n; ++i) diff |= (unsigned int)(pa[i] ^ pb[i]);
    return diff; // 0 if equal
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal SHA-256 implementation (FIPS 180-4)
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    uint32_t state[8];
    uint64_t bitcount; // total bits processed
    uint8_t  buffer[64];
} aes2_sha256_ctx;

static inline uint32_t rotr32(uint32_t x, uint32_t n){ return (x>>n) | (x<<(32-n)); }

static void aes2_sha256_init(aes2_sha256_ctx* ctx) {
    static const uint32_t H0[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->bitcount = 0;
}

static void aes2_sha256_compress(aes2_sha256_ctx* ctx, const uint8_t block[64]) {
    static const uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    uint32_t W[64];
    for (int i=0;i<16;i++) {
        W[i] = ((uint32_t)block[4*i]<<24) | ((uint32_t)block[4*i+1]<<16) |
               ((uint32_t)block[4*i+2]<<8) | ((uint32_t)block[4*i+3]);
    }
    for (int i=16;i<64;i++) {
        uint32_t s0 = rotr32(W[i-15],7) ^ rotr32(W[i-15],18) ^ (W[i-15]>>3);
        uint32_t s1 = rotr32(W[i-2],17) ^ rotr32(W[i-2],19) ^ (W[i-2]>>10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    uint32_t a=ctx->state[0], b=ctx->state[1], c=ctx->state[2], d=ctx->state[3];
    uint32_t e=ctx->state[4], f=ctx->state[5], g=ctx->state[6], h=ctx->state[7];

    for (int i=0;i<64;i++) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e;
        e = d + temp1;
        d = c; c = b; b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void aes2_sha256_update(aes2_sha256_ctx* ctx, const uint8_t* data, size_t len) {
    size_t have = (size_t)((ctx->bitcount >> 3) & 0x3F);
    size_t need = 64 - have;
    ctx->bitcount += (uint64_t)len * 8u;

    if (len >= need) {
        if (have) { memcpy(ctx->buffer + have, data, need); aes2_sha256_compress(ctx, ctx->buffer); data += need; len -= need; have = 0; }
        while (len >= 64) { aes2_sha256_compress(ctx, data); data += 64; len -= 64; }
    }
    if (len) memcpy(ctx->buffer + have, data, len);
}

static void aes2_sha256_final(aes2_sha256_ctx* ctx, uint8_t out[32]) {
    uint8_t pad[64+8];
    size_t have = (size_t)((ctx->bitcount >> 3) & 0x3F);
    size_t padlen = (have < 56) ? (56 - have) : (56 + 64 - have);
    pad[0] = 0x80; memset(pad+1, 0x00, padlen-1);

    uint64_t bits_be = ctx->bitcount; // big-endian write
    uint8_t lenbuf[8];
    for (int i=0;i<8;i++) lenbuf[7-i] = (uint8_t)(bits_be >> (i*8));

    aes2_sha256_update(ctx, pad, padlen);
    aes2_sha256_update(ctx, lenbuf, 8);

    for (int i=0;i<8;i++) {
        out[4*i+0] = (uint8_t)(ctx->state[i] >> 24);
        out[4*i+1] = (uint8_t)(ctx->state[i] >> 16);
        out[4*i+2] = (uint8_t)(ctx->state[i] >> 8);
        out[4*i+3] = (uint8_t)(ctx->state[i]);
    }
    AES2_secure_zero(ctx, sizeof(*ctx));
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 (RFC 2104)
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    aes2_sha256_ctx inner;
    aes2_sha256_ctx outer;
} aes2_hmac_ctx;

static void aes2_hmac_init(aes2_hmac_ctx* ctx, const uint8_t* key, size_t key_len) {
    uint8_t kopad[64];
    uint8_t kipad[64];
    uint8_t khash[32];
    if (key_len > 64) {
        aes2_sha256_ctx t; aes2_sha256_init(&t); aes2_sha256_update(&t, key, key_len); aes2_sha256_final(&t, khash);
        key = khash; key_len = 32;
    }
    memset(kopad, 0x00, sizeof(kopad));
    memset(kipad, 0x00, sizeof(kipad));
    memcpy(kopad, key, key_len);
    memcpy(kipad, key, key_len);
    for (size_t i=0;i<64;i++){ kopad[i]^=0x5c; kipad[i]^=0x36; }

    aes2_sha256_init(&ctx->inner); aes2_sha256_update(&ctx->inner, kipad, 64);
    aes2_sha256_init(&ctx->outer); aes2_sha256_update(&ctx->outer, kopad, 64);
    AES2_secure_zero(khash, sizeof(khash)); AES2_secure_zero(kopad, sizeof(kopad)); AES2_secure_zero(kipad, sizeof(kipad));
}

static void aes2_hmac_update(aes2_hmac_ctx* ctx, const uint8_t* data, size_t len) {
    aes2_sha256_update(&ctx->inner, data, len);
}

static void aes2_hmac_final(aes2_hmac_ctx* ctx, uint8_t out[32]) {
    uint8_t ihash[32];
    aes2_sha256_final(&ctx->inner, ihash);
    aes2_sha256_update(&ctx->outer, ihash, 32);
    aes2_sha256_final(&ctx->outer, out);
    AES2_secure_zero(ihash, sizeof(ihash));
}

static void aes2_hmac_sha256_multi(const uint8_t* key, size_t key_len,
                                   const uint8_t** parts, const size_t* lens, size_t count,
                                   uint8_t out[32]){
    aes2_hmac_ctx h; aes2_hmac_init(&h, key, key_len);
    for (size_t i=0;i<count;i++) if (parts[i] && lens[i]) aes2_hmac_update(&h, parts[i], lens[i]);
    aes2_hmac_final(&h, out);
}

// ─────────────────────────────────────────────────────────────────────────────
// HKDF (RFC 5869) using HMAC-SHA256
// ─────────────────────────────────────────────────────────────────────────────
static void aes2_hkdf_extract(const uint8_t* salt, size_t salt_len,
                              const uint8_t* ikm, size_t ikm_len,
                              uint8_t prk[32]){
    // HMAC(salt, ikm) — if salt is NULL/empty, use zeros of HashLen
    uint8_t zeros[32];
    if (!salt || salt_len==0) { memset(zeros, 0x00, sizeof(zeros)); salt = zeros; salt_len = sizeof(zeros); }
    const uint8_t* parts[1] = { ikm };
    size_t lens[1] = { ikm_len };
    aes2_hmac_sha256_multi(salt, salt_len, parts, lens, 1, prk);
    AES2_secure_zero(zeros, sizeof(zeros));
}

static void aes2_hkdf_expand(const uint8_t prk[32],
                             const uint8_t* info, size_t info_len,
                             uint8_t* okm, size_t okm_len){
    uint8_t T[32]; size_t Tlen = 0; size_t pos = 0; uint8_t counter = 1;
    while (pos < okm_len) {
        aes2_hmac_ctx h; aes2_hmac_init(&h, prk, 32);
        if (Tlen) aes2_hmac_update(&h, T, Tlen);
        if (info && info_len) aes2_hmac_update(&h, info, info_len);
        aes2_hmac_update(&h, &counter, 1);
        aes2_hmac_final(&h, T);
        size_t copy = (okm_len - pos > 32) ? 32 : (okm_len - pos);
        memcpy(okm + pos, T, copy);
        pos += copy; Tlen = 32; counter++;
    }
    AES2_secure_zero(T, sizeof(T));
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers for domain-separated info
// ─────────────────────────────────────────────────────────────────────────────
static size_t aes2_build_info(const uint8_t* user_info, size_t user_info_len,
                              const char* label, uint8_t* out, size_t out_cap){
    size_t label_len = strlen(label);
    if (user_info_len + label_len > out_cap) return 0;
    size_t pos = 0;
    if (user_info && user_info_len) { memcpy(out+pos, user_info, user_info_len); pos += user_info_len; }
    memcpy(out+pos, label, label_len); pos += label_len;
    return pos;
}

// ─────────────────────────────────────────────────────────────────────────────
// AES2 API
// ─────────────────────────────────────────────────────────────────────────────
AESStatus AES2_init_hardened(AES2_SecCtx* s,
                             const uint8_t* master_key, AESKeyLength keyLen,
                             const AES2_KDFParams* kdf,
                             AES2_Flags flags,
                             uint8_t mac_tag_len){
    if (!s || !master_key) return AES_ERR_BAD_PARAM;
    if (keyLen!=AES128 && keyLen!=AES192 && keyLen!=AES256) return AES_ERR_BAD_PARAM;
    if ((flags & AES2_F_MAC_ENABLE) && !(mac_tag_len==16 || mac_tag_len==32)) return AES_ERR_BAD_PARAM;

    // Derive encryption key (keyLen) and optional MAC key (32) using HKDF-SHA256
    uint8_t prk[32];
    aes2_hkdf_extract(kdf? kdf->salt: NULL, kdf? kdf->salt_len: 0, master_key, (size_t)keyLen, prk);

    uint8_t info_enc[128];
    size_t info_enc_len = aes2_build_info(kdf? kdf->info: NULL, kdf? kdf->info_len: 0, "|AES2|enc", info_enc, sizeof(info_enc));
    if (info_enc_len==0 && kdf && kdf->info_len) { AES2_secure_zero(prk, sizeof(prk)); return AES_ERR_BAD_PARAM; }

    uint8_t enc_key[32];
    aes2_hkdf_expand(prk, info_enc, info_enc_len, enc_key, (size_t)keyLen);

    AESStatus st = AES_init(&s->aes, enc_key, keyLen);
    AES2_secure_zero(enc_key, sizeof(enc_key));
    if (st!=AES_OK) { AES2_secure_zero(prk, sizeof(prk)); return st; }

    s->keylen = keyLen;
    s->flags  = flags;
    s->tag_len = (flags & AES2_F_MAC_ENABLE) ? mac_tag_len : 0;
    s->last_nonce_set = false;
    s->last_iv_set = false;

    if (flags & AES2_F_MAC_ENABLE) {
        uint8_t info_mac[128];
        size_t info_mac_len = aes2_build_info(kdf? kdf->info: NULL, kdf? kdf->info_len: 0, "|AES2|mac", info_mac, sizeof(info_mac));
        if (info_mac_len==0 && kdf && kdf->info_len) { AES2_secure_zero(prk, sizeof(prk)); return AES_ERR_BAD_PARAM; }
        aes2_hkdf_expand(prk, info_mac, info_mac_len, s->mac_key, 32);
        AES2_secure_zero(info_mac, sizeof(info_mac));
    } else {
        AES2_secure_zero(s->mac_key, sizeof(s->mac_key));
    }

    AES2_secure_zero(prk, sizeof(prk));
    AES2_secure_zero(info_enc, sizeof(info_enc));
    return AES_OK;
}

static AESStatus aes2_check_nonce_guard_and_update(AES2_SecCtx* s, const uint8_t* nonce16, const uint8_t* iv16) {
    if (!s || !nonce16 || !iv16) return AES_ERR_BAD_PARAM;
    if ((s->flags & AES2_F_NONCE_GUARD) && s->last_nonce_set && s->last_iv_set) {
        if (memcmp(s->last_nonce, nonce16, 16)==0 && memcmp(s->last_iv, iv16, 16)==0) {
            return AES_ERR_STATE; // reject exact reuse of (nonce, iv)
        }
    }
    memcpy(s->last_nonce, nonce16, 16); s->last_nonce_set = true;
    memcpy(s->last_iv, iv16, 16);       s->last_iv_set    = true;
    return AES_OK;
}

static AESStatus aes2_compute_tag_if_enabled(AES2_SecCtx* s,
                                             const char* label,
                                             const uint8_t* nonce16,
                                             const uint8_t* iv16,
                                             const uint8_t* data, size_t data_len,
                                             uint8_t* tag, size_t tag_cap, size_t* tag_len_out) {
    if (!(s->flags & AES2_F_MAC_ENABLE)) {
        if (tag_len_out) *tag_len_out = 0;
        return AES_OK;
    }
    if (!tag || tag_cap < s->tag_len || !nonce16 || !iv16) return AES_ERR_BUF_SMALL;

    const uint8_t* parts[4]; size_t lens[4];
    parts[0] = (const uint8_t*)label; lens[0] = strlen(label);
    parts[1] = nonce16; lens[1] = 16;
    parts[2] = iv16;    lens[2] = 16;
    parts[3] = data;    lens[3] = data_len;

    uint8_t full_tag[32];
    aes2_hmac_sha256_multi(s->mac_key, 32, parts, lens, 4, full_tag);
    memcpy(tag, full_tag, s->tag_len);
    if (tag_len_out) *tag_len_out = s->tag_len;
    AES2_secure_zero(full_tag, sizeof(full_tag));
    return AES_OK;
}

static AESStatus aes2_verify_tag_if_enabled(AES2_SecCtx* s,
                                            const char* label,
                                            const uint8_t* nonce16,
                                            const uint8_t* iv16,
                                            const uint8_t* data, size_t data_len,
                                            const uint8_t* tag, size_t tag_len_in) {
    if (!(s->flags & AES2_F_MAC_ENABLE)) return AES_OK;
    if (!tag || !(tag_len_in==16 || tag_len_in==32) || tag_len_in!=s->tag_len) return AES_ERR_BAD_PARAM;

    uint8_t calc[32];
    const uint8_t* parts[4]; size_t lens[4];
    parts[0] = (const uint8_t*)label; lens[0] = strlen(label);
    parts[1] = nonce16; lens[1] = 16;
    parts[2] = iv16;    lens[2] = 16;
    parts[3] = data;    lens[3] = data_len;
    aes2_hmac_sha256_multi(s->mac_key, 32, parts, lens, 4, calc);
    int diff = AES2_ct_memcmp(calc, tag, s->tag_len);
    AESStatus st = (diff==0) ? AES_OK : AES_ERR_STATE;
    AES2_secure_zero(calc, sizeof(calc));
    return st;
}

AESStatus AES2_seal_CTR(AES2_SecCtx* s,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out){
    if (!s || !nonce16 || !iv16 || (!pt && pt_len) || !ct || !ct_len) return AES_ERR_BAD_PARAM;
    if (ct_cap < pt_len) return AES_ERR_BUF_SMALL;

    AESStatus gst = aes2_check_nonce_guard_and_update(s, nonce16, iv16);
    if (gst!=AES_OK) return gst;

    uint8_t ctr[16]; memcpy(ctr, iv16, 16);
    AESStatus st = AES_cryptCTR(&s->aes, pt, pt_len, ct, ctr);
    if (st!=AES_OK) return st;

    *ct_len = pt_len;
    return aes2_compute_tag_if_enabled(s, "AES2|CTR", nonce16, iv16, ct, *ct_len, tag, tag_cap, tag_len_out);
}

AESStatus AES2_open_CTR(AES2_SecCtx* s,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out){
    if (!s || !nonce16 || !iv16 || (!ct && ct_len) || !pt || !pt_len_out) return AES_ERR_BAD_PARAM;
    if (pt_cap < ct_len) return AES_ERR_BUF_SMALL;

    AESStatus vst = aes2_verify_tag_if_enabled(s, "AES2|CTR", nonce16, iv16, ct, ct_len, tag, tag_len_in);
    if (vst!=AES_OK) return vst;

    uint8_t ctr[16]; memcpy(ctr, iv16, 16);
    AESStatus st = AES_cryptCTR(&s->aes, ct, ct_len, pt, ctr);
    if (st!=AES_OK) return st;
    *pt_len_out = ct_len;

    // Record last seen (optional)
    memcpy(s->last_nonce, nonce16, 16); s->last_nonce_set = true;
    memcpy(s->last_iv, iv16, 16);       s->last_iv_set    = true;
    return AES_OK;
}

AESStatus AES2_seal_CBC(AES2_SecCtx* s,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len,
                        AESPadding padding,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out){
    if (!s || !nonce16 || !iv16 || (!pt && pt_len) || !ct || !ct_len) return AES_ERR_BAD_PARAM;

    AESStatus gst = aes2_check_nonce_guard_and_update(s, nonce16, iv16);
    if (gst!=AES_OK) return gst;

    uint8_t iv_work[16]; memcpy(iv_work, iv16, 16);
    AESStatus st = AES_encryptCBC(&s->aes, pt, pt_len, ct, ct_cap, ct_len, iv_work, padding);
    if (st!=AES_OK) return st;

    return aes2_compute_tag_if_enabled(s, "AES2|CBC", nonce16, iv16, ct, *ct_len, tag, tag_cap, tag_len_out);
}

AESStatus AES2_open_CBC(AES2_SecCtx* s,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        AESPadding padding,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out){
    if (!s || !nonce16 || !iv16 || (!ct && ct_len) || !pt || !pt_len_out) return AES_ERR_BAD_PARAM;

    AESStatus vst = aes2_verify_tag_if_enabled(s, "AES2|CBC", nonce16, iv16, ct, ct_len, tag, tag_len_in);
    if (vst!=AES_OK) return vst;

    uint8_t iv_work[16]; memcpy(iv_work, iv16, 16);
    AESStatus st = AES_decryptCBC(&s->aes, ct, ct_len, pt, pt_cap, pt_len_out, iv_work, padding);
    if (st!=AES_OK) return st;

    // Record last seen (optional)
    memcpy(s->last_nonce, nonce16, 16); s->last_nonce_set = true;
    memcpy(s->last_iv, iv16, 16);       s->last_iv_set    = true;
    return AES_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Self test
// ─────────────────────────────────────────────────────────────────────────────
AESStatus AES2_selftest(void){
    // Simple functional KAT-like checks (not full NIST vectors)
    uint8_t master_key[16]; memset(master_key, 0x00, sizeof(master_key));
    uint8_t salt[16];       memset(salt, 0x11, sizeof(salt));
    const char* info = "AES2|test";
    AES2_KDFParams kdf = { salt, sizeof(salt), (const uint8_t*)info, strlen(info) };

    AES2_SecCtx s; AESStatus st;
    st = AES2_init_hardened(&s, master_key, AES128, &kdf, (AES2_F_MAC_ENABLE|AES2_F_NONCE_GUARD), 16);
    if (st!=AES_OK) return st;

    const uint8_t nonce[16] = {0};
    const uint8_t iv[16]    = {0};

    // CTR
    const uint8_t msg1[] = { 'a','b','c','d','e','f' };
    uint8_t ct1[sizeof msg1]; size_t ct1_len=0;
    uint8_t tag1[32]; size_t tag1_len=0;
    st = AES2_seal_CTR(&s, nonce, iv, msg1, sizeof(msg1), ct1, sizeof(ct1), &ct1_len, tag1, sizeof(tag1), &tag1_len);
    if (st!=AES_OK || ct1_len!=sizeof(msg1) || tag1_len!=16) return AES_ERR_STATE;

    uint8_t pt1[sizeof msg1]; size_t pt1_len=0;
    st = AES2_open_CTR(&s, nonce, iv, ct1, ct1_len, tag1, tag1_len, pt1, sizeof(pt1), &pt1_len);
    if (st!=AES_OK || pt1_len!=sizeof(msg1) || memcmp(pt1, msg1, sizeof(msg1))!=0) return AES_ERR_STATE;

    // CBC
    const uint8_t msg2[] = { 0x00,0x01,0x02,0x03, 0x04 };
    uint8_t ct2[64]; size_t ct2_len=0;
    uint8_t tag2[32]; size_t tag2_len=0;
    st = AES2_seal_CBC(&s, nonce, iv, msg2, sizeof(msg2), ct2, sizeof(ct2), &ct2_len, AES_PADDING_PKCS7, tag2, sizeof(tag2), &tag2_len);
    if (st!=AES_OK || (ct2_len % 16)!=0 || tag2_len!=16) return AES_ERR_STATE;

    uint8_t pt2[64]; size_t pt2_len=0;
    st = AES2_open_CBC(&s, nonce, iv, ct2, ct2_len, tag2, tag2_len, AES_PADDING_PKCS7, pt2, sizeof(pt2), &pt2_len);
    if (st!=AES_OK || pt2_len!=sizeof(msg2) || memcmp(pt2, msg2, sizeof(msg2))!=0) return AES_ERR_STATE;

    // MAC fail check
    tag1[0] ^= 0x01;
    st = AES2_open_CTR(&s, nonce, iv, ct1, ct1_len, tag1, tag1_len, pt1, sizeof(pt1), &pt1_len);
    if (st==AES_OK) return AES_ERR_STATE;

    return AES_OK;
}
