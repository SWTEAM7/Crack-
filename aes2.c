#pragma execution_character_set("utf-8")

#include "aes2.h"
#include "sha512.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt")
#elif defined(__APPLE__)
#  include <stdlib.h>
#else
#  include <stdlib.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/types.h>
#endif

/* ---------- 내부 헬퍼 ---------- */
static void aes2_burn(void* p, size_t n) {
    if (!p || !n) return;
    secure_zero(p, n);
}

static AESStatus aes2_expand_label(const uint8_t* prk,
                                   const AES2_KDFParams* kdf,
                                   const char* label,
                                   uint8_t* out, size_t out_len) {
    static const char prefix[] = "AES2|";
    static const char suffix[] = "|v1|STRONG";
    uint8_t info_buf[SHA512_BLOCK_LEN + 256];
    size_t prefix_len = sizeof(prefix) - 1;
    size_t label_len  = strlen(label);
    size_t suffix_len = sizeof(suffix) - 1;
    size_t pos = 0;

    if (!prk || !out || !out_len) return AES_ERR_BAD_PARAM;

    size_t extra_info_len = 0;
    if (kdf && kdf->info && kdf->info_len) {
        extra_info_len = 1 + kdf->info_len; /* 구분용 '|' + 사용자 info */
    }

    size_t need = prefix_len + label_len + suffix_len + extra_info_len;
    if (need > sizeof(info_buf)) return AES_ERR_BAD_PARAM;

    memcpy(info_buf + pos, prefix, prefix_len); pos += prefix_len;
    memcpy(info_buf + pos, label,  label_len);  pos += label_len;
    memcpy(info_buf + pos, suffix, suffix_len); pos += suffix_len;
    if (extra_info_len) {
        info_buf[pos++] = '|';
        memcpy(info_buf + pos, kdf->info, kdf->info_len);
        pos += kdf->info_len;
    }

    int rc = hkdf_sha512_expand(prk, info_buf, pos, out, out_len);
    aes2_burn(info_buf, sizeof(info_buf));
    return (rc == HKDF_SHA512_OK) ? AES_OK : AES_ERR_STATE;
}

static int aes2_valid_keylen(AESKeyLength keyLen) {
    return (keyLen == AES128) || (keyLen == AES192) || (keyLen == AES256);
}

static int aes2_valid_taglen(AES2_TagLen tag_len) {
    return (tag_len == AES2_TagLen_16) || (tag_len == AES2_TagLen_32);
}

/* ---------- 공개 API: init/KDF ---------- */
AESStatus AES2_init_hardened(AES2_SecCtx* s,
                             const uint8_t* master_key, AESKeyLength keyLen,
                             const AES2_KDFParams* kdf,
                             AES2_Flags flags,
                             AES2_TagLen mac_tag_len) {
    if (!s || !master_key || !aes2_valid_keylen(keyLen) || !aes2_valid_taglen(mac_tag_len)) {
        return AES_ERR_BAD_PARAM;
    }
    if (!kdf) return AES_ERR_BAD_PARAM;
    if (kdf->salt_len && !kdf->salt) return AES_ERR_BAD_PARAM;
    if (kdf->info_len && !kdf->info) return AES_ERR_BAD_PARAM;

    uint8_t prk[HKDF_SHA512_PRK_LEN];
    uint8_t kenc[32];
    uint8_t kmac[64];
    AESStatus st = AES_OK;
    AESStatus aes_rc;

    hkdf_sha512_extract(kdf->salt, kdf->salt_len, master_key, (size_t)keyLen, prk);

    st = aes2_expand_label(prk, kdf, "enc", kenc, (size_t)keyLen);
    if (st != AES_OK) goto cleanup;

    aes_rc = AES_init(&s->aes, kenc, keyLen);
    if (aes_rc != AES_OK) {
        st = aes_rc;
        goto cleanup;
    }

    st = aes2_expand_label(prk, kdf, "mac", kmac, sizeof(kmac));
    if (st != AES_OK) goto cleanup;

    memcpy(s->mac_key, kmac, sizeof(kmac));
    s->keylen = keyLen;
    s->flags = flags;
    s->tag_len = (uint8_t)mac_tag_len;
    s->last_nonce_set = false;
    s->last_iv_set = false;
    memset(s->last_nonce, 0, sizeof(s->last_nonce));
    memset(s->last_iv, 0, sizeof(s->last_iv));

cleanup:
    aes2_burn(prk, sizeof(prk));
    aes2_burn(kenc, sizeof(kenc));
    aes2_burn(kmac, sizeof(kmac));
    if (st != AES_OK) {
        aes2_burn(&s->aes, sizeof(s->aes));
        aes2_burn(s->mac_key, sizeof(s->mac_key));
        s->last_nonce_set = false;
        s->last_iv_set = false;
    }
    return st;
}

/* ---------- HMAC / 상수시간 비교 / 보안 삭제 / 난수 ---------- */
AESStatus AES2_HMAC_tag(const uint8_t* mac_key, size_t mac_key_len,
                        const uint8_t* m, size_t m_len,
                        AES2_TagLen tag_len,
                        uint8_t* out_tag, size_t out_tag_cap) {
    if (!mac_key || !m || !out_tag || !aes2_valid_taglen(tag_len)) return AES_ERR_BAD_PARAM;
    if (out_tag_cap < (size_t)tag_len) return AES_ERR_BUF_SMALL;

    uint8_t full_tag[HMAC_SHA512_LEN];
    hmac_sha512(mac_key, mac_key_len, m, m_len, full_tag);
    memcpy(out_tag, full_tag, (size_t)tag_len);
    aes2_burn(full_tag, sizeof(full_tag));
    return AES_OK;
}

int AES2_ct_memcmp(const void* a, const void* b, size_t n) {
    return ct_memcmp(a, b, n);
}

void AES2_secure_zero(void* p, size_t n) {
    aes2_burn(p, n);
}

AESStatus AES2_rand_bytes(uint8_t* out, size_t n) {
    if (!out && n) return AES_ERR_BAD_PARAM;
    if (n == 0) return AES_OK;

#if defined(_WIN32)
    NTSTATUS rc = BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (rc == 0) ? AES_OK : AES_ERR_STATE;
#elif defined(__APPLE__)
    arc4random_buf(out, n);
    return AES_OK;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return AES_ERR_STATE;
    size_t filled = 0;
    while (filled < n) {
        ssize_t r = read(fd, out + filled, n - filled);
        if (r <= 0) { close(fd); return AES_ERR_STATE; }
        filled += (size_t)r;
    }
    close(fd);
    return AES_OK;
#endif
}

/* ---------- 라이브러리 정보 / selftest ---------- */
const AES2_LibraryInfo* AES2_libinfo(void) {
    static const AES2_LibraryInfo info = {
        0x00010000,
        0x00000003  /* bit0: HKDF, bit1: HMAC */
    };
    return &info;
}

AESStatus AES2_selftest(void) {
    if (sha512_selftest() != 0) return AES_ERR_STATE;

    static const uint8_t master_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    static const uint8_t salt[] = "AES2-selftest-salt";
    static const uint8_t info[] = "AES2-selftest-info";
    AES2_KDFParams params = {
        salt, sizeof(salt) - 1,
        info, sizeof(info) - 1
    };

    uint8_t prk[HKDF_SHA512_PRK_LEN];
    uint8_t expected_kenc[16];
    uint8_t expected_kmac[64];

    hkdf_sha512_extract(params.salt, params.salt_len,
                        master_key, sizeof(master_key), prk);
    if (aes2_expand_label(prk, &params, "enc", expected_kenc, sizeof(expected_kenc)) != AES_OK ||
        aes2_expand_label(prk, &params, "mac", expected_kmac, sizeof(expected_kmac)) != AES_OK) {
        aes2_burn(prk, sizeof(prk));
        return AES_ERR_STATE;
    }
    aes2_burn(prk, sizeof(prk));

    AES2_SecCtx ctx;
    AESStatus rc = AES2_init_hardened(&ctx, master_key, AES128,
                                      &params, AES2_F_MAC_ENABLE, AES2_TagLen_32);
    if (rc != AES_OK) {
        aes2_burn(expected_kenc, sizeof(expected_kenc));
        aes2_burn(expected_kmac, sizeof(expected_kmac));
        return rc;
    }

    if (ct_memcmp(ctx.mac_key, expected_kmac, sizeof(expected_kmac)) != 0) {
        aes2_burn(&ctx, sizeof(ctx));
        aes2_burn(expected_kenc, sizeof(expected_kenc));
        aes2_burn(expected_kmac, sizeof(expected_kmac));
        return AES_ERR_STATE;
    }

    uint8_t zero_block[16] = {0};
    uint8_t out1[16], out2[16];
    AES_ctx ref;
    AES_init(&ref, expected_kenc, AES128);
    AES_encryptBlock(&ctx.aes, zero_block, out1);
    AES_encryptBlock(&ref, zero_block, out2);

    aes2_burn(&ref, sizeof(ref));
    aes2_burn(expected_kenc, sizeof(expected_kenc));
    aes2_burn(expected_kmac, sizeof(expected_kmac));
    aes2_burn(&ctx, sizeof(ctx));

    return (ct_memcmp(out1, out2, sizeof(out1)) == 0) ? AES_OK : AES_ERR_STATE;
}

/* ---------- 내부 겹침/nonce/IV 헬퍼 ---------- */
static int aes2_forbidden_overlap(const void* in, size_t in_len,
                                  const void* out, size_t out_len)
{
    if (!in || !out || in_len == 0 || out_len == 0) return 0;
    if (in == out) return 0; // 완전 in-place 허용

    const uint8_t* a = (const uint8_t*)in;
    const uint8_t* b = (const uint8_t*)out;

    if (a + in_len <= b) return 0;
    if (b + out_len <= a) return 0;

    return 1; // 부분 겹침 → 금지
}

static AESStatus aes2_check_and_update_nonce(AES2_SecCtx* s,
                                             const uint8_t nonce16[16])
{
    if (!s || !nonce16) return AES_ERR_BAD_PARAM;
    if (s->flags & AES2_F_NONCE_GUARD) {
        if (s->last_nonce_set &&
            memcmp(s->last_nonce, nonce16, 16) == 0) {
            return AES_ERR_STATE; // nonce 재사용
        }
    }
    memcpy(s->last_nonce, nonce16, 16);
    s->last_nonce_set = true;
    return AES_OK;
}

static AESStatus aes2_check_and_update_iv(AES2_SecCtx* s,
                                          const uint8_t iv16[16])
{
    if (!s || !iv16) return AES_ERR_BAD_PARAM;
    if (s->flags & AES2_F_NONCE_GUARD) {
        if (s->last_iv_set &&
            memcmp(s->last_iv, iv16, 16) == 0) {
            return AES_ERR_STATE; // IV 재사용
        }
    }
    memcpy(s->last_iv, iv16, 16);
    s->last_iv_set = true;
    return AES_OK;
}

/* ---------- EtM: CTR ---------- */
AESStatus AES2_seal_CTR(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out)
{
    if (!s || !nonce16 || !ct || !ct_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_len && !pt)
        return AES_ERR_BAD_PARAM;
    if (ct_cap < pt_len)
        return AES_ERR_BUF_SMALL;

    if ((s->flags & AES2_F_MAC_ENABLE) && (!tag || !tag_len_out))
        return AES_ERR_BAD_PARAM;

    if (aes2_forbidden_overlap(pt, pt_len, ct, ct_cap))
        return AES_ERR_OVERLAP;

    AESStatus st = aes2_check_and_update_nonce(s, nonce16);
    if (st != AES_OK) return st;

    uint8_t ctr[16];
    memcpy(ctr, nonce16, 16);
    st = AES_cryptCTR(&s->aes,
                      pt_len ? pt : (const uint8_t*)"", pt_len,
                      ct,
                      ctr);
    AES2_secure_zero(ctr, sizeof(ctr));
    if (st != AES_OK) return st;

    *ct_len_out = pt_len;

    if (!(s->flags & AES2_F_MAC_ENABLE)) {
        if (tag_len_out) *tag_len_out = 0;
        return AES_OK;
    }

    size_t mac_len = aad_len + 16 + pt_len;
    uint8_t* mac_buf = NULL;

    if (mac_len) {
        mac_buf = (uint8_t*)malloc(mac_len);
        if (!mac_buf) return AES_ERR_STATE;

        size_t pos = 0;
        if (aad_len) {
            memcpy(mac_buf + pos, aad, aad_len);
            pos += aad_len;
        }
        memcpy(mac_buf + pos, nonce16, 16);
        pos += 16;
        if (pt_len) {
            memcpy(mac_buf + pos, ct, pt_len);
            pos += pt_len;
        }
    }

    st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                       mac_buf, mac_len,
                       (AES2_TagLen)s->tag_len,
                       tag, tag_cap);

    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }

    if (st != AES_OK) return st;
    if (tag_len_out) *tag_len_out = s->tag_len;
    return AES_OK;
}

AESStatus AES2_open_CTR(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out)
{
    if (!s || !nonce16 || !ct || !pt || !pt_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_cap < ct_len)
        return AES_ERR_BUF_SMALL;

    if (aes2_forbidden_overlap(ct, ct_len, pt, pt_cap))
        return AES_ERR_OVERLAP;

    /* 무결성 비사용 경로: 바로 복호화 */
    if (!(s->flags & AES2_F_MAC_ENABLE)) {
        uint8_t ctr[16];
        memcpy(ctr, nonce16, 16);
        AESStatus st = AES_cryptCTR(&s->aes, ct, ct_len, pt, ctr);
        AES2_secure_zero(ctr, sizeof(ctr));
        if (st != AES_OK) return st;
        *pt_len_out = ct_len;
        return AES_OK;
    }

    if (tag_len_in != (size_t)s->tag_len)
        return AES_ERR_AUTH;
    if (!tag)
        return AES_ERR_BAD_PARAM;

    size_t mac_len = aad_len + 16 + ct_len;
    uint8_t* mac_buf = NULL;

    if (mac_len) {
        mac_buf = (uint8_t*)malloc(mac_len);
        if (!mac_buf) return AES_ERR_STATE;

        size_t pos = 0;
        if (aad_len) {
            memcpy(mac_buf + pos, aad, aad_len);
            pos += aad_len;
        }
        memcpy(mac_buf + pos, nonce16, 16);
        pos += 16;
        if (ct_len) {
            memcpy(mac_buf + pos, ct, ct_len);
            pos += ct_len;
        }
    }

    uint8_t calc_tag[HMAC_SHA512_LEN];
    AESStatus st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                                 mac_buf, mac_len,
                                 (AES2_TagLen)s->tag_len,
                                 calc_tag, sizeof(calc_tag));

    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }
    if (st != AES_OK) return st;

    if (AES2_ct_memcmp(calc_tag, tag, tag_len_in) != 0) {
        AES2_secure_zero(calc_tag, sizeof(calc_tag));
        return AES_ERR_AUTH;
    }
    AES2_secure_zero(calc_tag, sizeof(calc_tag));

    uint8_t ctr[16];
    memcpy(ctr, nonce16, 16);
    st = AES_cryptCTR(&s->aes, ct, ct_len, pt, ctr);
    AES2_secure_zero(ctr, sizeof(ctr));
    if (st != AES_OK) return st;

    *pt_len_out = ct_len;
    return AES_OK;
}

/* ---------- EtM: CBC ---------- */
AESStatus AES2_seal_CBC(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                        AESPadding padding,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out)
{
    if (!s || !nonce16 || !iv16 || !ct || !ct_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_len && !pt)
        return AES_ERR_BAD_PARAM;

    if (aes2_forbidden_overlap(pt, pt_len, ct, ct_cap))
        return AES_ERR_OVERLAP;

    AESStatus st = aes2_check_and_update_nonce(s, nonce16);
    if (st != AES_OK) return st;
    st = aes2_check_and_update_iv(s, iv16);
    if (st != AES_OK) return st;

    uint8_t iv_work[16];
    memcpy(iv_work, iv16, 16);

    st = AES_encryptCBC(&s->aes,
                        pt_len ? pt : (const uint8_t*)"", pt_len,
                        ct, ct_cap, ct_len_out,
                        iv_work, padding);
    AES2_secure_zero(iv_work, sizeof(iv_work));
    if (st != AES_OK) return st;

    if (!(s->flags & AES2_F_MAC_ENABLE)) {
        if (tag_len_out) *tag_len_out = 0;
        return AES_OK;
    }

    size_t ct_len = *ct_len_out;
    size_t mac_len = aad_len + 16 + 16 + ct_len;
    uint8_t* mac_buf = NULL;

    if (mac_len) {
        mac_buf = (uint8_t*)malloc(mac_len);
        if (!mac_buf) return AES_ERR_STATE;

        size_t pos = 0;
        if (aad_len) {
            memcpy(mac_buf + pos, aad, aad_len);
            pos += aad_len;
        }
        memcpy(mac_buf + pos, nonce16, 16);
        pos += 16;
        memcpy(mac_buf + pos, iv16, 16);
        pos += 16;
        if (ct_len) {
            memcpy(mac_buf + pos, ct, ct_len);
            pos += ct_len;
        }
    }

    st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                       mac_buf, mac_len,
                       (AES2_TagLen)s->tag_len,
                       tag, tag_cap);

    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }

    if (st != AES_OK) return st;
    if (tag_len_out) *tag_len_out = s->tag_len;
    return AES_OK;
}

AESStatus AES2_open_CBC(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        AESPadding padding,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out)
{
    (void)nonce16; // 현재 구현에서는 MAC 입력에만 사용 → 이미 MAC 단계에서 사용함
    if (!s || !nonce16 || !iv16 || !ct || !pt || !pt_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_cap < ct_len)
        return AES_ERR_BUF_SMALL;

    if (aes2_forbidden_overlap(ct, ct_len, pt, pt_cap))
        return AES_ERR_OVERLAP;

    if (!(s->flags & AES2_F_MAC_ENABLE)) {
        uint8_t iv_work[16];
        memcpy(iv_work, iv16, 16);
        AESStatus st = AES_decryptCBC(&s->aes,
                                      ct, ct_len,
                                      pt, pt_cap, pt_len_out,
                                      iv_work, padding);
        AES2_secure_zero(iv_work, sizeof(iv_work));
        return st;
    }

    if (tag_len_in != (size_t)s->tag_len)
        return AES_ERR_AUTH;
    if (!tag)
        return AES_ERR_BAD_PARAM;

    size_t mac_len = aad_len + 16 + 16 + ct_len;
    uint8_t* mac_buf = NULL;

    if (mac_len) {
        mac_buf = (uint8_t*)malloc(mac_len);
        if (!mac_buf) return AES_ERR_STATE;

        size_t pos = 0;
        if (aad_len) {
            memcpy(mac_buf + pos, aad, aad_len);
            pos += aad_len;
        }
        memcpy(mac_buf + pos, nonce16, 16);
        pos += 16;
        memcpy(mac_buf + pos, iv16, 16);
        pos += 16;
        if (ct_len) {
            memcpy(mac_buf + pos, ct, ct_len);
            pos += ct_len;
        }
    }

    uint8_t calc_tag[HMAC_SHA512_LEN];
    AESStatus st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                                 mac_buf, mac_len,
                                 (AES2_TagLen)s->tag_len,
                                 calc_tag, sizeof(calc_tag));

    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }
    if (st != AES_OK) return st;

    if (AES2_ct_memcmp(calc_tag, tag, tag_len_in) != 0) {
        AES2_secure_zero(calc_tag, sizeof(calc_tag));
        return AES_ERR_AUTH;
    }
    AES2_secure_zero(calc_tag, sizeof(calc_tag));

    uint8_t iv_work[16];
    memcpy(iv_work, iv16, 16);
    st = AES_decryptCBC(&s->aes,
                        ct, ct_len,
                        pt, pt_cap, pt_len_out,
                        iv_work, padding);
    AES2_secure_zero(iv_work, sizeof(iv_work));
    return st;
}

/* ---------- auto nonce/IV 래퍼 ---------- */
AESStatus AES2_seal_CTR_autoIV(AES2_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               uint8_t out_nonce16[16],
                               const uint8_t* pt, size_t pt_len,
                               uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                               uint8_t* tag, size_t tag_cap, size_t* tag_len_out)
{
    if (!out_nonce16) return AES_ERR_BAD_PARAM;

    AESStatus st = AES2_rand_bytes(out_nonce16, 16);
    if (st != AES_OK) return st;

    return AES2_seal_CTR(s, aad, aad_len,
                         out_nonce16,
                         pt, pt_len,
                         ct, ct_cap, ct_len_out,
                         tag, tag_cap, tag_len_out);
}

AESStatus AES2_open_CTR_autoIV(AES2_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t in_nonce16[16],
                               const uint8_t* ct, size_t ct_len,
                               const uint8_t* tag, size_t tag_len_in,
                               uint8_t* pt, size_t pt_cap, size_t* pt_len_out)
{
    if (!in_nonce16) return AES_ERR_BAD_PARAM;

    return AES2_open_CTR(s, aad, aad_len,
                         in_nonce16,
                         ct, ct_len,
                         tag, tag_len_in,
                         pt, pt_cap, pt_len_out);
}

AESStatus AES2_seal_CBC_autoIV(AES2_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               uint8_t out_nonce16[16],
                               uint8_t out_iv16[16],
                               const uint8_t* pt, size_t pt_len,
                               uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                               AESPadding padding,
                               uint8_t* tag, size_t tag_cap, size_t* tag_len_out)
{
    if (!out_nonce16 || !out_iv16) return AES_ERR_BAD_PARAM;

    AESStatus st = AES2_rand_bytes(out_nonce16, 16);
    if (st != AES_OK) return st;
    st = AES2_rand_bytes(out_iv16, 16);
    if (st != AES_OK) return st;

    return AES2_seal_CBC(s, aad, aad_len,
                         out_nonce16,
                         out_iv16,
                         pt, pt_len,
                         ct, ct_cap, ct_len_out,
                         padding,
                         tag, tag_cap, tag_len_out);
}

AESStatus AES2_open_CBC_autoIV(AES2_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t in_nonce16[16],
                               const uint8_t in_iv16[16],
                               const uint8_t* ct, size_t ct_len,
                               const uint8_t* tag, size_t tag_len_in,
                               AESPadding padding,
                               uint8_t* pt, size_t pt_cap, size_t* pt_len_out)
{
    if (!in_nonce16 || !in_iv16) return AES_ERR_BAD_PARAM;

    return AES2_open_CBC(s, aad, aad_len,
                         in_nonce16,
                         in_iv16,
                         ct, ct_len,
                         tag, tag_len_in,
                         padding,
                         pt, pt_cap, pt_len_out);
}
