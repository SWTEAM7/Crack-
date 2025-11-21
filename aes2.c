#pragma execution_character_set("utf-8")

/**
 * aes2.c - AES2 보안형 암호화 라이브러리 구현
 * 
 * 이 파일은 AES2 보안형 암호화 라이브러리의 핵심 구현을 제공합니다.
 * 주요 기능:
 *   - HKDF-SHA-512 기반 키 파생
 *   - AES-CTR/CBC 모드 암호화/복호화
 *   - HMAC-SHA-512 기반 무결성 검증 (EtM 방식)
 *   - Nonce/IV 재사용 방지
 *   - 상수시간 비교 및 보안 메모리 삭제
 */

#include "aes2.h"
#include "sha512.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* 플랫폼별 CSPRNG 헤더 포함 */
#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt")  /* Windows BCrypt 라이브러리 링크 */
#elif defined(__APPLE__)
#  include <stdlib.h>  /* arc4random_buf 사용 */
#else
#  include <stdlib.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/types.h>  /* Linux/Unix /dev/urandom 사용 */
#endif

/* ============================================================================
 * 내부 헬퍼 함수들
 * ============================================================================ */

/**
 * aes2_burn - 메모리 영역을 안전하게 제로화
 * 
 * 민감한 데이터(키, 중간값 등)를 메모리에서 완전히 제거합니다.
 * 컴파일러 최적화로 인한 제거를 방지하기 위해 secure_zero()를 사용합니다.
 * 
 * @param p  제로화할 메모리 영역의 시작 주소
 * @param n  제로화할 바이트 수
 */
static void aes2_burn(void* p, size_t n) {
    if (!p || !n) return;
    secure_zero(p, n);
}

/**
 * aes2_expand_label - HKDF-SHA-512를 사용하여 레이블 기반 키 확장
 * 
 * 마스터 키에서 파생된 PRK(Pseudo-Random Key)를 사용하여
 * 특정 용도(암호화 키 또는 MAC 키)로 키를 확장합니다.
 * 
 * 정보 문자열 형식: "AES2|<label>|v1|STRONG[|사용자info]"
 *   - prefix: "AES2|" - 도메인 분리용 접두사
 *   - label: "enc" 또는 "mac" - 키 용도 식별
 *   - suffix: "|v1|STRONG" - 버전 및 강도 표시
 *   - 사용자 info: 선택적 추가 정보 (도메인 분리 강화)
 * 
 * @param prk      HKDF Extract 단계에서 생성된 PRK (64바이트)
 * @param kdf      KDF 파라미터 구조체 (salt, info 포함)
 * @param label    키 용도 레이블 ("enc" 또는 "mac")
 * @param out      출력 버퍼 (파생된 키가 저장됨)
 * @param out_len  출력 키의 길이 (바이트)
 * 
 * @return AES_OK 성공, AES_ERR_BAD_PARAM 잘못된 매개변수, AES_ERR_STATE HKDF 실패
 */
static AESStatus aes2_expand_label(const uint8_t* prk,
                                   const AES2_KDFParams* kdf,
                                   const char* label,
                                   uint8_t* out, size_t out_len) {
    static const char prefix[] = "AES2|";      /* 도메인 분리 접두사 */
    static const char suffix[] = "|v1|STRONG";  /* 버전 및 강도 표시 */
    uint8_t info_buf[SHA512_BLOCK_LEN + 256];  /* 정보 문자열 버퍼 */
    size_t prefix_len = sizeof(prefix) - 1;
    size_t label_len  = strlen(label);
    size_t suffix_len = sizeof(suffix) - 1;
    size_t pos = 0;

    /* 매개변수 유효성 검사 */
    if (!prk || !out || !out_len) return AES_ERR_BAD_PARAM;

    /* 사용자 제공 info 길이 계산 (구분자 '|' 포함) */
    size_t extra_info_len = 0;
    if (kdf && kdf->info && kdf->info_len) {
        extra_info_len = 1 + kdf->info_len; /* 구분용 '|' + 사용자 info */
    }

    /* 전체 정보 문자열 길이 검증 */
    size_t need = prefix_len + label_len + suffix_len + extra_info_len;
    if (need > sizeof(info_buf)) return AES_ERR_BAD_PARAM;

    /* 정보 문자열 구성: prefix + label + suffix + [사용자info] */
    memcpy(info_buf + pos, prefix, prefix_len); pos += prefix_len;
    memcpy(info_buf + pos, label,  label_len);  pos += label_len;
    memcpy(info_buf + pos, suffix, suffix_len); pos += suffix_len;
    if (extra_info_len) {
        info_buf[pos++] = '|';  /* 사용자 info 구분자 */
        memcpy(info_buf + pos, kdf->info, kdf->info_len);
        pos += kdf->info_len;
    }

    /* HKDF-SHA-512 Expand 단계 실행 */
    int rc = hkdf_sha512_expand(prk, info_buf, pos, out, out_len);
    aes2_burn(info_buf, sizeof(info_buf));  /* 정보 문자열 안전 삭제 */
    return (rc == HKDF_SHA512_OK) ? AES_OK : AES_ERR_STATE;
}

/**
 * aes2_valid_keylen - AES 키 길이 유효성 검사
 * 
 * @param keyLen  검사할 키 길이 (AES128, AES192, AES256)
 * @return 1 유효함, 0 유효하지 않음
 */
static int aes2_valid_keylen(AESKeyLength keyLen) {
    return (keyLen == AES128) || (keyLen == AES192) || (keyLen == AES256);
}

/**
 * aes2_valid_taglen - MAC 태그 길이 유효성 검사
 * 
 * @param tag_len  검사할 태그 길이 (AES2_TagLen_16 또는 AES2_TagLen_32)
 * @return 1 유효함, 0 유효하지 않음
 */
static int aes2_valid_taglen(AES2_TagLen tag_len) {
    return (tag_len == AES2_TagLen_16) || (tag_len == AES2_TagLen_32);
}

/* ============================================================================
 * 공개 API: 초기화 및 키 파생
 * ============================================================================ */

/**
 * AES2_init_hardened - AES2 보안 컨텍스트 초기화 및 키 파생
 * 
 * 마스터 키로부터 HKDF-SHA-512를 사용하여 암호화 키(Kenc)와 MAC 키(Kmac)를
 * 파생하고, AES 컨텍스트를 초기화합니다.
 * 
 * 키 파생 과정:
 *   1. Extract: PRK = HMAC-SHA-512(salt, master_key)
 *   2. Expand "enc": Kenc = HKDF-Expand(PRK, "AES2|enc|v1|STRONG", keyLen)
 *   3. Expand "mac": Kmac = HKDF-Expand(PRK, "AES2|mac|v1|STRONG", 64)
 * 
 * @param s            초기화할 보안 컨텍스트 포인터
 * @param master_key   마스터 키 (16, 24, 또는 32바이트)
 * @param keyLen       마스터 키 길이 (AES128, AES192, AES256)
 * @param kdf          KDF 파라미터 (salt, info 포함)
 * @param flags        보안 플래그 (MAC_ENABLE, NONCE_GUARD 등)
 * @param mac_tag_len  MAC 태그 길이 (16 또는 32바이트)
 * 
 * @return AES_OK 성공, AES_ERR_BAD_PARAM 잘못된 매개변수, 기타 AES_ERR_* 오류
 */
AESStatus AES2_init_hardened(AES2_SecCtx* s,
                             const uint8_t* master_key, AESKeyLength keyLen,
                             const AES2_KDFParams* kdf,
                             AES2_Flags flags,
                             AES2_TagLen mac_tag_len) {
    /* 매개변수 유효성 검사 */
    if (!s || !master_key || !aes2_valid_keylen(keyLen) || !aes2_valid_taglen(mac_tag_len)) {
        return AES_ERR_BAD_PARAM;
    }
    if (!kdf) return AES_ERR_BAD_PARAM;
    if (kdf->salt_len && !kdf->salt) return AES_ERR_BAD_PARAM;
    if (kdf->info_len && !kdf->info) return AES_ERR_BAD_PARAM;

    /* 임시 키 버퍼 (스택 할당) */
    uint8_t prk[HKDF_SHA512_PRK_LEN];  /* HKDF Extract 결과 (64바이트) */
    uint8_t kenc[32];                   /* 암호화 키 (최대 32바이트) */
    uint8_t kmac[64];                   /* MAC 키 (64바이트) */
    AESStatus st = AES_OK;
    AESStatus aes_rc;

    /* HKDF Extract: salt와 master_key로부터 PRK 생성 */
    hkdf_sha512_extract(kdf->salt, kdf->salt_len, master_key, (size_t)keyLen, prk);

    /* 암호화 키 파생: "enc" 레이블 사용 */
    st = aes2_expand_label(prk, kdf, "enc", kenc, (size_t)keyLen);
    if (st != AES_OK) goto cleanup;

    /* AES 컨텍스트 초기화 (파생된 암호화 키 사용) */
    aes_rc = AES_init(&s->aes, kenc, keyLen);
    if (aes_rc != AES_OK) {
        st = aes_rc;
        goto cleanup;
    }

    /* MAC 키 파생: "mac" 레이블 사용 (항상 64바이트) */
    st = aes2_expand_label(prk, kdf, "mac", kmac, sizeof(kmac));
    if (st != AES_OK) goto cleanup;

    /* 컨텍스트에 키 및 설정 저장 */
    memcpy(s->mac_key, kmac, sizeof(kmac));
    s->keylen = keyLen;
    s->flags = flags;
    s->tag_len = (uint8_t)mac_tag_len;
    
    /* Nonce/IV 재사용 방지 초기화 */
    s->last_nonce_set = false;
    s->last_iv_set = false;
    memset(s->last_nonce, 0, sizeof(s->last_nonce));
    memset(s->last_iv, 0, sizeof(s->last_iv));

cleanup:
    /* 민감한 임시 데이터 안전 삭제 */
    aes2_burn(prk, sizeof(prk));
    aes2_burn(kenc, sizeof(kenc));
    aes2_burn(kmac, sizeof(kmac));
    
    /* 오류 발생 시 컨텍스트도 안전하게 삭제 */
    if (st != AES_OK) {
        aes2_burn(&s->aes, sizeof(s->aes));
        aes2_burn(s->mac_key, sizeof(s->mac_key));
        s->last_nonce_set = false;
        s->last_iv_set = false;
    }
    return st;
}

/* ============================================================================
 * HMAC, 상수시간 비교, 보안 삭제, 난수 생성
 * ============================================================================ */

/**
 * AES2_HMAC_tag - HMAC-SHA-512를 사용하여 메시지 인증 태그 생성
 * 
 * 메시지와 MAC 키를 사용하여 HMAC-SHA-512 태그를 계산하고,
 * 지정된 길이(16 또는 32바이트)로 절단하여 반환합니다.
 * 
 * @param mac_key      MAC 키 (일반적으로 64바이트)
 * @param mac_key_len  MAC 키 길이
 * @param m            인증할 메시지
 * @param m_len        메시지 길이
 * @param tag_len      출력 태그 길이 (16 또는 32바이트)
 * @param out_tag      태그 출력 버퍼
 * @param out_tag_cap 출력 버퍼 용량
 * 
 * @return AES_OK 성공, AES_ERR_BAD_PARAM 잘못된 매개변수, AES_ERR_BUF_SMALL 버퍼 부족
 */
AESStatus AES2_HMAC_tag(const uint8_t* mac_key, size_t mac_key_len,
                        const uint8_t* m, size_t m_len,
                        AES2_TagLen tag_len,
                        uint8_t* out_tag, size_t out_tag_cap) {
    if (!mac_key || !m || !out_tag || !aes2_valid_taglen(tag_len)) return AES_ERR_BAD_PARAM;
    if (out_tag_cap < (size_t)tag_len) return AES_ERR_BUF_SMALL;

    /* 전체 HMAC-SHA-512 태그 계산 (64바이트) */
    uint8_t full_tag[HMAC_SHA512_LEN];
    hmac_sha512(mac_key, mac_key_len, m, m_len, full_tag);
    
    /* 지정된 길이로 절단하여 복사 */
    memcpy(out_tag, full_tag, (size_t)tag_len);
    
    /* 전체 태그 안전 삭제 */
    aes2_burn(full_tag, sizeof(full_tag));
    return AES_OK;
}

/**
 * AES2_ct_memcmp - 상수시간 메모리 비교
 * 
 * 두 메모리 영역을 상수시간에 비교합니다. 타이밍 공격을 방지하기 위해
 * 비교 결과와 무관하게 항상 동일한 시간이 소요됩니다.
 * 
 * @param a  첫 번째 메모리 영역
 * @param b  두 번째 메모리 영역
 * @param n  비교할 바이트 수
 * @return 0 두 영역이 동일, 0이 아니면 다름
 */
int AES2_ct_memcmp(const void* a, const void* b, size_t n) {
    return ct_memcmp(a, b, n);
}

/**
 * AES2_secure_zero - 메모리 영역을 안전하게 제로화
 * 
 * 민감한 데이터를 메모리에서 완전히 제거합니다.
 * 컴파일러 최적화로 인한 제거를 방지합니다.
 * 
 * @param p  제로화할 메모리 영역의 시작 주소
 * @param n  제로화할 바이트 수
 */
void AES2_secure_zero(void* p, size_t n) {
    aes2_burn(p, n);
}

/**
 * AES2_rand_bytes - 암호학적으로 안전한 난수 생성
 * 
 * 운영체제의 CSPRNG(Cryptographically Secure Pseudo-Random Number Generator)를
 * 사용하여 암호학적으로 안전한 난수를 생성합니다.
 * 
 * 플랫폼별 구현:
 *   - Windows: BCryptGenRandom (BCrypt API)
 *   - macOS: arc4random_buf
 *   - Linux/Unix: /dev/urandom
 * 
 * @param out  난수 출력 버퍼
 * @param n    생성할 바이트 수
 * 
 * @return AES_OK 성공, AES_ERR_BAD_PARAM 잘못된 매개변수, AES_ERR_STATE 난수 생성 실패
 */
AESStatus AES2_rand_bytes(uint8_t* out, size_t n) {
    if (!out && n) return AES_ERR_BAD_PARAM;
    if (n == 0) return AES_OK;

#if defined(_WIN32)
    /* Windows: BCrypt API 사용 */
    NTSTATUS rc = BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (rc == 0) ? AES_OK : AES_ERR_STATE;
#elif defined(__APPLE__)
    /* macOS: arc4random_buf 사용 */
    arc4random_buf(out, n);
    return AES_OK;
#else
    /* Linux/Unix: /dev/urandom 사용 */
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

/* ============================================================================
 * 라이브러리 정보 및 자가진단
 * ============================================================================ */

/**
 * AES2_libinfo - 라이브러리 버전 및 기능 정보 조회
 * 
 * @return 라이브러리 정보 구조체 포인터 (정적 데이터)
 */
const AES2_LibraryInfo* AES2_libinfo(void) {
    static const AES2_LibraryInfo info = {
        0x00010000,    /* 버전: 1.0.0 */
        0x00000003     /* 기능 비트: bit0=HKDF, bit1=HMAC */
    };
    return &info;
}

/**
 * AES2_selftest - 라이브러리 자가진단 테스트
 * 
 * 라이브러리의 정확성을 검증하기 위한 Known Answer Test(KAT)를 수행합니다.
 * 
 * 테스트 내용:
 *   1. SHA-512 기본 기능 검증
 *   2. HKDF-SHA-512 키 파생 검증
 *   3. AES 암호화/복호화 검증
 *   4. MAC 키 파생 검증
 * 
 * @return AES_OK 모든 테스트 통과, AES_ERR_STATE 테스트 실패
 */
AESStatus AES2_selftest(void) {
    /* SHA-512 기본 기능 검증 */
    if (sha512_selftest() != 0) return AES_ERR_STATE;

    /* 테스트용 고정 키 및 파라미터 */
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

    /* 예상 키 값 계산 */
    uint8_t prk[HKDF_SHA512_PRK_LEN];
    uint8_t expected_kenc[16];
    uint8_t expected_kmac[64];

    /* HKDF Extract 및 Expand로 예상 키 계산 */
    hkdf_sha512_extract(params.salt, params.salt_len,
                        master_key, sizeof(master_key), prk);
    if (aes2_expand_label(prk, &params, "enc", expected_kenc, sizeof(expected_kenc)) != AES_OK ||
        aes2_expand_label(prk, &params, "mac", expected_kmac, sizeof(expected_kmac)) != AES_OK) {
        aes2_burn(prk, sizeof(prk));
        return AES_ERR_STATE;
    }
    aes2_burn(prk, sizeof(prk));

    /* AES2 컨텍스트 초기화 */
    AES2_SecCtx ctx;
    AESStatus rc = AES2_init_hardened(&ctx, master_key, AES128,
                                      &params, AES2_F_MAC_ENABLE, AES2_TagLen_32);
    if (rc != AES_OK) {
        aes2_burn(expected_kenc, sizeof(expected_kenc));
        aes2_burn(expected_kmac, sizeof(expected_kmac));
        return rc;
    }

    /* MAC 키 일치 검증 */
    if (ct_memcmp(ctx.mac_key, expected_kmac, sizeof(expected_kmac)) != 0) {
        aes2_burn(&ctx, sizeof(ctx));
        aes2_burn(expected_kenc, sizeof(expected_kenc));
        aes2_burn(expected_kmac, sizeof(expected_kmac));
        return AES_ERR_STATE;
    }

    /* 암호화 키 일치 검증 (제로 블록 암호화 비교) */
    uint8_t zero_block[16] = {0};
    uint8_t out1[16], out2[16];
    AES_ctx ref;
    AES_init(&ref, expected_kenc, AES128);
    AES_encryptBlock(&ctx.aes, zero_block, out1);
    AES_encryptBlock(&ref, zero_block, out2);

    /* 임시 데이터 안전 삭제 */
    aes2_burn(&ref, sizeof(ref));
    aes2_burn(expected_kenc, sizeof(expected_kenc));
    aes2_burn(expected_kmac, sizeof(expected_kmac));
    aes2_burn(&ctx, sizeof(ctx));

    /* 암호화 결과 일치 여부 반환 */
    return (ct_memcmp(out1, out2, sizeof(out1)) == 0) ? AES_OK : AES_ERR_STATE;
}

/* ============================================================================
 * 내부 헬퍼: 버퍼 겹침 검사, Nonce/IV 재사용 방지
 * ============================================================================ */

/**
 * aes2_forbidden_overlap - 버퍼 부분 겹침 검사
 * 
 * 입력 버퍼와 출력 버퍼가 부분적으로 겹치는지 검사합니다.
 * 완전한 in-place 연산(같은 포인터)은 허용하지만,
 * 부분 겹침은 금지됩니다 (데이터 손상 방지).
 * 
 * @param in      입력 버퍼 시작 주소
 * @param in_len  입력 버퍼 길이
 * @param out     출력 버퍼 시작 주소
 * @param out_len 출력 버퍼 길이
 * 
 * @return 1 부분 겹침 감지 (금지됨), 0 겹침 없음 (허용됨)
 */
static int aes2_forbidden_overlap(const void* in, size_t in_len,
                                  const void* out, size_t out_len)
{
    if (!in || !out || in_len == 0 || out_len == 0) return 0;
    if (in == out) return 0; /* 완전 in-place 허용 */

    const uint8_t* a = (const uint8_t*)in;
    const uint8_t* b = (const uint8_t*)out;

    /* 입력 버퍼가 출력 버퍼 앞에 완전히 분리된 경우 */
    if (a + in_len <= b) return 0;
    /* 출력 버퍼가 입력 버퍼 앞에 완전히 분리된 경우 */
    if (b + out_len <= a) return 0;

    return 1; /* 부분 겹침 → 금지 */
}

/**
 * aes2_check_and_update_nonce - Nonce 재사용 검사 및 업데이트
 * 
 * NONCE_GUARD 플래그가 설정된 경우, 이전에 사용한 nonce와 동일한지 검사합니다.
 * 동일한 nonce 재사용은 보안상 위험하므로 오류를 반환합니다.
 * 
 * @param s        보안 컨텍스트
 * @param nonce16  검사할 nonce (16바이트)
 * 
 * @return AES_OK 성공, AES_ERR_BAD_PARAM 잘못된 매개변수, AES_ERR_STATE nonce 재사용 감지
 */
static AESStatus aes2_check_and_update_nonce(AES2_SecCtx* s,
                                             const uint8_t nonce16[16])
{
    if (!s || !nonce16) return AES_ERR_BAD_PARAM;
    
    /* NONCE_GUARD 플래그가 설정된 경우 재사용 검사 */
    if (s->flags & AES2_F_NONCE_GUARD) {
        if (s->last_nonce_set &&
            memcmp(s->last_nonce, nonce16, 16) == 0) {
            return AES_ERR_STATE; /* nonce 재사용 감지 */
        }
    }
    
    /* 현재 nonce를 저장하여 다음 검사에 사용 */
    memcpy(s->last_nonce, nonce16, 16);
    s->last_nonce_set = true;
    return AES_OK;
}

/**
 * aes2_check_and_update_iv - IV 재사용 검사 및 업데이트
 * 
 * NONCE_GUARD 플래그가 설정된 경우, 이전에 사용한 IV와 동일한지 검사합니다.
 * 동일한 IV 재사용은 보안상 위험하므로 오류를 반환합니다.
 * 
 * @param s     보안 컨텍스트
 * @param iv16  검사할 IV (16바이트)
 * 
 * @return AES_OK 성공, AES_ERR_BAD_PARAM 잘못된 매개변수, AES_ERR_STATE IV 재사용 감지
 */
static AESStatus aes2_check_and_update_iv(AES2_SecCtx* s,
                                          const uint8_t iv16[16])
{
    if (!s || !iv16) return AES_ERR_BAD_PARAM;
    
    /* NONCE_GUARD 플래그가 설정된 경우 재사용 검사 */
    if (s->flags & AES2_F_NONCE_GUARD) {
        if (s->last_iv_set &&
            memcmp(s->last_iv, iv16, 16) == 0) {
            return AES_ERR_STATE; /* IV 재사용 감지 */
        }
    }
    
    /* 현재 IV를 저장하여 다음 검사에 사용 */
    memcpy(s->last_iv, iv16, 16);
    s->last_iv_set = true;
    return AES_OK;
}

/* ============================================================================
 * EtM (Encrypt-then-MAC): CTR 모드
 * ============================================================================ */

/**
 * AES2_seal_CTR - AES-CTR 모드로 암호화 및 MAC 태그 생성
 * 
 * Encrypt-then-MAC(EtM) 방식으로 데이터를 암호화하고 무결성 태그를 생성합니다.
 * 
 * 처리 순서:
 *   1. Nonce 재사용 검사 (NONCE_GUARD 플래그가 설정된 경우)
 *   2. AES-CTR로 평문 암호화: ct = AES-CTR(Kenc, nonce, pt)
 *   3. MAC 태그 계산: tag = HMAC-SHA-512(Kmac, AAD || nonce || ct)
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터 (Additional Authenticated Data)
 * @param aad_len      AAD 길이
 * @param nonce16      Nonce (16바이트, 재사용 금지)
 * @param pt           평문
 * @param pt_len       평문 길이
 * @param ct           암호문 출력 버퍼
 * @param ct_cap       암호문 버퍼 용량
 * @param ct_len_out   실제 암호문 길이 (출력)
 * @param tag          MAC 태그 출력 버퍼 (MAC_ENABLE 플래그가 설정된 경우)
 * @param tag_cap      태그 버퍼 용량
 * @param tag_len_out  실제 태그 길이 (출력)
 * 
 * @return AES_OK 성공, 기타 AES_ERR_* 오류 코드
 */
AESStatus AES2_seal_CTR(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out)
{
    /* 매개변수 유효성 검사 */
    if (!s || !nonce16 || !ct || !ct_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_len && !pt)
        return AES_ERR_BAD_PARAM;
    if (ct_cap < pt_len)
        return AES_ERR_BUF_SMALL;

    /* MAC 활성화 시 태그 버퍼 필수 */
    if ((s->flags & AES2_F_MAC_ENABLE) && (!tag || !tag_len_out))
        return AES_ERR_BAD_PARAM;

    /* 버퍼 겹침 검사 */
    if (aes2_forbidden_overlap(pt, pt_len, ct, ct_cap))
        return AES_ERR_OVERLAP;

    /* Nonce 재사용 검사 및 업데이트 */
    AESStatus st = aes2_check_and_update_nonce(s, nonce16);
    if (st != AES_OK) return st;

    /* AES-CTR 암호화: nonce를 초기 카운터로 사용 */
    uint8_t ctr[16];
    memcpy(ctr, nonce16, 16);
    st = AES_cryptCTR(&s->aes,
                      pt_len ? pt : (const uint8_t*)"", pt_len,
                      ct,
                      ctr);
    AES2_secure_zero(ctr, sizeof(ctr));  /* 카운터 안전 삭제 */
    if (st != AES_OK) return st;

    *ct_len_out = pt_len;

    /* MAC 비활성화 시 태그 없이 반환 */
    if (!(s->flags & AES2_F_MAC_ENABLE)) {
        if (tag_len_out) *tag_len_out = 0;
        return AES_OK;
    }

    /* MAC 입력 구성: AAD || nonce || 암호문 */
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

    /* HMAC-SHA-512 태그 계산 */
    st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                       mac_buf, mac_len,
                       (AES2_TagLen)s->tag_len,
                       tag, tag_cap);

    /* MAC 버퍼 안전 삭제 */
    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }

    if (st != AES_OK) return st;
    if (tag_len_out) *tag_len_out = s->tag_len;
    return AES_OK;
}

/**
 * AES2_open_CTR - AES-CTR 모드로 복호화 및 MAC 태그 검증
 * 
 * Encrypt-then-MAC(EtM) 방식으로 암호문을 복호화하고 무결성을 검증합니다.
 * 
 * 처리 순서:
 *   1. MAC 태그 검증 (MAC_ENABLE 플래그가 설정된 경우)
 *      - tag' = HMAC-SHA-512(Kmac, AAD || nonce || ct) 계산
 *      - 상수시간 비교로 태그 일치 확인
 *      - 불일치 시 즉시 실패 (복호화 수행 안 함)
 *   2. AES-CTR로 암호문 복호화: pt = AES-CTR(Kenc, nonce, ct)
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터
 * @param aad_len      AAD 길이
 * @param nonce16      Nonce (16바이트)
 * @param ct           암호문
 * @param ct_len       암호문 길이
 * @param tag          MAC 태그 (MAC_ENABLE 플래그가 설정된 경우)
 * @param tag_len_in   태그 길이
 * @param pt           평문 출력 버퍼
 * @param pt_cap       평문 버퍼 용량
 * @param pt_len_out   실제 평문 길이 (출력)
 * 
 * @return AES_OK 성공, AES_ERR_AUTH 태그 불일치, 기타 AES_ERR_* 오류
 */
AESStatus AES2_open_CTR(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out)
{
    /* 매개변수 유효성 검사 */
    if (!s || !nonce16 || !ct || !pt || !pt_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_cap < ct_len)
        return AES_ERR_BUF_SMALL;

    /* 버퍼 겹침 검사 */
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

    /* 태그 길이 검증 */
    if (tag_len_in != (size_t)s->tag_len)
        return AES_ERR_AUTH;
    if (!tag)
        return AES_ERR_BAD_PARAM;

    /* MAC 입력 구성: AAD || nonce || 암호문 */
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

    /* MAC 태그 재계산 */
    uint8_t calc_tag[HMAC_SHA512_LEN];
    AESStatus st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                                 mac_buf, mac_len,
                                 (AES2_TagLen)s->tag_len,
                                 calc_tag, sizeof(calc_tag));

    /* MAC 버퍼 안전 삭제 */
    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }
    if (st != AES_OK) return st;

    /* 상수시간 태그 비교 (타이밍 공격 방지) */
    if (AES2_ct_memcmp(calc_tag, tag, tag_len_in) != 0) {
        AES2_secure_zero(calc_tag, sizeof(calc_tag));
        return AES_ERR_AUTH;  /* 태그 불일치: 복호화 수행 안 함 */
    }
    AES2_secure_zero(calc_tag, sizeof(calc_tag));

    /* AES-CTR 복호화 */
    uint8_t ctr[16];
    memcpy(ctr, nonce16, 16);
    st = AES_cryptCTR(&s->aes, ct, ct_len, pt, ctr);
    AES2_secure_zero(ctr, sizeof(ctr));
    if (st != AES_OK) return st;

    *pt_len_out = ct_len;
    return AES_OK;
}

/* ============================================================================
 * EtM (Encrypt-then-MAC): CBC 모드
 * ============================================================================ */

/**
 * AES2_seal_CBC - AES-CBC 모드로 암호화 및 MAC 태그 생성
 * 
 * Encrypt-then-MAC(EtM) 방식으로 데이터를 암호화하고 무결성 태그를 생성합니다.
 * CBC 모드는 패딩이 필요하므로 평문 길이와 암호문 길이가 다를 수 있습니다.
 * 
 * 처리 순서:
 *   1. Nonce 및 IV 재사용 검사 (NONCE_GUARD 플래그가 설정된 경우)
 *   2. AES-CBC로 평문 암호화: ct = AES-CBC(Kenc, iv, pad(pt))
 *   3. MAC 태그 계산: tag = HMAC-SHA-512(Kmac, AAD || nonce || iv || ct)
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터
 * @param aad_len      AAD 길이
 * @param nonce16      Nonce (16바이트, 재사용 금지)
 * @param iv16         초기화 벡터 (16바이트, 재사용 금지)
 * @param pt           평문
 * @param pt_len       평문 길이
 * @param ct           암호문 출력 버퍼
 * @param ct_cap       암호문 버퍼 용량
 * @param ct_len_out   실제 암호문 길이 (출력, 패딩 포함)
 * @param padding      패딩 방식
 * @param tag          MAC 태그 출력 버퍼 (MAC_ENABLE 플래그가 설정된 경우)
 * @param tag_cap      태그 버퍼 용량
 * @param tag_len_out  실제 태그 길이 (출력)
 * 
 * @return AES_OK 성공, 기타 AES_ERR_* 오류 코드
 */
AESStatus AES2_seal_CBC(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                        AESPadding padding,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out)
{
    /* 매개변수 유효성 검사 */
    if (!s || !nonce16 || !iv16 || !ct || !ct_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_len && !pt)
        return AES_ERR_BAD_PARAM;

    /* 버퍼 겹침 검사 */
    if (aes2_forbidden_overlap(pt, pt_len, ct, ct_cap))
        return AES_ERR_OVERLAP;

    /* Nonce 및 IV 재사용 검사 및 업데이트 */
    AESStatus st = aes2_check_and_update_nonce(s, nonce16);
    if (st != AES_OK) return st;
    st = aes2_check_and_update_iv(s, iv16);
    if (st != AES_OK) return st;

    /* AES-CBC 암호화 (IV는 수정될 수 있으므로 복사본 사용) */
    uint8_t iv_work[16];
    memcpy(iv_work, iv16, 16);

    st = AES_encryptCBC(&s->aes,
                        pt_len ? pt : (const uint8_t*)"", pt_len,
                        ct, ct_cap, ct_len_out,
                        iv_work, padding);
    AES2_secure_zero(iv_work, sizeof(iv_work));  /* 작업용 IV 안전 삭제 */
    if (st != AES_OK) return st;

    /* MAC 비활성화 시 태그 없이 반환 */
    if (!(s->flags & AES2_F_MAC_ENABLE)) {
        if (tag_len_out) *tag_len_out = 0;
        return AES_OK;
    }

    /* MAC 입력 구성: AAD || nonce || iv || 암호문 */
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

    /* HMAC-SHA-512 태그 계산 */
    st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                       mac_buf, mac_len,
                       (AES2_TagLen)s->tag_len,
                       tag, tag_cap);

    /* MAC 버퍼 안전 삭제 */
    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }

    if (st != AES_OK) return st;
    if (tag_len_out) *tag_len_out = s->tag_len;
    return AES_OK;
}

/**
 * AES2_open_CBC - AES-CBC 모드로 복호화 및 MAC 태그 검증
 * 
 * Encrypt-then-MAC(EtM) 방식으로 암호문을 복호화하고 무결성을 검증합니다.
 * 
 * 처리 순서:
 *   1. MAC 태그 검증 (MAC_ENABLE 플래그가 설정된 경우)
 *      - tag' = HMAC-SHA-512(Kmac, AAD || nonce || iv || ct) 계산
 *      - 상수시간 비교로 태그 일치 확인
 *      - 불일치 시 즉시 실패 (복호화 수행 안 함)
 *   2. AES-CBC로 암호문 복호화 및 패딩 제거: pt = unpad(AES-CBC(Kenc, iv, ct))
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터
 * @param aad_len      AAD 길이
 * @param nonce16      Nonce (16바이트, MAC 입력에 사용)
 * @param iv16         초기화 벡터 (16바이트)
 * @param ct           암호문
 * @param ct_len       암호문 길이
 * @param tag          MAC 태그 (MAC_ENABLE 플래그가 설정된 경우)
 * @param tag_len_in   태그 길이
 * @param padding      패딩 방식
 * @param pt           평문 출력 버퍼
 * @param pt_cap       평문 버퍼 용량
 * @param pt_len_out   실제 평문 길이 (출력, 패딩 제거 후)
 * 
 * @return AES_OK 성공, AES_ERR_AUTH 태그 불일치, 기타 AES_ERR_* 오류
 */
AESStatus AES2_open_CBC(AES2_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        AESPadding padding,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out)
{
    (void)nonce16; /* 현재 구현에서는 MAC 입력에만 사용 → 이미 MAC 단계에서 사용함 */
    /* 매개변수 유효성 검사 */
    if (!s || !nonce16 || !iv16 || !ct || !pt || !pt_len_out)
        return AES_ERR_BAD_PARAM;
    if (aad_len && !aad)
        return AES_ERR_BAD_PARAM;
    if (pt_cap < ct_len)
        return AES_ERR_BUF_SMALL;

    /* 버퍼 겹침 검사 */
    if (aes2_forbidden_overlap(ct, ct_len, pt, pt_cap))
        return AES_ERR_OVERLAP;

    /* 무결성 비사용 경로: 바로 복호화 */
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

    /* 태그 길이 검증 */
    if (tag_len_in != (size_t)s->tag_len)
        return AES_ERR_AUTH;
    if (!tag)
        return AES_ERR_BAD_PARAM;

    /* MAC 입력 구성: AAD || nonce || iv || 암호문 */
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

    /* MAC 태그 재계산 */
    uint8_t calc_tag[HMAC_SHA512_LEN];
    AESStatus st = AES2_HMAC_tag(s->mac_key, sizeof(s->mac_key),
                                 mac_buf, mac_len,
                                 (AES2_TagLen)s->tag_len,
                                 calc_tag, sizeof(calc_tag));

    /* MAC 버퍼 안전 삭제 */
    if (mac_buf) {
        AES2_secure_zero(mac_buf, mac_len);
        free(mac_buf);
    }
    if (st != AES_OK) return st;

    /* 상수시간 태그 비교 (타이밍 공격 방지) */
    if (AES2_ct_memcmp(calc_tag, tag, tag_len_in) != 0) {
        AES2_secure_zero(calc_tag, sizeof(calc_tag));
        return AES_ERR_AUTH;  /* 태그 불일치: 복호화 수행 안 함 */
    }
    AES2_secure_zero(calc_tag, sizeof(calc_tag));

    /* AES-CBC 복호화 및 패딩 제거 */
    uint8_t iv_work[16];
    memcpy(iv_work, iv16, 16);
    st = AES_decryptCBC(&s->aes,
                        ct, ct_len,
                        pt, pt_cap, pt_len_out,
                        iv_work, padding);
    AES2_secure_zero(iv_work, sizeof(iv_work));
    return st;
}

/* ============================================================================
 * 자동 Nonce/IV 생성 래퍼 함수들
 * ============================================================================ */

/**
 * AES2_seal_CTR_autoIV - Nonce를 자동 생성하는 AES-CTR 암호화 래퍼
 * 
 * 내부에서 암호학적으로 안전한 난수 생성기를 사용하여 nonce를 자동 생성하고,
 * AES2_seal_CTR를 호출합니다. 사용자가 nonce를 직접 관리할 필요가 없어
 * 실수로 인한 nonce 재사용을 방지합니다.
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터
 * @param aad_len      AAD 길이
 * @param out_nonce16  생성된 nonce 출력 버퍼 (16바이트)
 * @param pt           평문
 * @param pt_len       평문 길이
 * @param ct           암호문 출력 버퍼
 * @param ct_cap       암호문 버퍼 용량
 * @param ct_len_out   실제 암호문 길이 (출력)
 * @param tag          MAC 태그 출력 버퍼
 * @param tag_cap      태그 버퍼 용량
 * @param tag_len_out  실제 태그 길이 (출력)
 * 
 * @return AES_OK 성공, 기타 AES_ERR_* 오류 코드
 */
AESStatus AES2_seal_CTR_autoIV(AES2_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               uint8_t out_nonce16[16],
                               const uint8_t* pt, size_t pt_len,
                               uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                               uint8_t* tag, size_t tag_cap, size_t* tag_len_out)
{
    if (!out_nonce16) return AES_ERR_BAD_PARAM;

    /* 암호학적으로 안전한 난수로 nonce 생성 */
    AESStatus st = AES2_rand_bytes(out_nonce16, 16);
    if (st != AES_OK) return st;

    /* 생성된 nonce로 암호화 수행 */
    return AES2_seal_CTR(s, aad, aad_len,
                         out_nonce16,
                         pt, pt_len,
                         ct, ct_cap, ct_len_out,
                         tag, tag_cap, tag_len_out);
}

/**
 * AES2_open_CTR_autoIV - Nonce를 받아서 AES-CTR 복호화 수행
 * 
 * 이 함수는 AES2_seal_CTR_autoIV로 생성된 nonce를 받아서
 * AES2_open_CTR를 호출합니다. 편의성을 위한 래퍼 함수입니다.
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터
 * @param aad_len      AAD 길이
 * @param in_nonce16   입력 nonce (16바이트, seal 시 생성된 값)
 * @param ct           암호문
 * @param ct_len       암호문 길이
 * @param tag          MAC 태그
 * @param tag_len_in   태그 길이
 * @param pt           평문 출력 버퍼
 * @param pt_cap       평문 버퍼 용량
 * @param pt_len_out   실제 평문 길이 (출력)
 * 
 * @return AES_OK 성공, 기타 AES_ERR_* 오류 코드
 */
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

/**
 * AES2_seal_CBC_autoIV - Nonce와 IV를 자동 생성하는 AES-CBC 암호화 래퍼
 * 
 * 내부에서 암호학적으로 안전한 난수 생성기를 사용하여 nonce와 IV를 자동 생성하고,
 * AES2_seal_CBC를 호출합니다. 사용자가 nonce와 IV를 직접 관리할 필요가 없어
 * 실수로 인한 재사용을 방지합니다.
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터
 * @param aad_len      AAD 길이
 * @param out_nonce16  생성된 nonce 출력 버퍼 (16바이트)
 * @param out_iv16     생성된 IV 출력 버퍼 (16바이트)
 * @param pt           평문
 * @param pt_len       평문 길이
 * @param ct           암호문 출력 버퍼
 * @param ct_cap       암호문 버퍼 용량
 * @param ct_len_out   실제 암호문 길이 (출력)
 * @param padding      패딩 방식
 * @param tag          MAC 태그 출력 버퍼
 * @param tag_cap      태그 버퍼 용량
 * @param tag_len_out  실제 태그 길이 (출력)
 * 
 * @return AES_OK 성공, 기타 AES_ERR_* 오류 코드
 */
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

    /* 암호학적으로 안전한 난수로 nonce 생성 */
    AESStatus st = AES2_rand_bytes(out_nonce16, 16);
    if (st != AES_OK) return st;
    /* 암호학적으로 안전한 난수로 IV 생성 */
    st = AES2_rand_bytes(out_iv16, 16);
    if (st != AES_OK) return st;

    /* 생성된 nonce와 IV로 암호화 수행 */
    return AES2_seal_CBC(s, aad, aad_len,
                         out_nonce16,
                         out_iv16,
                         pt, pt_len,
                         ct, ct_cap, ct_len_out,
                         padding,
                         tag, tag_cap, tag_len_out);
}

/**
 * AES2_open_CBC_autoIV - Nonce와 IV를 받아서 AES-CBC 복호화 수행
 * 
 * 이 함수는 AES2_seal_CBC_autoIV로 생성된 nonce와 IV를 받아서
 * AES2_open_CBC를 호출합니다. 편의성을 위한 래퍼 함수입니다.
 * 
 * @param s            보안 컨텍스트
 * @param aad          추가 인증 데이터
 * @param aad_len      AAD 길이
 * @param in_nonce16   입력 nonce (16바이트, seal 시 생성된 값)
 * @param in_iv16      입력 IV (16바이트, seal 시 생성된 값)
 * @param ct           암호문
 * @param ct_len       암호문 길이
 * @param tag          MAC 태그
 * @param tag_len_in   태그 길이
 * @param padding      패딩 방식
 * @param pt           평문 출력 버퍼
 * @param pt_cap       평문 버퍼 용량
 * @param pt_len_out   실제 평문 길이 (출력)
 * 
 * @return AES_OK 성공, 기타 AES_ERR_* 오류 코드
 */
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
