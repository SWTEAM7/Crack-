/* =========================================================================
 * sha512.h - SHA-512, HMAC-SHA-512, HKDF-SHA-512 (RFC 6234 / RFC 4231 / RFC 5869)
 * C99 순수 구현 (동적 할당 없음). 라이선스: 퍼블릭 도메인/CC0 유사.
 * ------------------------------------------------------------------------- */
#pragma execution_character_set("utf-8")

#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SHA-512 상수 정의
 * ============================================================================ */

/** SHA512_DIGEST_LEN - SHA-512 해시 출력 길이 (바이트) */
#define SHA512_DIGEST_LEN 64u

/** SHA512_BLOCK_LEN - SHA-512 블록 크기 (바이트) */
#define SHA512_BLOCK_LEN  128u

/* ============================================================================
 * SHA-512 컨텍스트 구조체
 * ============================================================================ */

/**
 * SHA512_CTX - SHA-512 해시 계산을 위한 컨텍스트 구조체
 * 
 * 이 구조체는 SHA-512 해시 계산의 중간 상태를 저장합니다.
 * 여러 데이터 청크를 순차적으로 처리할 때 사용됩니다.
 * 
 * 멤버:
 *   h[8]        - 해시 상태 값 (8개의 64비트 워드)
 *   tot_len_hi  - 처리된 총 바이트 수의 상위 64비트
 *   tot_len_lo  - 처리된 총 바이트 수의 하위 64비트
 *   buf         - 부분 블록 버퍼 (최대 128바이트)
 *   buf_len     - 버퍼에 저장된 바이트 수
 */
typedef struct {
    uint64_t h[8];          /* 해시 상태 (8개 워드) */
    uint64_t tot_len_hi;    /* 총 길이 상위 64비트 */
    uint64_t tot_len_lo;    /* 총 길이 하위 64비트 */
    uint8_t  buf[SHA512_BLOCK_LEN];  /* 부분 블록 버퍼 */
    size_t   buf_len;       /* 버퍼에 저장된 바이트 수 */
} SHA512_CTX;

/* ============================================================================
 * SHA-512 기본 함수
 * ============================================================================ */

/**
 * sha512_init - SHA-512 해시 컨텍스트 초기화
 * 
 * SHA-512 해시 계산을 시작하기 위해 컨텍스트를 초기 상태로 설정합니다.
 * 
 * @param c  초기화할 SHA-512 컨텍스트 포인터
 */
void sha512_init(SHA512_CTX* c);

/**
 * sha512_update - SHA-512 해시에 데이터 추가
 * 
 * 주어진 데이터를 해시 계산에 포함시킵니다. 이 함수는 여러 번 호출될 수 있으며,
 * 각 호출마다 데이터가 누적되어 해시에 반영됩니다.
 * 
 * @param c     SHA-512 컨텍스트 포인터
 * @param data  해시에 포함할 데이터
 * @param len   데이터 길이 (바이트)
 */
void sha512_update(SHA512_CTX* c, const void* data, size_t len);

/**
 * sha512_final - SHA-512 해시 계산 완료 및 결과 출력
 * 
 * 모든 데이터가 추가된 후 최종 해시 값을 계산하고 출력합니다.
 * 이 함수 호출 후 컨텍스트는 더 이상 사용할 수 없습니다.
 * 
 * @param c    SHA-512 컨텍스트 포인터
 * @param out  해시 결과 출력 버퍼 (64바이트)
 */
void sha512_final(SHA512_CTX* c, uint8_t out[SHA512_DIGEST_LEN]);

/**
 * sha512 - 단일 호출로 SHA-512 해시 계산
 * 
 * 데이터를 한 번에 해시하는 편의 함수입니다.
 * 내부적으로 init, update, final을 순차적으로 호출합니다.
 * 
 * @param data  해시할 데이터
 * @param len   데이터 길이 (바이트)
 * @param out   해시 결과 출력 버퍼 (64바이트)
 */
void sha512(const void* data, size_t len, uint8_t out[SHA512_DIGEST_LEN]);

/* ============================================================================
 * HMAC-SHA-512 함수
 * ============================================================================ */

/** HMAC_SHA512_LEN - HMAC-SHA-512 출력 길이 (바이트) */
#define HMAC_SHA512_LEN 64u

/**
 * hmac_sha512 - HMAC-SHA-512 메시지 인증 코드 계산
 * 
 * HMAC (Hash-based Message Authentication Code) 알고리즘을 사용하여
 * 메시지의 무결성과 인증을 위한 태그를 생성합니다.
 * 
 * 구현: HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
 *   - K': 키를 블록 크기에 맞게 패딩 또는 해시
 *   - opad: 외부 패딩 (0x5c 반복)
 *   - ipad: 내부 패딩 (0x36 반복)
 *   - H: SHA-512 해시 함수
 * 
 * @param key      MAC 키
 * @param key_len  키 길이 (바이트)
 * @param msg      인증할 메시지
 * @param msg_len  메시지 길이 (바이트)
 * @param out      HMAC 출력 버퍼 (64바이트)
 */
void hmac_sha512(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[HMAC_SHA512_LEN]);

/**
 * hmac_sha512_verify - HMAC-SHA-512 태그 검증
 * 
 * 계산된 HMAC 태그와 제공된 태그를 비교하여 메시지의 무결성을 검증합니다.
 * 
 * @param key      MAC 키
 * @param key_len  키 길이 (바이트)
 * @param msg      검증할 메시지
 * @param msg_len  메시지 길이 (바이트)
 * @param tag      검증할 태그
 * @param tag_len  태그 길이 (바이트, 최대 64)
 * 
 * @return 0 태그 일치 (검증 성공), 0이 아니면 불일치 (검증 실패)
 */
int hmac_sha512_verify(const uint8_t* key, size_t key_len,
                       const uint8_t* msg, size_t msg_len,
                       const uint8_t* tag, size_t tag_len);

/* ============================================================================
 * HKDF-SHA-512 함수 (RFC 5869)
 * ============================================================================ */

/** HKDF_SHA512_PRK_LEN - HKDF Extract 단계 출력 길이 (바이트) */
#define HKDF_SHA512_PRK_LEN 64u

/** HKDF_SHA512_OK - HKDF 작업 성공 */
#define HKDF_SHA512_OK   0

/** HKDF_SHA512_ERR - HKDF 작업 실패 */
#define HKDF_SHA512_ERR -1

/**
 * hkdf_sha512_extract - HKDF Extract 단계 수행
 * 
 * HKDF (HMAC-based Key Derivation Function)의 Extract 단계를 수행합니다.
 * 입력 키 재료(IKM)와 솔트(salt)로부터 의사 난수 키(PRK)를 생성합니다.
 * 
 * 구현: PRK = HMAC-SHA-512(salt, IKM)
 * 
 * @param salt      솔트 (선택적, NULL이면 제로 패딩)
 * @param salt_len  솔트 길이 (바이트)
 * @param ikm       입력 키 재료 (Input Keying Material)
 * @param ikm_len   IKM 길이 (바이트)
 * @param prk       출력 PRK 버퍼 (64바이트)
 */
void hkdf_sha512_extract(const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm,  size_t ikm_len,
                         uint8_t prk[HKDF_SHA512_PRK_LEN]);

/**
 * hkdf_sha512_expand - HKDF Expand 단계 수행
 * 
 * HKDF의 Expand 단계를 수행합니다. PRK와 정보 문자열(info)을 사용하여
 * 원하는 길이의 출력 키 재료(OKM)를 생성합니다.
 * 
 * 구현: OKM = T(1) || T(2) || ... || T(L)
 *   T(i) = HMAC-SHA-512(PRK, T(i-1) || info || i)
 *   (T(0)는 빈 문자열)
 * 
 * @param prk       PRK (Extract 단계에서 생성)
 * @param info      정보 문자열 (도메인 분리용)
 * @param info_len  정보 문자열 길이 (바이트)
 * @param okm       출력 키 재료 버퍼
 * @param okm_len   원하는 OKM 길이 (바이트, 최대 255 * 64)
 * 
 * @return HKDF_SHA512_OK 성공, HKDF_SHA512_ERR 실패
 */
int hkdf_sha512_expand(const uint8_t* prk,
                       const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len);

/**
 * hkdf_sha512 - HKDF 전체 과정 수행 (Extract + Expand)
 * 
 * HKDF의 Extract와 Expand 단계를 한 번에 수행하는 편의 함수입니다.
 * 
 * @param salt      솔트
 * @param salt_len  솔트 길이 (바이트)
 * @param ikm       입력 키 재료
 * @param ikm_len   IKM 길이 (바이트)
 * @param info      정보 문자열
 * @param info_len  정보 문자열 길이 (바이트)
 * @param okm       출력 키 재료 버퍼
 * @param okm_len   원하는 OKM 길이 (바이트)
 * 
 * @return HKDF_SHA512_OK 성공, HKDF_SHA512_ERR 실패
 */
int hkdf_sha512(const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm,  size_t ikm_len,
                const uint8_t* info, size_t info_len,
                uint8_t* okm, size_t okm_len);

/* ============================================================================
 * 보안 유틸리티 함수
 * ============================================================================ */

/**
 * secure_zero - 메모리 영역을 안전하게 제로화
 * 
 * 민감한 데이터(키, 중간값 등)를 메모리에서 완전히 제거합니다.
 * 컴파일러 최적화로 인한 제거를 방지하기 위해 volatile 접근을 사용합니다.
 * 
 * @param p  제로화할 메모리 영역의 시작 주소
 * @param n  제로화할 바이트 수
 */
void secure_zero(void* p, size_t n);

/**
 * ct_memcmp - 상수시간 메모리 비교
 * 
 * 두 메모리 영역을 상수시간에 비교합니다. 타이밍 공격을 방지하기 위해
 * 비교 결과와 무관하게 항상 동일한 시간이 소요됩니다.
 * 
 * @param a  첫 번째 메모리 영역
 * @param b  두 번째 메모리 영역
 * @param n  비교할 바이트 수
 * 
 * @return 0 두 영역이 동일, 0이 아니면 다름
 */
int  ct_memcmp(const void* a, const void* b, size_t n);

/* ============================================================================
 * 자가진단 함수
 * ============================================================================ */

/**
 * sha512_selftest - SHA-512 구현 자가진단 테스트
 * 
 * SHA-512 구현의 정확성을 검증하기 위한 Known Answer Test(KAT)를 수행합니다.
 * 표준 테스트 벡터를 사용하여 해시 함수가 올바르게 동작하는지 확인합니다.
 * 
 * @return 0 모든 테스트 통과, 0이 아니면 테스트 실패
 */
int sha512_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* SHA512_H */
