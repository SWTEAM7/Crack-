#ifndef AES2_SECURE_H
#define AES2_SECURE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "aes.h"   // AES #1(위에 속도형 코드): 기존 API 유지 (ECB/CBC/CTR, 패딩, 오류처리)

// ── KDF 파라미터 ─────────────────────────────────────────────────────────────
typedef struct {
    const uint8_t* salt;   // 세션/메시지 식별(권장 16~32B, 재사용 금지)
    size_t         salt_len;
    const uint8_t* info;   // 도메인 분리 문자열(예: "AES2|rk")
    size_t         info_len;
} AES2_KDFParams;

// ── 보안 컨트롤 플래그 ───────────────────────────────────────────────────────
typedef enum {
    AES2_F_NONE       = 0,
    AES2_F_MAC_ENABLE = 1 << 0,   // HMAC-SHA256 태그 사용
    AES2_F_NONCE_GUARD= 1 << 1    // 최근 nonce/IV 재사용 차단
} AES2_Flags;

// ── 보안 컨텍스트(라운드키/무결성/오남용 방지 상태) ─────────────────────────
typedef struct {
    AES_ctx    aes;                 // 기존 AES 컨텍스트(라운드 함수 재사용)
    AESKeyLength keylen;            // AES128/192/256
    AES2_Flags flags;               // 보안 기능 토글

    // MAC용 키(옵션)
    uint8_t mac_key[32];            // HMAC-SHA256
    uint8_t tag_len;                // 16 or 32

    // 재사용 방지(간단 캐시): 마지막 nonce/iv 저장
    uint8_t last_nonce[16];
    uint8_t last_iv[16];
    bool    last_nonce_set;
    bool    last_iv_set;
} AES2_SecCtx;

// ── 필수: 보안형 초기화 (라운드키 독립 파생 + 선택적 MAC키 파생) ────────────
AESStatus AES2_init_hardened(AES2_SecCtx* s,
                             const uint8_t* master_key, AESKeyLength keyLen,
                             const AES2_KDFParams* kdf,
                             AES2_Flags flags,
                             uint8_t mac_tag_len /* 16 or 32 */);

// ── 헬퍼: CTR/CBC에 무결성 태그 붙이기/검증(간단 인터페이스) ────────────────
// * CTR: 패딩 없음 / CBC: PKCS#7 또는 ANSI X9.23
AESStatus AES2_seal_CTR(AES2_SecCtx* s,
                        const uint8_t* nonce16,  // 16바이트(= salt 재사용 가능)
                        const uint8_t* iv16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out);

AESStatus AES2_open_CTR(AES2_SecCtx* s,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out);

AESStatus AES2_seal_CBC(AES2_SecCtx* s,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len,
                        AESPadding padding,  // PKCS7/X9.23
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out);

AESStatus AES2_open_CBC(AES2_SecCtx* s,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        AESPadding padding,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out);

// ── 유틸(선택) ───────────────────────────────────────────────────────────────
void AES2_secure_zero(void* p, size_t n);   // 안전 삭제
int  AES2_ct_memcmp(const void* a, const void* b, size_t n); // 상수시간 비교

// 간단 자기진단(KAT) 훅: 구현 후 NIST 벡터로 통과 확인
AESStatus AES2_selftest(void);

#endif /* AES2_SECURE_H */
