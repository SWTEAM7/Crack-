#pragma execution_character_set("utf-8")

#ifndef CRACK_AES_SECURE_H
#define CRACK_AES_SECURE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "aes.h"   // AES1(속도형) 재사용: 키스케줄/ECB/CBC/CTR/패딩/에러코드
/* [PLAN] 1) 공통 규약: AESKeyLength / AESStatus / AESPadding 재사용
 * [MAP]  가. 키 길이/상태코드/패딩 -> aes.h의 열거형 그대로 사용 (API 일관성)
 */

/* ============================================================================
 * CRACK_AES(보안형) - 설계 요약 (SHA-512 고정)
 *  - 기밀성: AES-CTR 또는 AES-CBC (AES1 블록/모드 구현 재사용)
 *  - 무결성: HMAC-SHA-512 (출력 64B, 전송은 16B/32B 절단)
 *  - 키파생: HKDF-SHA-512 (Kmaster + salt + info -> Kenc, Kmac)
 *  - EtM(Encrypt-then-MAC): tag = HMAC-SHA-512(Kmac, AAD||nonce||IV?||CT)
 *  - 재사용 방지: 최근 nonce/IV 캐시로 연속 재사용 차단(옵션)
 * [MAP]  2) 프로파일별 설계(CRACK_AES) 전반을 SHA-512로 확정 반영.
 * ==========================================================================*/

/* == AES1 에러코드에 "인증 실패"가 없을 경우 대비 =========================
 * [PLAN]  에러 음수코드 집합 언급(무결성 실패 코드는 명시 없었음)
 * [MAP]   태그 불일치 구분을 위해 AES_ERR_AUTH(-7)을 조건부 정의(오라클 완화).
 */
#ifndef AES_ERR_AUTH
#define AES_ERR_AUTH (-7)  // 인증 실패(HMAC 태그 불일치)
#endif

/* == 태그 길이(절단 길이) ==================================================
 * [PLAN]  CRACK_AES 태그 32B 명시(일부 섹션), 16/32B 운용 가능
 * [MAP]   SHA-512 출력(64B)에서 16 또는 32바이트로 절단. ENUM으로 고정.
 */
typedef enum {
    CRACK_AES_TagLen_16 = 16,
    CRACK_AES_TagLen_32 = 32
} CRACK_AES_TagLen;

/* == KDF 파라미터 ===========================================================
 * [PLAN]  salt(세션 유일, 16B 권장), info(도메인 분리 문자열) 명시
 * [MAP]   HKDF-SHA-512 Extract/Expand에 그대로 투입. 재사용 금지 원칙 문서화.
 */
typedef struct {
    const uint8_t* salt;   // [PLAN] 세션/메시지 식별(권장 16~32B, 재사용 금지)
    size_t         salt_len;
    const uint8_t* info;   // [PLAN] 도메인 분리 문자열(예: "CRACK_AES|rk")
    size_t         info_len;
} CRACK_AES_KDFParams;

/* == 보안 컨트롤 플래그 ====================================================
 * [PLAN]  MAC_ENABLE / NONCE_GUARD 제시
 * [MAP]   EtM 사용/비사용, nonce/IV 재사용 차단을 라이브러리 차원에서 보조.
 */
typedef enum {
    CRACK_AES_F_NONE        = 0,
    CRACK_AES_F_MAC_ENABLE  = 1 << 0,  // [PLAN] 무결성 태그 사용(EtM: HMAC-SHA-512)
    CRACK_AES_F_NONCE_GUARD = 1 << 1   // [PLAN] 최근 nonce/IV 재사용 차단
} CRACK_AES_Flags;

/* == 보안 컨텍스트 =========================================================
 * [PLAN]  AES 컨텍스트(aes_ctx) 존재, CRACK_AES에서 KDF로 라운드키 주입·고정
 * [MAP]   aes: AES1 컨텍스트(라운드키/라운드함수) 재사용
 *          mac_key: HKDF-SHA-512로 파생된 HMAC 키 저장(64B)
 *          tag_len: 16/32
 *          last_nonce/iv: NONCE_GUARD 용 캐시
 */
typedef struct {
    AES_ctx       aes;           // [PLAN] 다. AES 컨텍스트: AES1 재사용
    AESKeyLength  keylen;
    CRACK_AES_Flags    flags;

    uint8_t       mac_key[64];   // [MAP] HMAC-SHA-512 키(64B) 보관
    uint8_t       tag_len;       // [MAP] CRACK_AES_TagLen_16 또는 _32

    // [PLAN] NONCE_GUARD: 최근 사용 nonce/iv 캐시
    uint8_t       last_nonce[16];
    uint8_t       last_iv[16];
    bool          last_nonce_set;
    bool          last_iv_set;
} CRACK_AES_SecCtx;

/* == 초기화 규약 ===========================================================
 * [PLAN]  나. 초기화 규약
 *   - AES1(속도형): 표준 키스케줄(round_keys/nr) 채움
 *   - CRACK_AES(보안형): HKDF-**SHA-512**로 파생된 키를 주입·고정(라운드키 독립성)
 * [MAP]  init: HKDF-SHA-512로 Kenc/Kmac 파생 -> AES_init(ctx,Kenc) 호출
 *        PRK = HMAC-SHA-512(salt, Kmaster)
 *        Kenc = HKDF-Expand(PRK, info="enc|v1|STRONG", L=keyLen)
 *        Kmac = HKDF-Expand(PRK, info="mac|v1|STRONG", L=64)
 */
AESStatus CRACK_AES_init_hardened(CRACK_AES_SecCtx* s,
                             const uint8_t* master_key, AESKeyLength keyLen,
                             const CRACK_AES_KDFParams* kdf,
                             CRACK_AES_Flags flags,
                             CRACK_AES_TagLen mac_tag_len /* 16 or 32 */);

/* == 버퍼 겹침 규칙(헤더 차원 주석) =======================================
 * [PLAN]  다. 버퍼 겹침 규칙
 *   - 동일 포인터(in-place) 허용 / 부분 겹침 금지 -> AES_ERR_OVERLAP
 * [MAP]  구현부에서 포인터 범위 검사로 강제. 아래 모든 seal/open 함수에 적용.
 */

/* == HMAC-SHA-512 태그 산출(절단 포함) =====================================
 * [PLAN]  태그 계산 및 상수시간 비교, 16/32B 절단 사용
 * [MAP]   EtM 빌딩블록 제공. SHA-512 고정. out_tag_cap >= tag_len 필요.
 */
AESStatus CRACK_AES_HMAC_tag(const uint8_t* mac_key, size_t mac_key_len,
                        const uint8_t* m, size_t m_len,
                        CRACK_AES_TagLen tag_len,
                        uint8_t* out_tag, size_t out_tag_cap);

/* == 상수시간 비교 / 보안 삭제 =============================================
 * [PLAN]  태그 비교 상수시간 구현 / secure zero 제공
 * [MAP]   타이밍 누출 완화 / 키·중간버퍼 잔류 제거
 */
int  CRACK_AES_ct_memcmp(const void* a, const void* b, size_t n);
void CRACK_AES_secure_zero(void* p, size_t n);

/* == OS CSPRNG 바이트 ======================================================
 * [PLAN]  OS 의사난수(BCrypt/arc4random/urandom) 사용
 * [MAP]   nonce/IV/임시키 생성용. rand() 금지.
 */
AESStatus CRACK_AES_rand_bytes(uint8_t* out, size_t n);

/* == EtM Helper: CTR (SHA-512 태그) =======================================
 * [PLAN]  CRACK_AES-보안형 CTR 경로 (SHA-512)
 *   암호화:  ct = AES-CTR(Kenc, nonce16, pt)
 *           tag = HMAC-SHA-512(Kmac, AAD || nonce16 || ct) -> 16/32B 절단
 *   복호화:  tag' 재계산 -> 상수시간 비교 -> 불일치시 즉시 실패(복호 금지)
 *   포맷:    header | nonce(16B) | ct | tag(16/32B)
 */
AESStatus CRACK_AES_seal_CTR(CRACK_AES_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,   // [PLAN] header(AAD)
                        const uint8_t* nonce16,               // [PLAN] 16B, 재사용 금지
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out);

AESStatus CRACK_AES_open_CTR(CRACK_AES_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out);

/* == EtM Helper: CBC (SHA-512 태그) =======================================
 * [PLAN]  CRACK_AES-보안형 CBC 경로(패딩 필요, SHA-512)
 *   암호화:  ct = AES-CBC(Kenc, iv16, pad(pt))
 *           tag = HMAC-SHA-512(Kmac, AAD || nonce16 || iv16 || ct) -> 16/32B 절단
 *   복호화:  태그 검증 성공 후 복호/패딩 제거
 */
AESStatus CRACK_AES_seal_CBC(CRACK_AES_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                        AESPadding padding,
                        uint8_t* tag, size_t tag_cap, size_t* tag_len_out);

AESStatus CRACK_AES_open_CBC(CRACK_AES_SecCtx* s,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* nonce16,
                        const uint8_t* iv16,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len_in,
                        AESPadding padding,
                        uint8_t* pt, size_t pt_cap, size_t* pt_len_out);

/* == 자동 nonce/IV 버전(편의/Fail-fast) ===================================
 * [PLAN]  “nonce/iv 자동 생성 버전 제공” 제안
 * [MAP]   내부에서 CRACK_AES_rand_bytes로 안전 생성 -> out_nonce/out_iv 반환.
 *         실사용 실수(재사용)를 줄이기 위한 래퍼. 포맷은 동일.
 */
AESStatus CRACK_AES_seal_CTR_autoIV(CRACK_AES_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               uint8_t out_nonce16[16],           // 생성·반환
                               const uint8_t* pt, size_t pt_len,
                               uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                               uint8_t* tag, size_t tag_cap, size_t* tag_len_out);

AESStatus CRACK_AES_open_CTR_autoIV(CRACK_AES_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t in_nonce16[16],
                               const uint8_t* ct, size_t ct_len,
                               const uint8_t* tag, size_t tag_len_in,
                               uint8_t* pt, size_t pt_cap, size_t* pt_len_out);

AESStatus CRACK_AES_seal_CBC_autoIV(CRACK_AES_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               uint8_t out_nonce16[16],
                               uint8_t out_iv16[16],
                               const uint8_t* pt, size_t pt_len,
                               uint8_t* ct, size_t ct_cap, size_t* ct_len_out,
                               AESPadding padding,
                               uint8_t* tag, size_t tag_cap, size_t* tag_len_out);

AESStatus CRACK_AES_open_CBC_autoIV(CRACK_AES_SecCtx* s,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t in_nonce16[16],
                               const uint8_t in_iv16[16],
                               const uint8_t* ct, size_t ct_len,
                               const uint8_t* tag, size_t tag_len_in,
                               AESPadding padding,
                               uint8_t* pt, size_t pt_cap, size_t* pt_len_out);

/* == 라이브러리 정보/자가진단 =============================================
 * [PLAN]  selftest(KAT) 훅
 * [MAP]   CRACK_AES_selftest() 제공(NIST/RFC 벡터 기반). libinfo는 기능비트/버전 조회.
 */
typedef struct {
    int      version;     // 내부 버전(예: 0x00010000)
    uint32_t features;    // 미래 확장(EtM/CCM/GCM 지원비트 등)
} CRACK_AES_LibraryInfo;

const CRACK_AES_LibraryInfo* CRACK_AES_libinfo(void);
AESStatus CRACK_AES_selftest(void);

/* == 태그 길이 경계 =======================================================
 * [PLAN]  태그 길이 16/32 운용
 * [MAP]   상수 제공(빌드타임/런타임 검증에 사용 가능)
 */
#define CRACK_AES_TAGLEN_MIN 16
#define CRACK_AES_TAGLEN_MAX 32

#endif /* CRACK_AES_SECURE_H */