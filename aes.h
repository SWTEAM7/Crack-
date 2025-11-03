#ifndef AES_H
#define AES_H

#include <stdint.h> // uint(고정 크기 정수 타입)쓰려고 사용
#include <stddef.h> // size_t(버퍼 길이)쓰려고

// ====== 키 길이 ======
typedef enum {
    AES128 = 16,
    AES192 = 24,
    AES256 = 32
} AESKeyLength;

// ====== 에러 코드 ======
typedef enum {
    AES_OK = 0,
    AES_ERR_BAD_PARAM     = -1,  // NULL, 잘못된 길이/값 등
    AES_ERR_BUF_SMALL     = -2,  // 출력 버퍼 부족
    AES_ERR_PADDING       = -3,  // 패딩 불일치/손상
    AES_ERR_OVERLAP       = -4,  // 금지된 메모리 구간 겹침
    AES_ERR_STATE         = -5,  // 초기화 안 됨/내부 상태 오류
    AES_ERR_LENGTH        = -6   // 블록 배수 제약 불만족 등
} AESStatus;

// ====== 패딩 ======
//  - PKCS#7: 가장 안전/표준. 마지막 바이트에 패딩 길이 N(1..16), 모두 N으로 채움.
//  - ANSI X9.23: 마지막 바이트 N, 나머지는 0x00. 길이 바이트로 구분 명확.
//  - ZERO 패딩: 0x00으로 채움. **데이터 말미 0과 구분 불가 → 금지.**
typedef enum {
    AES_PADDING_NONE = 0,
    AES_PADDING_PKCS7,
    AES_PADDING_ANSI_X923,
    AES_PADDING_ZERO_FORBIDDEN
} AESPadding;

// ====== 전방선언/함수 포인터 ======
struct AES_ctx;
typedef void (*AES_EncryptBlockFn)(struct AES_ctx* ctx,
                                   const uint8_t in[16],
                                   uint8_t out[16]);
typedef void (*AES_DecryptBlockFn)(struct AES_ctx* ctx,
                                   const uint8_t in[16],
                                   uint8_t out[16]);

// 에러 콜백: (code, message, user_data)
typedef void (*AES_ErrorCallback)(AESStatus, const char*, void*); //위에 등록해둔 에러들로 어떤 오류인지 알려줄 수 있게 하는 역할이란다

// ====== 컨텍스트 ======
typedef struct AES_ctx {
    uint32_t roundKeys[60];     // 최대 60워드(14라운드×4 + 여유)
    int      Nr;                // 10/12/14
    AES_EncryptBlockFn encrypt_block; // 함수 포인터 타입인데 주소 저장하는거 예시로 ctx.encrypt_block = AES_encryptBlock
    AES_DecryptBlockFn decrypt_block;

    // 에러 처리
    AESStatus          last_err;
    AES_ErrorCallback  on_error; // 선택
    void*              err_ud;   // 콜백 user data
} AES_ctx;

// ====== 공용 유틸 ======
const char* AES_strerror(AESStatus code);

// ====== 초기화/블록 ======
AESStatus AES_init(AES_ctx* ctx, const uint8_t* key, AESKeyLength keyLen);
void      AES_encryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]);
void      AES_decryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]);

// ====== 패딩 유틸 ======
AESStatus AES_applyPadding(const uint8_t* in, size_t in_len,
                           uint8_t* out, size_t out_cap,
                           AESPadding padding, size_t* out_len); // 붙이기

AESStatus AES_stripPadding(const uint8_t* in, size_t in_len,
                           AESPadding padding, size_t* out_plain_len); // 벗기기

// ====== 운용 모드 ======
// ⚠️ ECB 단점(실무 비권장):
//    - 동일 평문 블록 → 동일 암호문 블록 → 패턴 누설(이미지/레코드 반복이 그대로 보임).
//    - 문맥·무결성 보장 없음, 메시지 구조가 그대로 드러남.
//    - 교육/테스트 외 사용 금지 권장. 패딩 필요.
AESStatus AES_encryptECB(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         AESPadding padding);

AESStatus AES_decryptECB(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         AESPadding padding);

// CBC 단점:
//  1) 직렬 의존성 → 병렬화 어려움/지연 증가.
//  2) 패딩 필요 → 패딩 오라클 위험(프로토콜 부주의 시).
//  3) IV 재사용 시 정보 누설(동일 프리픽스 등).
//  4) 비트플립이 다음 블록 평문에 전파(무결성 미보장).
//  ⇒ 랜덤/유일 IV(16B) 필수, 상위에서 무결성(HMAC/AEAD) 필수.
AESStatus AES_encryptCBC(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         uint8_t iv[16], AESPadding padding);

AESStatus AES_decryptCBC(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         uint8_t iv[16], AESPadding padding);

// ✅ CTR 장점(주로 쓰는 이유):
//  - 스트림 동작 → **패딩 불필요**
//  - 블록 독립 → **완전 병렬화/랜덤액세스**
//  - 일부 수정/시킹 용이
//  주의: **nonce||counter 재사용 금지**(같은 키로 재사용 시 치명적 누설).
//        스트림 XOR라 **변조 용이성** → 반드시 MAC/AEAD(GCM)로 무결성 보강.
AESStatus AES_cryptCTR(AES_ctx* ctx,
                       const uint8_t* in, size_t len,
                       uint8_t* out,
                       uint8_t nonce_counter[16]); // in/out: 최종 값으로 업데이트


#endif /* AES_H */

