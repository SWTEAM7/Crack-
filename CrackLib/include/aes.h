/**
 * @file aes.h
 * @brief AES (Advanced Encryption Standard) 암호화 라이브러리 헤더
 * @details FIPS-197 표준을 따르는 AES-128/192/256 구현
 *          ECB, CBC, CTR 운용 모드 지원
 * @author AES 구현팀
 * @date 2025
 */

 #pragma execution_character_set("utf-8")

 #ifndef AES_H
 #define AES_H
 
 #include <stdint.h>  // 고정 크기 정수 타입 (uint8_t, uint32_t 등)
 #include <stddef.h>  // size_t 타입 (버퍼 길이 표현용)
 
 // ====== 키 길이 ======
 /**
  * @brief AES 키 길이 열거형
  * @details AES는 3가지 키 길이를 지원합니다:
  *          - AES128: 128비트 (16바이트) 키, 10라운드
  *          - AES192: 192비트 (24바이트) 키, 12라운드
  *          - AES256: 256비트 (32바이트) 키, 14라운드
  */
 typedef enum {
     AES128 = 16,  ///< 128비트 키 (16바이트)
     AES192 = 24,  ///< 192비트 키 (24바이트)
     AES256 = 32   ///< 256비트 키 (32바이트)
 } AESKeyLength;
 
 // ====== 에러 코드 ======
 /**
  * @brief AES 함수 반환 상태 코드
  * @details 모든 AES 함수는 AESStatus를 반환하여 성공/실패를 알립니다.
  *          AES_strerror() 함수로 에러 메시지를 얻을 수 있습니다.
  */
 typedef enum {
     AES_OK = 0,                    ///< 성공
     AES_ERR_BAD_PARAM     = -1,    ///< 잘못된 매개변수 (NULL 포인터, 잘못된 길이/값 등)
     AES_ERR_BUF_SMALL     = -2,    ///< 출력 버퍼 용량 부족
     AES_ERR_PADDING       = -3,    ///< 패딩 불일치/손상 (복호화 시 패딩 검증 실패)
     AES_ERR_OVERLAP       = -4,    ///< 금지된 메모리 구간 겹침 (입력/출력 버퍼 겹침)
     AES_ERR_STATE         = -5,    ///< 초기화 안 됨/내부 상태 오류
     AES_ERR_LENGTH        = -6     ///< 블록 배수 제약 불만족 (16바이트 배수가 아님)
 } AESStatus;
 
 // ====== 패딩 방식 ======
 /**
  * @brief 패딩(Padding) 방식 열거형
  * @details AES는 블록 암호이므로 입력 데이터가 16바이트의 배수여야 합니다.
  *          패딩은 데이터 길이를 16의 배수로 맞추기 위해 추가하는 바이트입니다.
  * 
  * 패딩 방식 설명:
  * - PKCS#7: 가장 안전하고 표준적인 방식. 마지막 바이트에 패딩 길이 N(1~16) 저장,
  *           나머지 패딩 바이트도 모두 N으로 채움. 예: "Hello" + 패딩 11바이트 = "Hello" + 0x0B 11개
  * - ANSI X9.23: 마지막 바이트에 패딩 길이 N 저장, 나머지는 0x00으로 채움.
  *               예: "Hello" + 0x00 10개 + 0x0B
  * - NONE: 패딩 없음. 입력 데이터 길이가 반드시 16의 배수여야 함.
  * - ZERO_FORBIDDEN: 사용 금지 (데이터 말미의 0과 구분 불가)
  */
 typedef enum {
     AES_PADDING_NONE = 0,           ///< 패딩 없음 (길이 16의 배수 필수)
     AES_PADDING_PKCS7,              ///< PKCS#7 패딩 (권장)
     AES_PADDING_ANSI_X923,          ///< ANSI X9.23 패딩
     AES_PADDING_ZERO_FORBIDDEN      ///< 사용 금지 (내부용)
 } AESPadding;
 
 // ====== 전방선언 및 함수 포인터 ======
 struct AES_ctx;  // AES 컨텍스트 구조체 전방선언
 
 /**
  * @brief 블록 암호화 함수 포인터 타입
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 평문 블록 (16바이트)
  * @param out 출력 암호문 블록 (16바이트)
  * @details 컨텍스트에 저장되어 실제 암호화 구현을 호출할 때 사용
  */
 typedef void (*AES_EncryptBlockFn)(struct AES_ctx* ctx,
                                    const uint8_t in[16],
                                    uint8_t out[16]);
 
 /**
  * @brief 블록 복호화 함수 포인터 타입
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 암호문 블록 (16바이트)
  * @param out 출력 평문 블록 (16바이트)
  * @details 컨텍스트에 저장되어 실제 복호화 구현을 호출할 때 사용
  */
 typedef void (*AES_DecryptBlockFn)(struct AES_ctx* ctx,
                                    const uint8_t in[16],
                                    uint8_t out[16]);
 
 /**
  * @brief 에러 콜백 함수 포인터 타입
  * @param code 에러 코드
  * @param msg 에러 메시지 문자열
  * @param user_data 사용자 정의 데이터 포인터
  * @details 에러 발생 시 호출되는 콜백 함수
  *          사용자가 에러 처리를 커스터마이징할 수 있음
  */
 typedef void (*AES_ErrorCallback)(AESStatus code, const char* msg, void* user_data);
 
 // ====== AES 컨텍스트 구조체 ======
 /**
  * @brief AES 암호화/복호화 컨텍스트
  * @details 모든 AES 연산에 필요한 상태 정보를 저장하는 구조체
  *          AES_init()으로 초기화한 후 사용해야 합니다.
  *          16바이트 정렬로 메모리 접근 최적화
  */
 #ifdef _MSC_VER
     typedef __declspec(align(16)) struct AES_ctx {
 #else
     typedef struct __attribute__((aligned(16))) AES_ctx {
 #endif
     uint32_t roundKeys[60];        ///< 라운드 키 배열 (최대 60워드 = AES-256의 14라운드×4워드 + 여유)
     int      Nr;                    ///< 라운드 수 (AES128=10, AES192=12, AES256=14)
     AES_EncryptBlockFn encrypt_block;  ///< 블록 암호화 함수 포인터 (예: AES_encryptBlock)
     AES_DecryptBlockFn decrypt_block;  ///< 블록 복호화 함수 포인터 (예: AES_decryptBlock)
 
     // 에러 처리 관련 필드
     AESStatus          last_err;    ///< 마지막 발생한 에러 코드
     AES_ErrorCallback  on_error;  ///< 에러 콜백 함수 포인터 (선택적, NULL 가능)
     void*              err_ud;      ///< 에러 콜백에 전달할 사용자 정의 데이터 포인터
 } AES_ctx;  // 16바이트 정렬로 메모리 접근 최적화
 
 // ====== 공용 유틸리티 함수 ======
 
 /**
  * @brief 에러 코드를 문자열로 변환
  * @param code AESStatus 에러 코드
  * @return 에러 메시지 문자열
  * @details 사용자에게 에러 메시지를 표시할 때 사용
  */
 const char* AES_strerror(AESStatus code);
 
 // ====== 초기화 및 블록 단위 암호화/복호화 ======
 
/**
 * @brief AES 컨텍스트 초기화
 * @param ctx AES 컨텍스트 포인터
 * @param key 암호화 키 (16/24/32 바이트)
 * @param keyLen 키 길이 (AES128/AES192/AES256)
 * @return AES_OK 성공, 그 외 에러 코드
 * @details 키 길이에 따른 라운드 수(Nr)를 명시적으로 설정하고,
 *          키 확장을 수행하여 컨텍스트를 초기화합니다.
 *          반드시 이 함수를 먼저 호출해야 합니다.
 * 
 * 설정되는 파라미터:
 * - ctx->Nr: 라운드 수 (AES128=10, AES192=12, AES256=14)
 * - ctx->roundKeys: 키 확장으로 생성된 라운드 키
 * - ctx->encrypt_block, ctx->decrypt_block: 블록 암호화/복호화 함수 포인터
 */
AESStatus AES_init(AES_ctx* ctx, const uint8_t* key, AESKeyLength keyLen);
 
 /**
  * @brief 단일 블록 암호화 (16바이트)
  * @param ctx AES 컨텍스트 포인터 (AES_init으로 초기화 필요)
  * @param in 입력 평문 블록 (16바이트)
  * @param out 출력 암호문 블록 (16바이트)
  */
 void AES_encryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]);
 
 /**
  * @brief 단일 블록 복호화 (16바이트)
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 암호문 블록 (16바이트)
  * @param out 출력 평문 블록 (16바이트)
  */
 void AES_decryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]);
 
 // ====== 패딩 유틸리티 함수 ======
 
 /**
  * @brief 패딩 적용 함수
  * @param in 입력 데이터 포인터
  * @param in_len 입력 데이터 길이 (바이트)
  * @param out 출력 버퍼 포인터
  * @param out_cap 출력 버퍼 용량 (바이트)
  * @param padding 패딩 방식
  * @param out_len 출력 데이터 길이 (바이트, 패딩 포함)
  * @return AES_OK 성공, 그 외 에러 코드
  */
 AESStatus AES_applyPadding(const uint8_t* in, size_t in_len,
                            uint8_t* out, size_t out_cap,
                            AESPadding padding, size_t* out_len);
 
 /**
  * @brief 패딩 제거 함수
  * @param in 입력 데이터 포인터 (패딩 포함)
  * @param in_len 입력 데이터 길이 (바이트, 16의 배수)
  * @param padding 패딩 방식
  * @param out_plain_len 출력 평문 길이 (바이트, 패딩 제외)
  * @return AES_OK 성공, 그 외 에러 코드
  */
 AESStatus AES_stripPadding(const uint8_t* in, size_t in_len,
                            AESPadding padding, size_t* out_plain_len);
 
 // ====== 운용 모드 (Mode of Operation) ======
 
 /**
  * @brief ECB 모드 암호화 (Electronic Codebook)
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 평문 포인터
  * @param in_len 입력 평문 길이 (바이트)
  * @param out 출력 버퍼 포인터
  * @param out_cap 출력 버퍼 용량 (바이트)
  * @param out_len 출력 암호문 길이 (바이트)
  * @param padding 패딩 방식
  * @return AES_OK 성공, 그 외 에러 코드
  * @warning ⚠️ ECB 모드는 실무에서 사용하지 않기를 강력히 권장합니다!
  *          - 동일한 평문 블록은 항상 동일한 암호문 블록을 생성 (패턴 누설)
  *          - 이미지나 반복적인 데이터에서 구조가 그대로 드러남
  *          - 문맥/무결성 보장 없음
  *          - 교육/테스트 목적으로만 사용 권장
  */
 AESStatus AES_encryptECB(AES_ctx* ctx,
                          const uint8_t* in, size_t in_len,
                          uint8_t* out, size_t out_cap, size_t* out_len,
                          AESPadding padding);
 
 /**
  * @brief ECB 모드 복호화
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 암호문 포인터
  * @param in_len 입력 암호문 길이 (바이트, 16의 배수)
  * @param out 출력 버퍼 포인터
  * @param out_cap 출력 버퍼 용량 (바이트)
  * @param out_len 출력 평문 길이 (바이트)
  * @param padding 패딩 방식
  * @return AES_OK 성공, 그 외 에러 코드
  */
 AESStatus AES_decryptECB(AES_ctx* ctx,
                          const uint8_t* in, size_t in_len,
                          uint8_t* out, size_t out_cap, size_t* out_len,
                          AESPadding padding);
 
 /**
  * @brief CBC 모드 암호화 (Cipher Block Chaining)
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 평문 포인터
  * @param in_len 입력 평문 길이 (바이트)
  * @param out 출력 버퍼 포인터
  * @param out_cap 출력 버퍼 용량 (바이트)
  * @param out_len 출력 암호문 길이 (바이트)
  * @param iv 초기화 벡터 (16바이트, 입력/출력: 암호화 후 마지막 암호문 블록으로 업데이트됨)
  * @param padding 패딩 방식
  * @return AES_OK 성공, 그 외 에러 코드
  * @details 
  * CBC 모드 특징:
  * - 각 블록을 이전 블록의 암호문과 XOR한 후 암호화 (체인 방식)
  * - 첫 번째 블록은 IV와 XOR
  * - 장점: 동일한 평문 블록도 다른 암호문 생성 (ECB 문제 해결)
  * - 단점: 
  *   * 직렬 의존성 (병렬화 어려움)
  *   * 패딩 필요 -> 패딩 오라클 공격 위험
  *   * IV 재사용 시 정보 누설
  *   * 비트플립이 다음 블록 평문에 전파 (무결성 미보장)
  * - 주의: IV는 매번 랜덤하게 생성되어야 함! 상위에서 무결성(HMAC/AEAD) 필수
  */
 AESStatus AES_encryptCBC(AES_ctx* ctx,
                          const uint8_t* in, size_t in_len,
                          uint8_t* out, size_t out_cap, size_t* out_len,
                          uint8_t iv[16], AESPadding padding);
 
 /**
  * @brief CBC 모드 복호화
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 암호문 포인터
  * @param in_len 입력 암호문 길이 (바이트, 16의 배수)
  * @param out 출력 버퍼 포인터
  * @param out_cap 출력 버퍼 용량 (바이트)
  * @param out_len 출력 평문 길이 (바이트)
  * @param iv 초기화 벡터 (16바이트, 입력/출력: 복호화 후 입력 마지막 암호문 블록으로 업데이트됨)
  * @param padding 패딩 방식
  * @return AES_OK 성공, 그 외 에러 코드
  */
 AESStatus AES_decryptCBC(AES_ctx* ctx,
                          const uint8_t* in, size_t in_len,
                          uint8_t* out, size_t out_cap, size_t* out_len,
                          uint8_t iv[16], AESPadding padding);
 
 /**
  * @brief CTR 모드 암호화/복호화 (Counter)
  * @param ctx AES 컨텍스트 포인터
  * @param in 입력 데이터 포인터
  * @param len 입력 데이터 길이 (바이트, 16의 배수일 필요 없음)
  * @param out 출력 버퍼 포인터 (입력과 같을 수 있음, in-place 가능)
  * @param nonce_counter nonce+카운터 (16바이트, 입력/출력: 암호화 후 최종 값으로 업데이트됨)
  * @return AES_OK 성공, 그 외 에러 코드
  * @details 
  * ✅ CTR 모드의 장점:
  * - 스트림 암호처럼 동작 (패딩 불필요!)
  * - 블록 독립성 (병렬화 가능, 랜덤 액세스 가능)
  * - 암호화와 복호화가 동일한 함수 (구현 간단)
  * - 일부 데이터 수정/시킹(seeking) 용이
  * 
  * ⚠️ 주의사항:
  * - nonce+카운터 재사용 금지! (같은 키로 재사용 시 치명적 정보 누설)
  * - 스트림 XOR 방식이라 변조가 쉬움 -> 반드시 MAC/AEAD(GCM)로 무결성 보강 필요
  */
 AESStatus AES_cryptCTR(AES_ctx* ctx,
                        const uint8_t* in, size_t len,
                        uint8_t* out,
                        uint8_t nonce_counter[16]);
 
 
 #endif /* AES_H */
 
 