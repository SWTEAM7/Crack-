# Crack! 메시지 전송 보안 라이브러리 사용설명서

## 1. 개요

Crack! 라이브러리는 다음 두 가지 프로파일을 제공합니다.

- **AES1 (속도형)**: 순수 AES-ECB/CBC/CTR 구현. 빠른 암·복호화에 최적화.
- **CRACK_AES (보안형)**: AES + SHA-512 기반 HKDF/HMAC 을 결합한 보안 프로파일  
  - HKDF-SHA-512로 마스터 키에서 **암호화 키(Kenc)**와 **MAC 키(Kmac)** 분리 파생
  - AES-CTR / AES-CBC + HMAC-SHA-512 (Encrypt-then-MAC 구조)  
  - nonce/IV 재사용 가드 옵션 제공

- 지원 언어: **C99** (라이브러리 코어)
- 데모/예제: C17에서도 컴파일 가능
- 의존성: 표준 C 라이브러리, OS CSPRNG 
   (Windows BCryptGenRandom, macOS arc4random_buf, Linux /dev/urandom)

---

## 2. 빌드 및 통합 방법

### 2.1 디렉토리 구조 (예시)

```text
cracklib/
 ├─ include/
 │   ├─ aes.h
 │   ├─ crack_aes.h
 │   └─ sha512.h
 ├─ src/
 │   ├─ aes.c
 │   ├─ crack_aes.c
 │   └─ sha512.c
 ├─ examples/
 │   ├─ example_aes1_cbc.c
 │   ├─ example_aes1_ctr.c
 │   └─ example_crack_aes_ctr.c
 └─ README_cracklib_ko.md
```

### 2.2 정적 라이브러리 빌드 (Linux / macOS 예시)

```bash
clang -O3 -std=c99 -c src/aes.c src/crack_aes.c src/sha512.c
ar rcs libcrack.a aes.o crack_aes.o sha512.o
```

### 2.3 애플리케이션에서 사용 (Linux / macOS)

```bash
clang -O3 -std=c99 my_app.c -Iinclude -L. -lcrack -o my_app
```

헤더 포함:

```c
#include "aes.h"   // AES1 (속도형)
#include "crack_aes.h"  // CRACK_AES (보안형, 필요 시)
```

### 2.4 정적 라이브러리 빌드 (Windows / MSVC 예시)

```bat
cl /c /O2 /std:c17 /utf-8 src\aes.c src\crack_aes.c src\sha512.c /Iinclude
lib /OUT:crack.lib aes.obj crack_aes.obj sha512.obj
```

### 2.5 애플리케이션에서 사용 (Windows)

```bat
cl /O2 /std:c17 /utf-8 my_app.c /Iinclude crack.lib bcrypt.lib
```

헤더 포함:

```c
#include "aes.h"   // AES1 (속도형)
#include "crack_aes.h"  // CRACK_AES (보안형, 필요 시)
```
---

## 3. 공통 타입 및 에러 처리

### 3.1 키 길이

```c
typedef enum {
    AES128 = 16,
    AES192 = 24,
    AES256 = 32
} AESKeyLength;
```

### 3.2 에러 코드

```c
typedef enum {
    AES_OK = 0,
    AES_ERR_BAD_PARAM = -1,
    AES_ERR_BUF_SMALL = -2,
    AES_ERR_PADDING   = -3,
    AES_ERR_OVERLAP   = -4,
    AES_ERR_STATE     = -5,
    AES_ERR_LENGTH    = -6,
    AES_ERR_AUTH      = -7   /* CRACK_AES: MAC 인증 실패 */
} AESStatus;

const char* AES_strerror(AESStatus code);
```

모든 API 호출 후 반드시 반환값이 `AES_OK`인지 확인해야 합니다.
CRACK_AES 사용 시 AES_ERR_AUTH는 반드시 치명적 오류로 처리해야 하며,
복호화된 데이터는 사용해서는 안 됩니다.


---

## 4. AES1 (속도형) 사용법

### 4.1 컨텍스트 & 초기화

```c
typedef struct AES_ctx AES_ctx;

AESStatus AES_init(AES_ctx* ctx,
                   const uint8_t* key,
                   AESKeyLength keyLen);
```

- `ctx`는 스택/전역에 선언 후 `AES_init`으로 초기화합니다.
- 동일 키로 여러 번 재사용할 수 있습니다.

### 4.2 CBC 모드 예시 (PKCS#7 패딩)

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

void example_aes1_cbc(void) {
    const uint8_t key[16] = "0123456789abcdef";
    uint8_t iv[16] = {0}; /* 데모용: 실사용은 반드시 랜덤 IV */

    const char* msg = "Hello AES1 CBC!";
    size_t msg_len = strlen(msg);

    uint8_t ct[1024];
    uint8_t pt[1025]; /* +1 for '\0' */
    size_t ct_len = 0, pt_len = 0;

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, key, AES128);
    if (st != AES_OK) { fprintf(stderr, "AES_init 실패: %s\n", AES_strerror(st)); return; }

    uint8_t iv_enc[16]; memcpy(iv_enc, iv, 16);
    st = AES_encryptCBC(&ctx, (const uint8_t*)msg, msg_len,
                        ct, sizeof(ct), &ct_len,
                        iv_enc, AES_PADDING_PKCS7);
    if (st != AES_OK) { fprintf(stderr, "AES_encryptCBC 실패: %s\n", AES_strerror(st)); return; }

    uint8_t iv_dec[16]; memcpy(iv_dec, iv, 16);
    st = AES_decryptCBC(&ctx, ct, ct_len,
                        pt, sizeof(pt) - 1, &pt_len,
                        iv_dec, AES_PADDING_PKCS7);
    if (st != AES_OK) { fprintf(stderr, "AES_decryptCBC 실패: %s\n", AES_strerror(st)); return; }

    pt[pt_len] = '\0';
    printf("복호화 결과: %s\n", pt);
}
```

### 4.3 CTR 모드 예시 (패딩 없음)

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

void example_aes1_ctr(void) {
    const uint8_t key[16] = "0123456789abcdef";
    uint8_t nonce_counter[16] = {0}; 
    /* 데모용 고정 nonce: 실사용 시 반드시 랜덤/유일 nonce 사용 */


    const char* msg = "Hello AES1 CTR!";
    size_t len = strlen(msg);

    uint8_t ct[1024];
    uint8_t pt[1025]; /* +1 for '\0' */

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, key, AES128);
    if (st != AES_OK) { fprintf(stderr, "AES_init 실패: %s\n", AES_strerror(st)); return; }

    uint8_t nc_enc[16]; memcpy(nc_enc, nonce_counter, 16);
    st = AES_cryptCTR(&ctx, (const uint8_t*)msg, len, ct, nc_enc);
    if (st != AES_OK) { fprintf(stderr, "AES_cryptCTR 실패(암호화): %s\n", AES_strerror(st)); return; }

    uint8_t nc_dec[16]; memcpy(nc_dec, nonce_counter, 16);
    st = AES_cryptCTR(&ctx, ct, len, pt, nc_dec);
    if (st != AES_OK) { fprintf(stderr, "AES_cryptCTR 실패(복호화): %s\n", AES_strerror(st)); return; }

    pt[len] = '\0';
    printf("복호화 결과: %s\n", pt);
}
```

이 예시에서 송신 측은 nonce, ciphertext, tag를 함께 전송해야 하며,
수신 측은 동일한 AAD와 master_key를 사용하여 태그 검증 후 복호화를 수행합니다.

---

## 5. CRACK_AES (보안형) 사용법 – 설계 요약

CRACK_AES는 다음과 같은 보안 강화를 제공합니다.

1. **HKDF-SHA-512 키 분리**
   - 마스터 키 → Kenc(AES 암호화 키) / Kmac(MAC 키) 분리 파생
   - 라운드키가 노출되더라도 마스터 키로 역추적 불가 (비가역 KDF)

2. **Encrypt-then-MAC (EtM)**
   - AES-CTR 또는 AES-CBC 후 HMAC-SHA-512 적용
   - 기밀성 + 무결성 + 인증 동시 제공
   - 태그 검증 실패 시 `AES_ERR_AUTH` 반환

3. **Nonce/IV 재사용 가드 (옵션)**
   - `CRACK_AES_F_NONCE_GUARD` 플래그 사용 시, 동일 nonce/IV 재사용을 차단

### 5.1 주요 타입

```c
typedef enum {
    CRACK_AES_TagLen_16 = 16,
    CRACK_AES_TagLen_32 = 32
} CRACK_AES_TagLen;

typedef struct {
    const uint8_t* salt;
    size_t         salt_len;
    const uint8_t* info;
    size_t         info_len;
} CRACK_AES_KDFParams;

typedef enum {
    CRACK_AES_F_NONE        = 0,
    CRACK_AES_F_MAC_ENABLE  = 1 << 0,  /* EtM 사용 */
    CRACK_AES_F_NONCE_GUARD = 1 << 1   /* nonce/IV 재사용 차단 */
} CRACK_AES_Flags;

typedef struct {
    AES_ctx       aes;
    AESKeyLength  keylen;
    CRACK_AES_Flags    flags;

    uint8_t       mac_key[64];
    uint8_t       tag_len;

    uint8_t       last_nonce[16];
    uint8_t       last_iv[16];
    bool          last_nonce_set;
    bool          last_iv_set;
} CRACK_AES_SecCtx;
```

### 5.2 초기화 (마스터 키 → Kenc/Kmac 파생)

```c
AESStatus CRACK_AES_init_hardened(
    CRACK_AES_SecCtx* s,
    const uint8_t* master_key,
    AESKeyLength keyLen,
    const CRACK_AES_KDFParams* kdf,
    CRACK_AES_Flags flags,
    CRACK_AES_TagLen mac_tag_len);
```

예시:

```c
#include "crack_aes.h"

void example_crack_aes_init(CRACK_AES_SecCtx* sec) {
    uint8_t master_key[32] = {0};  /* 256-bit master key (예시) */
    uint8_t salt[16] = {0};        /* 세션 ID 또는 랜덤 값 */
    const uint8_t info[] = "CRACK_AES|session-v1";

    CRACK_AES_KDFParams kdf = {
        .salt = salt, .salt_len = sizeof(salt),
        .info = info, .info_len = sizeof(info) - 1
    };

    AESStatus st = CRACK_AES_init_hardened(sec,
                                      master_key, AES256,
                                      &kdf,
                                      CRACK_AES_F_MAC_ENABLE | CRACK_AES_F_NONCE_GUARD,
                                      CRACK_AES_TagLen_16);
    if (st != AES_OK) {
        /* 에러 처리 */
    }
}
```

---

## 6. CRACK_AES – CTR 보안형 예시 (내부 생성 nonce 반환)

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crack_aes.h"

void example_crack_aes_ctr(void) {
    CRACK_AES_SecCtx sec;

    /* 마스터 키 (256-bit 예시) */
    uint8_t master_key[32] = {0};

    /* KDF 파라미터 */
    uint8_t salt[16] = {0};
    const uint8_t info[] = "CRACK_AES|demo";

    CRACK_AES_KDFParams kdf = {
        salt, sizeof(salt),
        info, sizeof(info) - 1
    };

    /* 보안 컨텍스트 초기화 (EtM + nonce 재사용 가드 활성화) */
    AESStatus st = CRACK_AES_init_hardened(&sec,
                                           master_key, AES256,
                                           &kdf,
                                           CRACK_AES_F_MAC_ENABLE |
                                           CRACK_AES_F_NONCE_GUARD,
                                           CRACK_AES_TagLen_16);
    if (st != AES_OK) {
        fprintf(stderr, "CRACK_AES_init_hardened 실패: %d\n", st);
        return;
    }

    /* 추가 인증 데이터 (AAD) */
    const uint8_t aad[] = "header-v1";

    /* 평문 */
    const uint8_t pt[] = "Hello CRACK_AES CTR!";
    size_t pt_len = sizeof(pt) - 1;

    uint8_t nonce[16];
    uint8_t ct[1024];
    uint8_t tag[32];
    size_t ct_len = 0, tag_len = 0;

    /* 암호화 + 태그 생성 */
    st = CRACK_AES_seal_CTR_autoIV(&sec,
                                   aad, sizeof(aad) - 1,
                                   nonce,
                                   pt, pt_len,
                                   ct, sizeof(ct), &ct_len,
                                   tag, sizeof(tag), &tag_len);
    if (st != AES_OK) {
        fprintf(stderr, "CRACK_AES_seal_CTR_autoIV 실패: %d\n", st);
        return;
    }

    uint8_t dec[1024];
    size_t dec_len = 0;

    /* 복호화 + 태그 검증 */
    st = CRACK_AES_open_CTR_autoIV(&sec,
                                   aad, sizeof(aad) - 1,
                                   nonce,
                                   ct, ct_len,
                                   tag, tag_len,
                                   dec, sizeof(dec), &dec_len);
    if (st != AES_OK) {
        if (st == AES_ERR_AUTH)
            fprintf(stderr, "태그 불일치: 위변조 또는 키/nonce 오류\n");
        else
            fprintf(stderr, "CRACK_AES_open_CTR_autoIV 실패: %d\n", st);
        return;
    }

    /* 널 종료를 사용하지 않고 길이 기반으로 안전하게 출력 */
    printf("CRACK_AES 복호화 결과: \"%.*s\"\n",
           (int)dec_len, dec);
}
```

---

## 7. 사용 시 주의사항

1. **키 관리**
   - CRACK_AES에서는 `master_key`만 안전하게 보관하면 됩니다.
   - `Kenc`, `Kmac`, 라운드키가 노출되더라도 HKDF-SHA-512의 단방향성으로 인해 master_key를
      계산적으로 역추적하는 것은 현실적인 공격 모델에서 불가능합니다.

2. **nonce / IV**
   - CTR: 동일 `(key, nonce)` 조합은 절대 재사용 금지.
   - CBC: IV는 반드시 랜덤/유일해야 합니다.
   - 가능하면 `*_autoIV` API 사용을 권장합니다.

3. **버퍼 겹침**
   - 입력/출력 버퍼가 부분적으로 겹치면 `AES_ERR_OVERLAP`를 반환합니다.
   - 완전 동일 포인터(in-place)는 허용됩니다.

4. **무결성**
   - AES1은 기밀성만 제공 → 무결성이 필요한 경우 HMAC 등 별도 설계 필요.
   - CRACK_AES는 EtM 구조로 무결성을 내장하며, 태그 검증 실패 시 반드시 에러 처리해야 합니다.

---

이 문서는 Crack! 라이브러리를 사용하는 개발자를 위한 **사용자용 API 요약 및 샘플 코드**를 제공합니다.
