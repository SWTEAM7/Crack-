/* =========================================================================
 * test.c — AES1(속도형) vs AES2(보안형) 인터랙티브 데모 + 10MiB 벤치마크
 *
 * 기능:
 *   - 사용자 평문 입력
 *   - [1] AES1 속도형: CTR / ECB / CBC 모드 선택 데모
 *   - [2] AES2 보안형: CTR + HKDF-SHA-512 + HMAC-SHA-512 (EtM)
 *   - CTR 모드에 대해 10MiB 암호화 시간 및 처리량(MB/s) 측정
 * 
 * 빌드:
 *   Windows: cl /utf-8 /std:c17 /O2 /W4 /D_CRT_SECURE_NO_WARNINGS test.c aes.c aes2.c sha512.c
 *   Linux/Mac: gcc -O2 -std=c17 -Wall test1.c aes.c aes2.c sha512.c -o test
 * ========================================================================= */

/* 표준 C 라이브러리 헤더 */
#include <stdio.h>    /* 표준 입출력 함수 (printf, fgets 등) */
#include <stdint.h>   /* 고정 크기 정수 타입 (uint8_t, uint32_t 등) */
#include <string.h>   /* 문자열 처리 함수 (memcpy, memset, strlen 등) */
#include <stdlib.h>   /* 표준 라이브러리 함수 (malloc, free, atoi 등) */
#include <time.h>     /* 시간 관련 함수 (clock, CLOCKS_PER_SEC 등) */

/* 프로젝트 암호화 라이브러리 헤더 */
#include "aes.h"      /* AES1 (속도형) 암호화 함수 */
#include "aes2.h"     /* AES2 (보안형) 암호화 함수 */
#include "sha512.h"   /* SHA-512 해시 함수 (HMAC, HKDF에 사용) */

/* Windows 플랫폼 전용 헤더 */
#if defined(_WIN32)
  #include <windows.h>  /* Windows API (SetConsoleOutputCP 등) */
  #include <locale.h>   /* 로케일 설정 함수 (setlocale) */
#endif

/* 벤치마크용 데이터 크기: 10 MiB (10 * 1024 * 1024 바이트) */
#define BENCH_SIZE (10u * 1024u * 1024u) /* 10 MiB */

/**
 * 16진수 형태로 바이너리 데이터를 출력하는 유틸리티 함수
 * 
 * @param label 출력할 데이터의 레이블 (예: "ciphertext", "nonce")
 * @param buf 출력할 바이너리 데이터 버퍼
 * @param len 출력할 데이터의 길이 (바이트 단위)
 * 
 * 예시 출력: "ciphertext (32 bytes): 0123456789ABCDEF..."
 */
static void print_hex(const char* label, const uint8_t* buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    /* 각 바이트를 2자리 16진수(대문자)로 출력 */
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

/**
 * AES 상태 코드를 사람이 읽을 수 있는 문자열로 변환하는 함수
 * 
 * @param st AESStatus 열거형 값
 * @return 해당 상태 코드의 설명 문자열
 * 
 * 디버깅 및 오류 메시지 출력에 사용됩니다.
 */
static const char* aes_status_str(AESStatus st) {
    switch (st) {
    case AES_OK:            return "AES_OK";              /* 성공 */
    case AES_ERR_BAD_PARAM: return "AES_ERR_BAD_PARAM";  /* 잘못된 매개변수 */
    case AES_ERR_BUF_SMALL: return "AES_ERR_BUF_SMALL";  /* 버퍼 크기 부족 */
    case AES_ERR_PADDING:   return "AES_ERR_PADDING";    /* 패딩 오류 */
    case AES_ERR_OVERLAP:   return "AES_ERR_OVERLAP";    /* 버퍼 겹침 오류 */
    case AES_ERR_STATE:     return "AES_ERR_STATE";      /* 잘못된 상태 */
    case AES_ERR_LENGTH:    return "AES_ERR_LENGTH";     /* 길이 오류 */
#ifdef AES_ERR_AUTH
    case AES_ERR_AUTH:      return "AES_ERR_AUTH";       /* 인증 실패 (HMAC 검증 실패 등) */
#endif
    default:                return "AES_ERR_UNKNOWN";    /* 알 수 없는 오류 */
    }
}

/**
 * 현재 시간을 초 단위로 반환하는 함수
 * 
 * @return 프로그램 시작 이후 경과된 시간 (초 단위, double)
 * 
 * 벤치마크 성능 측정에 사용됩니다.
 * clock() 함수는 CPU 시간을 측정하므로 멀티스레드 환경에서는 주의가 필요합니다.
 */
static double now_seconds(void) {
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

/**
 * 공통 데모용 키 (AES-256)
 * 
 * ⚠️ 보안 경고:
 * 이 키는 데모 및 테스트 목적으로만 사용됩니다.
 * 실제 프로덕션 환경에서는 절대 사용하지 마세요!
 * 
 * 실제 사용 시:
 * - 암호학적으로 안전한 난수 생성기(CSPRNG)로 키를 생성해야 합니다.
 * - 키는 안전하게 보관하고 관리해야 합니다 (키 관리 시스템 사용 권장).
 * - 키 노출 시 즉시 키를 교체해야 합니다.
 * 
 * 키 크기: 32바이트 (256비트) - AES-256에 사용
 */
static const uint8_t DEMO_KEY256[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

/* --------------------------------------------------------------------------
 * AES1 — CTR 데모 + 10MiB 벤치마크
 * -------------------------------------------------------------------------- */

/**
 * AES1 CTR 모드 데모 및 10MiB 벤치마크 함수
 * 
 * CTR(Counter) 모드는 스트림 암호처럼 동작하는 블록 암호 운용 모드입니다.
 * - 장점: 병렬 처리 가능, 임의 접근 가능, 패딩 불필요
 * - 단점: nonce 재사용 시 보안 위험 (같은 nonce로 같은 키 사용 금지)
 * 
 * @param msg 암호화할 평문 데이터
 * @param msg_len 평문 데이터의 길이 (바이트)
 * 
 * 수행 작업:
 * 1. AES-256 컨텍스트 초기화
 * 2. CTR 모드로 평문 암호화
 * 3. CTR 모드로 암호문 복호화 (검증)
 * 4. 10MiB 데이터로 성능 벤치마크 수행
 */
static void aes1_ctr_demo_and_bench(const uint8_t* msg, size_t msg_len) {
    printf("\n========================================\n");
    printf(" [AES1] CTR 모드 데모 + 10MiB 벤치마크\n");
    printf("========================================\n");

    /* AES-256 컨텍스트 초기화 */
    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[AES1-CTR] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 1) 평문 암호화 (CTR) */
    /* 
     * 주의: 데모용으로 nonce를 0으로 고정했습니다.
     * 실제 사용 시에는 매번 고유한 랜덤 nonce를 사용해야 합니다.
     * 같은 nonce를 같은 키로 재사용하면 보안이 깨집니다!
     */
    uint8_t nonce[16] = {0}; /* 데모용: 고정 nonce (실사용에서는 랜덤/유일 값 필요) */
    uint8_t ct[2048];  /* 암호문 저장 버퍼 */
    
    /* 입력 크기 검증 */
    if (msg_len > sizeof(ct)) {
        printf("[AES1-CTR] 평문이 데모 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    /* CTR 카운터 초기화 (nonce 복사) */
    uint8_t ctr[16];
    memcpy(ctr, nonce, 16);

    /* CTR 모드로 암호화 수행 */
    /* CTR 모드는 암호화와 복호화가 동일한 함수로 수행됩니다 */
    st = AES_cryptCTR(&ctx, msg, msg_len, ct, ctr);
    if (st != AES_OK) {
        printf("[AES1-CTR] AES_cryptCTR 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 결과 출력 */
    print_hex("[AES1-CTR] nonce", nonce, 16);
    print_hex("[AES1-CTR] ciphertext", ct, msg_len);

    /* 2) 복호화 (CTR) */
    /* CTR 모드는 대칭적이므로 암호화 함수를 다시 호출하면 복호화됩니다 */
    uint8_t dec[2048];  /* 복호화된 평문 저장 버퍼 */
    uint8_t ctr2[16];   /* 복호화용 CTR 카운터 (nonce로 초기화) */
    memcpy(ctr2, nonce, 16);  /* 같은 nonce를 사용해야 올바르게 복호화됩니다 */
    
    st = AES_cryptCTR(&ctx, ct, msg_len, dec, ctr2);
    if (st != AES_OK) {
        printf("[AES1-CTR] 복호화 실패: %s\n", aes_status_str(st));
        return;
    }
    printf("[AES1-CTR] 복호화 결과: \"%.*s\"\n", (int)msg_len, dec);

    /* 3) 10MiB 벤치마크 */
    /* 대용량 데이터 암호화 성능을 측정하여 처리량(MB/s)을 계산합니다 */
    printf("\n[AES1-CTR] 10MiB 암호화 성능 측정 중...\n");

    /* 벤치마크용 버퍼 할당 (10MiB = 10 * 1024 * 1024 바이트) */
    uint8_t* bench_pt = (uint8_t*)malloc(BENCH_SIZE);  /* 평문 버퍼 */
    uint8_t* bench_ct = (uint8_t*)malloc(BENCH_SIZE);  /* 암호문 버퍼 */
    if (!bench_pt || !bench_ct) {
        printf("[AES1-CTR] 10MiB 버퍼 할당 실패.\n");
        free(bench_pt);
        free(bench_ct);
        return;
    }

    /* 벤치마크용 평문 생성: 입력 메시지를 반복하여 10MiB 채우기 */
    for (size_t i = 0; i < BENCH_SIZE; i++) {
        bench_pt[i] = msg[i % msg_len];  /* 입력 메시지를 순환하여 채움 */
    }

    /* 벤치마크용 nonce 및 CTR 카운터 초기화 */
    uint8_t bench_nonce[16] = {0};
    uint8_t bench_ctr[16];
    memcpy(bench_ctr, bench_nonce, 16);

    /* 성능 측정 시작 */
    double t0 = now_seconds();
    /* 10MiB 데이터를 CTR 모드로 암호화 */
    st = AES_cryptCTR(&ctx, bench_pt, BENCH_SIZE, bench_ct, bench_ctr);
    double t1 = now_seconds();  /* 성능 측정 종료 */

    /* 메모리 해제 */
    free(bench_pt);
    free(bench_ct);

    if (st != AES_OK) {
        printf("[AES1-CTR] 10MiB 암호화 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 처리량 계산 */
    double elapsed = t1 - t0;  /* 경과 시간 (초) */
    if (elapsed <= 0.0) elapsed = 1e-9;  /* 0으로 나누기 방지 */
    double mb = (double)BENCH_SIZE / (1024.0 * 1024.0);  /* 데이터 크기를 MB로 변환 */
    double mbps = mb / elapsed;  /* 초당 처리량 (MB/s) */

    /* 결과 출력 */
    printf("[AES1-CTR] 10MiB 암호화 시간: %.4f 초\n", elapsed);
    printf("[AES1-CTR] 처리량: %.2f MB/s\n", mbps);
}

/* --------------------------------------------------------------------------
 * 패딩 선택 헬퍼 함수
 * -------------------------------------------------------------------------- */

/**
 * 패딩 타입을 사람이 읽을 수 있는 문자열로 변환하는 함수
 * 
 * @param pad AESPadding 열거형 값
 * @return 패딩 타입의 설명 문자열
 */
static const char* padding_name(AESPadding pad) {
    switch (pad) {
    case AES_PADDING_NONE:      return "NONE (16바이트 배수 필수)";  /* 패딩 없음 */
    case AES_PADDING_PKCS7:     return "PKCS#7";                     /* 표준 PKCS#7 패딩 */
    case AES_PADDING_ANSI_X923: return "ANSI X9.23";                 /* ANSI X9.23 패딩 */
    default:                    return "UNKNOWN";                    /* 알 수 없는 패딩 */
    }
}

/**
 * 사용자로부터 패딩 방식을 선택받는 함수
 * 
 * @return 선택된 AESPadding 값
 * 
 * 패딩 설명:
 * - PKCS#7: 가장 널리 사용되는 표준 패딩 방식 (권장)
 * - ANSI X9.23: 마지막 바이트만 패딩 길이, 나머지는 0으로 채움
 * - NONE: 패딩 없음 (입력이 반드시 16바이트 배수여야 함)
 */
static AESPadding select_padding(void) {
    printf("\n패딩 방식을 선택하세요:\n");
    printf("  [1] PKCS#7 (권장, 표준)\n");
    printf("  [2] ANSI X9.23\n");
    printf("  [3] NONE (입력이 16바이트 배수일 때만)\n");
    printf("선택: ");
    fflush(stdout);  /* 출력 버퍼 강제 플러시 (프롬프트 즉시 표시) */

    char buf[16];  /* 사용자 입력 버퍼 */
    if (!fgets(buf, sizeof(buf), stdin)) {
        printf("입력 오류. 기본값 PKCS#7을 사용합니다.\n");
        return AES_PADDING_PKCS7;  /* 입력 실패 시 기본값 반환 */
    }

    /* 문자열을 정수로 변환하여 선택값 확인 */
    int choice = atoi(buf);
    switch (choice) {
    case 1:  return AES_PADDING_PKCS7;      /* PKCS#7 선택 */
    case 2:  return AES_PADDING_ANSI_X923;  /* ANSI X9.23 선택 */
    case 3:  return AES_PADDING_NONE;        /* 패딩 없음 선택 */
    default:
        printf("잘못된 선택. 기본값 PKCS#7 사용.\n");
        return AES_PADDING_PKCS7;  /* 잘못된 입력 시 기본값 반환 */
    }
}

/* --------------------------------------------------------------------------
 * AES1 — ECB 데모 (교육/테스트용, 패딩 선택 가능)
 * -------------------------------------------------------------------------- */

/**
 * AES1 ECB 모드 데모 함수
 * 
 * ECB(Electronic Codebook) 모드는 가장 단순한 블록 암호 운용 모드입니다.
 * 
 * ⚠️ 보안 경고:
 * - ECB 모드는 실제 프로덕션 환경에서 사용하면 안 됩니다!
 * - 같은 평문 블록은 항상 같은 암호문 블록으로 변환됩니다.
 * - 패턴이 노출되어 보안이 취약합니다.
 * - 이 함수는 교육 및 테스트 목적으로만 제공됩니다.
 * 
 * @param msg 암호화할 평문 데이터
 * @param msg_len 평문 데이터의 길이 (바이트)
 * 
 * 수행 작업:
 * 1. 사용자로부터 패딩 방식 선택
 * 2. ECB 모드로 평문 암호화
 * 3. ECB 모드로 암호문 복호화 (검증)
 */
static void aes1_ecb_demo(const uint8_t* msg, size_t msg_len) {
    printf("\n========================================\n");
    printf(" [AES1] ECB 모드 데모 (교육/테스트용)\n");
    printf("========================================\n");

    /* 사용자로부터 패딩 방식 선택 */
    AESPadding padding = select_padding();
    printf("[AES1-ECB] 선택된 패딩: %s\n", padding_name(padding));

    /* NONE 패딩 선택 시 입력 크기 검증 */
    /* AES 블록 크기는 16바이트이므로, NONE 패딩을 사용하려면 입력이 16바이트 배수여야 합니다 */
    if (padding == AES_PADDING_NONE && (msg_len % 16) != 0) {
        printf("[AES1-ECB] 오류: NONE 패딩은 입력이 16바이트 배수여야 합니다. (현재 %zu바이트)\n", msg_len);
        return;
    }

    /* AES-256 컨텍스트 초기화 */
    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[AES1-ECB] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 암호문 및 복호화 결과 저장 버퍼 */
    uint8_t ct[2048];   /* 암호문 버퍼 */
    uint8_t dec[2048];  /* 복호화된 평문 버퍼 */
    size_t ct_len = 0, dec_len = 0;  /* 실제 데이터 길이 */

    /* 입력 크기 검증 */
    if (msg_len > sizeof(ct)) {
        printf("[AES1-ECB] 평문이 데모 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    /* 1) 암호화 */
    /* ECB 모드는 각 16바이트 블록을 독립적으로 암호화합니다 */
    st = AES_encryptECB(&ctx,
                        msg, msg_len,           /* 입력: 평문 */
                        ct, sizeof(ct), &ct_len, /* 출력: 암호문 버퍼 및 길이 */
                        padding);                /* 패딩 방식 */
    if (st != AES_OK) {
        printf("[AES1-ECB] AES_encryptECB 실패: %s\n", aes_status_str(st));
        return;
    }

    print_hex("[AES1-ECB] ciphertext", ct, ct_len);

    /* 2) 복호화 */
    /* ECB 모드로 암호문을 복호화하여 원본 평문을 복원합니다 */
    st = AES_decryptECB(&ctx,
                        ct, ct_len,                /* 입력: 암호문 */
                        dec, sizeof(dec), &dec_len, /* 출력: 복호화된 평문 버퍼 및 길이 */
                        padding);                   /* 패딩 방식 (암호화와 동일해야 함) */
    if (st != AES_OK) {
        printf("[AES1-ECB] AES_decryptECB 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES1-ECB] 복호화 결과: \"%.*s\"\n", (int)dec_len, dec);
}

/* --------------------------------------------------------------------------
 * AES1 — CBC 데모 (랜덤 IV + 패딩 선택 가능)
 * -------------------------------------------------------------------------- */

/**
 * AES1 CBC 모드 데모 함수
 * 
 * CBC(Cipher Block Chaining) 모드는 이전 블록의 암호문을 다음 블록 암호화에 사용하는 모드입니다.
 * 
 * 특징:
 * - 각 블록이 이전 블록의 암호문과 XOR되어 암호화됩니다.
 * - 첫 번째 블록은 IV(Initialization Vector)와 XOR됩니다.
 * - 패딩이 필요합니다 (블록 크기의 배수가 아닌 경우).
 * - IV는 매번 고유한 랜덤 값이어야 합니다 (보안상 중요).
 * 
 * @param msg 암호화할 평문 데이터
 * @param msg_len 평문 데이터의 길이 (바이트)
 * 
 * 수행 작업:
 * 1. 사용자로부터 패딩 방식 선택
 * 2. 랜덤 IV 생성
 * 3. CBC 모드로 평문 암호화
 * 4. CBC 모드로 암호문 복호화 (검증)
 */
static void aes1_cbc_demo(const uint8_t* msg, size_t msg_len) {
    printf("\n========================================\n");
    printf(" [AES1] CBC 모드 데모 (랜덤 IV + 패딩)\n");
    printf("========================================\n");

    /* 사용자로부터 패딩 방식 선택 */
    AESPadding padding = select_padding();
    printf("[AES1-CBC] 선택된 패딩: %s\n", padding_name(padding));

    /* AES-256 컨텍스트 초기화 */
    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[AES1-CBC] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 암호문 및 복호화 결과 저장 버퍼 */
    uint8_t ct[2048];   /* 암호문 버퍼 */
    uint8_t dec[2048];  /* 복호화된 평문 버퍼 */
    size_t ct_len = 0, dec_len = 0;  /* 실제 데이터 길이 */

    /* 입력 크기 검증 */
    if (msg_len > sizeof(ct)) {
        printf("[AES1-CBC] 평문이 데모 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    /* IV(Initialization Vector) 생성 */
    /* IV는 16바이트이며, 매번 고유한 랜덤 값이어야 합니다 */
    uint8_t iv_enc[16];  /* 암호화용 IV */
    uint8_t iv_dec[16];  /* 복호화용 IV (암호화와 동일한 값 사용) */

    /* CSPRNG(Cryptographically Secure Pseudorandom Number Generator)로 랜덤 IV 생성 */
    /* 실패 시 0으로 초기화 (데모용, 실제 사용 시에는 반드시 랜덤 IV 필요) */
    if (AES2_rand_bytes(iv_enc, sizeof(iv_enc)) != AES_OK) {
        memset(iv_enc, 0, sizeof(iv_enc)); /* 실패 시 0으로 (데모용) */
    }
    memcpy(iv_dec, iv_enc, sizeof(iv_enc));  /* 복호화 시 같은 IV 사용 */

    /* 1) 암호화 */
    /* CBC 모드는 IV와 함께 암호화를 수행합니다 */
    st = AES_encryptCBC(&ctx,
                        msg, msg_len,           /* 입력: 평문 */
                        ct, sizeof(ct), &ct_len, /* 출력: 암호문 버퍼 및 길이 */
                        iv_enc,                  /* 초기화 벡터 (IV) */
                        padding);                /* 패딩 방식 */
    if (st != AES_OK) {
        printf("[AES1-CBC] AES_encryptCBC 실패: %s\n", aes_status_str(st));
        return;
    }

    print_hex("[AES1-CBC] IV", iv_dec, 16);
    print_hex("[AES1-CBC] ciphertext", ct, ct_len);

    /* 2) 복호화 */
    /* CBC 모드로 암호문을 복호화합니다. 복호화 시에도 같은 IV를 사용해야 합니다 */
    st = AES_decryptCBC(&ctx,
                        ct, ct_len,                /* 입력: 암호문 */
                        dec, sizeof(dec), &dec_len, /* 출력: 복호화된 평문 버퍼 및 길이 */
                        iv_dec,                     /* 초기화 벡터 (암호화와 동일) */
                        padding);                   /* 패딩 방식 (암호화와 동일해야 함) */
    if (st != AES_OK) {
        printf("[AES1-CBC] AES_decryptCBC 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES1-CBC] 복호화 결과: \"%.*s\"\n", (int)dec_len, dec);
}

/* --------------------------------------------------------------------------
 * AES2(보안형) — CTR + HKDF + HMAC 데모 + 10MiB 벤치마크
 * -------------------------------------------------------------------------- */

/**
 * AES2 보안형 프로파일 데모 및 벤치마크 함수
 * 
 * AES2는 AES1보다 보안이 강화된 프로파일로, 다음 기능을 제공합니다:
 * - CTR 모드: 스트림 암호처럼 동작
 * - HKDF-SHA-512: 키 파생 함수로 마스터 키에서 암호화 키와 MAC 키를 파생
 * - HMAC-SHA-512: 메시지 인증 코드로 무결성 검증 (EtM: Encrypt-then-MAC)
 * - Nonce Guard: nonce 재사용 방지
 * 
 * 보안 특징:
 * - 암호화와 인증을 모두 제공 (AEAD: Authenticated Encryption with Associated Data)
 * - 변조 탐지: 암호문이 변경되면 복호화 시 오류 발생
 * - AAD(Additional Authenticated Data) 지원: 암호화하지 않고 인증만 하는 데이터
 * 
 * @param msg 암호화할 평문 데이터
 * @param msg_len 평문 데이터의 길이 (바이트)
 * 
 * 수행 작업:
 * 1. 마스터 키 및 KDF 파라미터 설정
 * 2. AES2 보안 컨텍스트 초기화
 * 3. CTR + HMAC으로 평문 암호화
 * 4. 복호화 및 태그 검증
 * 5. 변조 탐지 데모 (선택적)
 * 6. 10MiB 데이터로 성능 벤치마크 수행
 */
static void run_aes2_demo(const uint8_t* msg, size_t msg_len) {
    printf("\n=================================================\n");
    printf(" [AES2] 보안형 프로파일 — CTR + HKDF + HMAC 데모\n");
    printf("=================================================\n");

    /* 1) 마스터 키 / KDF 파라미터 (AES-256, 태그 32바이트) */
    /* 
     * 마스터 키: 실제 사용 시에는 안전하게 생성하고 보관해야 합니다.
     * HKDF를 통해 이 마스터 키에서 암호화 키와 MAC 키를 파생합니다.
     */
    static const uint8_t master_key[32] = {  /* AES-256 키 (32바이트) */
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    
    /* HKDF 파라미터 */
    /* salt: 키 파생에 사용되는 솔트 (고유한 값 권장) */
    static const uint8_t salt[] = "AES2-demo-salt";
    /* info: 키 파생에 사용되는 컨텍스트 정보 (애플리케이션별로 구분) */
    static const uint8_t info[] = "AES2-demo-info";

    /* KDF 파라미터 구조체 초기화 */
    AES2_KDFParams kdf = {
        salt, sizeof(salt) - 1,  /* salt 포인터 및 길이 (널 종료 문자 제외) */
        info, sizeof(info) - 1   /* info 포인터 및 길이 (널 종료 문자 제외) */
    };

    /* AES2 보안 컨텍스트 초기화 */
    AES2_SecCtx ctx;
    AESStatus st = AES2_init_hardened(&ctx,
                                      master_key, AES256,  /* 마스터 키 및 키 크기 */
                                      &kdf,                /* KDF 파라미터 */
                                      AES2_F_MAC_ENABLE | AES2_F_NONCE_GUARD,  /* 플래그: MAC 활성화, Nonce Guard 활성화 */
                                      AES2_TagLen_32);     /* 태그 길이: 32바이트 (보안형) */

    if (st != AES_OK) {
        printf("[AES2] AES2_init_hardened 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 2) 입력 평문 암호화 (CTR + EtM: Encrypt-then-MAC) */
    /* 
     * EtM 방식: 먼저 암호화를 수행한 후, 암호문에 대해 MAC을 계산합니다.
     * 이 방식은 암호문의 무결성을 보장하며, 변조 시 복호화 단계에서 오류가 발생합니다.
     */
    uint8_t nonce[16];      /* nonce 버퍼 (자동 생성됨) */
    uint8_t ct[2048];       /* 암호문 버퍼 */
    uint8_t tag[32];        /* MAC 태그 버퍼 (32바이트) */
    size_t  ct_len = 0;     /* 암호문 길이 */
    size_t  tag_len = 0;    /* 태그 길이 */

    /* 입력 크기 검증 */
    if (msg_len > sizeof(ct)) {
        printf("[AES2] 평문이 데모 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    /* AES2_seal_CTR_autoIV: CTR 모드로 암호화 + HMAC 태그 생성 */
    /* autoIV 옵션으로 nonce가 자동으로 생성됩니다 */
    st = AES2_seal_CTR_autoIV(&ctx,
                              (const uint8_t*)"AAD", 3,  /* AAD: 암호화하지 않고 인증만 하는 데이터 (예: 헤더) */
                              nonce,                     /* 출력: 생성된 nonce */
                              msg, msg_len,              /* 입력: 평문 */
                              ct, sizeof(ct), &ct_len,   /* 출력: 암호문 버퍼 및 길이 */
                              tag, sizeof(tag), &tag_len); /* 출력: MAC 태그 버퍼 및 길이 */
    if (st != AES_OK) {
        printf("[AES2] AES2_seal_CTR_autoIV 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 결과 출력 */
    print_hex("[AES2] nonce", nonce, 16);
    print_hex("[AES2] ciphertext", ct, ct_len);
    print_hex("[AES2] tag", tag, tag_len);

    /* 3) 복호화 + 태그 검증 */
    /* 
     * AES2_open_CTR_autoIV는 다음을 수행합니다:
     * 1. 암호문을 복호화
     * 2. MAC 태그를 검증 (변조 탐지)
     * 3. 검증 실패 시 AES_ERR_AUTH 오류 반환
     */
    uint8_t dec[2048];      /* 복호화된 평문 버퍼 */
    size_t  dec_len = 0;    /* 복호화된 평문 길이 */
    memset(dec, 0, sizeof(dec));  /* 버퍼 초기화 */

    st = AES2_open_CTR_autoIV(&ctx,
                              (const uint8_t*)"AAD", 3,  /* AAD: 암호화 시와 동일해야 함 */
                              nonce,                     /* 입력: 암호화 시 사용한 nonce */
                              ct, ct_len,                /* 입력: 암호문 */
                              tag, tag_len,              /* 입력: MAC 태그 */
                              dec, sizeof(dec), &dec_len); /* 출력: 복호화된 평문 버퍼 및 길이 */
    if (st != AES_OK) {
        printf("[AES2] AES2_open_CTR_autoIV 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES2] 복호화 결과: \"%.*s\"\n", (int)dec_len, dec);

#ifdef AES_ERR_AUTH
    /* 3-1) 간단한 변조 탐지 데모 */
    /* 
     * AES2의 HMAC 기능이 암호문 변조를 탐지하는지 확인하는 데모입니다.
     * 암호문의 1바이트만 변경해도 MAC 검증이 실패하여 복호화가 거부됩니다.
     */
    if (ct_len > 0) {
        uint8_t ct_tampered[2048];  /* 변조된 암호문 버퍼 */
        memcpy(ct_tampered, ct, ct_len);  /* 원본 암호문 복사 */
        ct_tampered[0] ^= 0x01;  /* 첫 번째 바이트를 1비트 변경 (변조 시뮬레이션) */
        
        size_t dummy_len = 0;
        /* 변조된 암호문으로 복호화 시도 */
        AESStatus st2 = AES2_open_CTR_autoIV(&ctx,
                                             (const uint8_t*)"AAD", 3,
                                             nonce,
                                             ct_tampered, ct_len,  /* 변조된 암호문 */
                                             tag, tag_len,
                                             dec, sizeof(dec), &dummy_len);
        /* 변조 탐지 시 AES_ERR_AUTH 오류가 반환되어야 합니다 */
        if (st2 == AES_ERR_AUTH) {
            printf("[AES2] 암호문 변조 → AES_ERR_AUTH로 정상 차단.\n");
        }
    }
#endif

    /* 4) 10MiB 벤치마크 */
    /* AES2의 CTR + HMAC 성능을 측정합니다 */
    printf("\n[AES2] 10MiB CTR+HMAC 암호화 성능 측정 중...\n");

    /* 벤치마크용 버퍼 할당 */
    uint8_t* bench_pt  = (uint8_t*)malloc(BENCH_SIZE);  /* 평문 버퍼 */
    uint8_t* bench_ct  = (uint8_t*)malloc(BENCH_SIZE);  /* 암호문 버퍼 */
    uint8_t* bench_tag = (uint8_t*)malloc(32);          /* 태그 버퍼 (32바이트) */
    if (!bench_pt || !bench_ct || !bench_tag) {
        printf("[AES2] 10MiB 버퍼 할당 실패.\n");
        free(bench_pt);
        free(bench_ct);
        free(bench_tag);
        return;
    }

    /* 벤치마크용 평문 생성: 입력 메시지를 반복하여 10MiB 채우기 */
    for (size_t i = 0; i < BENCH_SIZE; i++) {
        bench_pt[i] = msg[i % msg_len];  /* 입력 메시지를 순환하여 채움 */
    }

    /* 성능 측정 시작 */
    double t0 = now_seconds();
    uint8_t bench_nonce[16];      /* 벤치마크용 nonce (자동 생성됨) */
    size_t bench_ct_len  = 0;     /* 암호문 길이 */
    size_t bench_tag_len = 0;     /* 태그 길이 */

    /* 10MiB 데이터를 CTR + HMAC으로 암호화 */
    st = AES2_seal_CTR_autoIV(&ctx,
                              NULL, 0,      /* AAD 없음 */
                              bench_nonce,  /* 출력: 생성된 nonce */
                              bench_pt, BENCH_SIZE,  /* 입력: 평문 */
                              bench_ct, BENCH_SIZE, &bench_ct_len,  /* 출력: 암호문 버퍼 및 길이 */
                              bench_tag, 32, &bench_tag_len);  /* 출력: 태그 버퍼 (32바이트) 및 길이 */

    double t1 = now_seconds();  /* 성능 측정 종료 */

    if (st != AES_OK) {
        printf("[AES2] 10MiB 암호화 실패: %s\n", aes_status_str(st));
        free(bench_pt);
        free(bench_ct);
        free(bench_tag);
        return;
    }

    /* 메모리 해제 */
    free(bench_pt);
    free(bench_ct);
    free(bench_tag);

    /* 처리량 계산 */
    double elapsed = t1 - t0;  /* 경과 시간 (초) */
    if (elapsed <= 0.0) elapsed = 1e-9;  /* 0으로 나누기 방지 */
    double mb = (double)BENCH_SIZE / (1024.0 * 1024.0);  /* 데이터 크기를 MB로 변환 */
    double mbps = mb / elapsed;  /* 초당 처리량 (MB/s) */

    /* 결과 출력 */
    printf("[AES2] 10MiB 암호화 시간: %.4f 초\n", elapsed);
    printf("[AES2] 처리량: %.2f MB/s\n", mbps);
}

/* --------------------------------------------------------------------------
 * main: 평문 입력 + 프로파일 선택 + AES1 모드 선택
 * -------------------------------------------------------------------------- */

/**
 * 메인 함수
 * 
 * 프로그램의 진입점으로, 다음 작업을 수행합니다:
 * 1. Windows 환경에서 UTF-8 콘솔 설정
 * 2. 셀프 테스트 수행 (SHA-512, AES2)
 * 3. 사용자로부터 평문 입력 받기
 * 4. 프로파일 선택 (AES1 또는 AES2)
 * 5. 선택된 프로파일에 따라 암호화 데모 및 벤치마크 실행
 * 
 * @return 프로그램 종료 코드 (0: 성공, 1: 오류)
 */
int main(void) {
    /* Windows에서 UTF-8 콘솔 출력 설정 */
    /* 한글 등 멀티바이트 문자의 올바른 표시를 위해 필요합니다 */
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);  /* 콘솔 출력 코드 페이지를 UTF-8로 설정 */
    SetConsoleCP(CP_UTF8);        /* 콘솔 입력 코드 페이지를 UTF-8로 설정 */
    setlocale(LC_ALL, ".UTF-8");  /* C 런타임 로케일을 UTF-8로 설정 */
    #endif
    
    /* 프로그램 제목 출력 */
    printf("============================================================\n");
    printf("  AES1 (속도형) vs AES2 (보안형) 데모 + 10MiB 성능 측정\n");
    printf("============================================================\n\n");

    /* 0) 셀프 테스트 (SHA-512, AES2) */
    /* 
     * 셀프 테스트는 암호화 라이브러리가 올바르게 구현되었는지 검증합니다.
     * 테스트 실패 시 프로그램을 종료하여 잘못된 결과를 방지합니다.
     */
    if (sha512_selftest() != 0) {
        printf("[SELFTEST] SHA-512 selftest 실패.\n");
        return 1;  /* 오류 코드 반환 */
    }
    AESStatus st = AES2_selftest();
    if (st != AES_OK) {
        printf("[SELFTEST] AES2_selftest 실패: %s\n", aes_status_str(st));
        return 1;  /* 오류 코드 반환 */
    }
    printf("[SELFTEST] SHA-512 / AES2 selftest: OK\n\n");

    /* 1) 평문 입력 */
    /* 사용자로부터 암호화할 평문을 입력받습니다 */
    char line[2048];  /* 입력 버퍼 (최대 2047바이트 + 널 종료 문자) */
    printf("평문을 입력하세요 (최대 2047바이트):\n> ");
    if (!fgets(line, sizeof(line), stdin)) {
        printf("입력을 읽지 못했습니다.\n");
        return 1;  /* 입력 실패 시 종료 */
    }
    
    /* 개행 문자 제거 및 길이 계산 */
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';  /* 개행 문자 제거 */
        len--;  /* 길이 조정 */
    }
    
    /* 빈 입력 검증 */
    if (len == 0) {
        printf("빈 평문입니다. 종료합니다.\n");
        return 0;  /* 정상 종료 */
    }

    /* 2) 프로파일 선택 */
    /* 
     * AES1 (속도형): 빠른 암호화 성능, 기본적인 보안 기능
     * AES2 (보안형): 강화된 보안 기능 (HMAC, HKDF), 상대적으로 느림
     */
    printf("\n사용할 프로파일을 선택하세요:\n");
    printf("  [1] AES1 속도형 (CTR / ECB / CBC)\n");
    printf("  [2] AES2 보안형 (CTR + HKDF + HMAC-SHA-512)\n");
    printf("선택: ");

    char choice_buf[16];  /* 프로파일 선택 입력 버퍼 */
    if (!fgets(choice_buf, sizeof(choice_buf), stdin)) {
        printf("입력을 읽지 못했습니다.\n");
        return 1;  /* 입력 실패 시 종료 */
    }
    int choice = atoi(choice_buf);  /* 문자열을 정수로 변환 */

    if (choice == 1) {
        /* AES1 속도형 선택 */
        /* AES1은 여러 운용 모드를 지원합니다 */
        printf("\n[AES1] 운용 모드를 선택하세요:\n");
        printf("  [1] CTR (스트림 모드, 10MiB 벤치마크 포함)\n");
        printf("  [2] ECB (교육/테스트용)\n");
        printf("  [3] CBC (랜덤 IV + 패딩)\n");
        printf("선택: ");

        char mode_buf[16];  /* 모드 선택 입력 버퍼 */
        if (!fgets(mode_buf, sizeof(mode_buf), stdin)) {
            printf("입력을 읽지 못했습니다.\n");
            return 1;  /* 입력 실패 시 종료 */
        }
        int mode = atoi(mode_buf);  /* 문자열을 정수로 변환 */

        /* 선택된 모드에 따라 해당 데모 함수 호출 */
        if (mode == 1) {
            /* CTR 모드: 스트림 암호처럼 동작, 10MiB 벤치마크 포함 */
            aes1_ctr_demo_and_bench((const uint8_t*)line, len);
        } else if (mode == 2) {
            /* ECB 모드: 교육/테스트용 (실제 사용 비권장) */
            aes1_ecb_demo((const uint8_t*)line, len);
        } else if (mode == 3) {
            /* CBC 모드: 랜덤 IV와 패딩 사용 */
            aes1_cbc_demo((const uint8_t*)line, len);
        } else {
            printf("잘못된 모드 선택입니다. 1~3 중 하나를 선택해야 합니다.\n");
            return 1;  /* 잘못된 입력 시 종료 */
        }
    } else if (choice == 2) {
        /* AES2 보안형 선택 */
        /* AES2는 CTR + HKDF + HMAC을 사용하는 보안 강화 프로파일입니다 */
        run_aes2_demo((const uint8_t*)line, len);
    } else {
        printf("잘못된 프로파일 선택입니다. 1 또는 2를 입력해야 합니다.\n");
        return 1;  /* 잘못된 입력 시 종료 */
    }

    /* 프로그램 정상 종료 */
    printf("\n프로그램을 종료합니다.\n");
    return 0;  /* 성공 코드 반환 */
}
