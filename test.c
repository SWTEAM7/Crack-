/* =========================================================================
 * test.c — AES1(속도형) vs AES2(보안형) 인터랙티브 데모 + 10MiB 벤치마크
 *
 * 기능:
 *   - 사용자 평문 입력
 *   - [1] AES1 속도형(CTR, 무결성 없음)
 *   - [2] AES2 보안형(CTR + HKDF-SHA-512 + HMAC-SHA-512, EtM)
 *   - 선택한 프로파일로
 *       · 평문 암/복호 시연
 *       · 10MiB 암호화 시간 및 처리량(MB/s) 측정
 * 
 * 빌드:
 *   Windows: cl /utf-8 /std:c17 /O2 /W4 /D_CRT_SECURE_NO_WARNINGS test.c aes.c aes2.c sha512.c
 *   Linux/Mac: gcc -O2 -std=c17 -Wall test1.c aes.c aes2.c sha512.c -o test
 * ------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "aes.h"
#include "aes2.h"
#include "sha512.h"

#ifdef _WIN32
    #include <windows.h>
    #include <locale.h>
#endif

#define BENCH_SIZE (10u * 1024u * 1024u) /* 10 MiB */

static void print_hex(const char* label, const uint8_t* buf, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

static const char* aes_status_str(AESStatus st) {
    switch (st) {
    case AES_OK:            return "AES_OK";
    case AES_ERR_BAD_PARAM: return "AES_ERR_BAD_PARAM";
    case AES_ERR_BUF_SMALL: return "AES_ERR_BUF_SMALL";
    case AES_ERR_OVERLAP:   return "AES_ERR_OVERLAP";
    case AES_ERR_STATE:     return "AES_ERR_STATE";
#ifdef AES_ERR_AUTH
    case AES_ERR_AUTH:      return "AES_ERR_AUTH";
#endif
    default:                return "AES_ERR_UNKNOWN";
    }
}

static double now_seconds(void) {
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

/* --------------------------------------------------------------------------
 * AES1(속도형) 데모 + 10MiB 벤치마크
 * -------------------------------------------------------------------------- */

static void run_aes1_demo(const uint8_t* msg, size_t msg_len) {
    printf("\n========================================\n");
    printf(" [AES1] 속도형 프로파일 — CTR 모드 데모\n");
    printf("========================================\n");

    /* 1) 키/컨텍스트 준비 (AES-256) */
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, key, AES256);
    if (st != AES_OK) {
        printf("[AES1] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 2) 입력 평문 암호화 (CTR) */
    uint8_t nonce[16] = {0}; /* 데모용: 고정 nonce */
    uint8_t ct[2048];
    if (msg_len > sizeof(ct)) {
        printf("[AES1] 평문이 데모 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    memcpy(ct, msg, msg_len); /* in-place 가능하지만, 보기 쉽게 분리 */
    uint8_t ctr[16];
    memcpy(ctr, nonce, 16);

    st = AES_cryptCTR(&ctx, msg, msg_len, ct, ctr);
    if (st != AES_OK) {
        printf("[AES1] AES_cryptCTR 실패: %s\n", aes_status_str(st));
        return;
    }

    print_hex("[AES1] nonce", nonce, 16);
    print_hex("[AES1] ciphertext", ct, msg_len);

    /* 3) 복호화 (CTR) */
    uint8_t dec[2048];
    uint8_t ctr2[16];
    memcpy(ctr2, nonce, 16);
    st = AES_cryptCTR(&ctx, ct, msg_len, dec, ctr2);
    if (st != AES_OK) {
        printf("[AES1] 복호화 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES1] 복호화 결과: \"%.*s\"\n", (int)msg_len, dec);

    /* 4) 10MiB 벤치마크 */
    printf("\n[AES1] 10MiB CTR 암호화 성능 측정 중...\n");

    uint8_t* bench_pt = (uint8_t*)malloc(BENCH_SIZE);
    uint8_t* bench_ct = (uint8_t*)malloc(BENCH_SIZE);
    if (!bench_pt || !bench_ct) {
        printf("[AES1] 10MiB 버퍼 할당 실패.\n");
        free(bench_pt);
        free(bench_ct);
        return;
    }

    /* 평문 패턴 채우기: 입력 메시지를 반복 */
    for (size_t i = 0; i < BENCH_SIZE; i++) {
        bench_pt[i] = msg[i % msg_len];
    }

    uint8_t bench_nonce[16] = {0};
    uint8_t bench_ctr[16];
    memcpy(bench_ctr, bench_nonce, 16);

    double t0 = now_seconds();
    st = AES_cryptCTR(&ctx, bench_pt, BENCH_SIZE, bench_ct, bench_ctr);
    double t1 = now_seconds();

    free(bench_pt);
    free(bench_ct);

    if (st != AES_OK) {
        printf("[AES1] 10MiB 암호화 실패: %s\n", aes_status_str(st));
        return;
    }

    double elapsed = t1 - t0;
    if (elapsed <= 0.0) elapsed = 1e-9;
    double mb = (double)BENCH_SIZE / (1024.0 * 1024.0);
    double mbps = mb / elapsed;

    printf("[AES1] 10MiB 암호화 시간: %.4f 초\n", elapsed);
    printf("[AES1] 처리량: %.2f MB/s\n", mbps);
}

/* --------------------------------------------------------------------------
 * AES2(보안형) 데모 + 10MiB 벤치마크
 * -------------------------------------------------------------------------- */

static void run_aes2_demo(const uint8_t* msg, size_t msg_len) {
    printf("\n=================================================\n");
    printf(" [AES2] 보안형 프로파일 — CTR + HKDF + HMAC 데모\n");
    printf("=================================================\n");

    /* 1) 마스터 키 / KDF 파라미터 (AES-256, 태그 32바이트) */
    static const uint8_t master_key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    static const uint8_t salt[] = "AES2-demo-salt";
    static const uint8_t info[] = "AES2-demo-info";

    AES2_KDFParams kdf = {
        salt, sizeof(salt) - 1,
        info, sizeof(info) - 1
    };

    AES2_SecCtx ctx;
    AESStatus st = AES2_init_hardened(&ctx,
                                      master_key, AES256,
                                      &kdf,
                                      AES2_F_MAC_ENABLE | AES2_F_NONCE_GUARD,
                                      AES2_TagLen_32); /* 보안형: 32바이트 태그 */

    if (st != AES_OK) {
        printf("[AES2] AES2_init_hardened 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 2) 입력 평문 암호화 (CTR + EtM) */
    uint8_t nonce[16];
    uint8_t ct[2048];
    uint8_t tag[32];
    size_t  ct_len = 0;
    size_t  tag_len = 0;

    if (msg_len > sizeof(ct)) {
        printf("[AES2] 평문이 데모 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    st = AES2_seal_CTR_autoIV(&ctx,
                              (const uint8_t*)"AAD", 3, /* 간단한 AAD */
                              nonce,
                              msg, msg_len,
                              ct, sizeof(ct), &ct_len,
                              tag, sizeof(tag), &tag_len);
    if (st != AES_OK) {
        printf("[AES2] AES2_seal_CTR_autoIV 실패: %s\n", aes_status_str(st));
        return;
    }

    print_hex("[AES2] nonce", nonce, 16);
    print_hex("[AES2] ciphertext", ct, ct_len);
    print_hex("[AES2] tag", tag, tag_len);

    /* 3) 복호화 + 태그 검증 */
    uint8_t dec[2048];
    size_t  dec_len = 0;
    memset(dec, 0, sizeof(dec));

    st = AES2_open_CTR_autoIV(&ctx,
                              (const uint8_t*)"AAD", 3,
                              nonce,
                              ct, ct_len,
                              tag, tag_len,
                              dec, sizeof(dec), &dec_len);
    if (st != AES_OK) {
        printf("[AES2] AES2_open_CTR_autoIV 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES2] 복호화 결과: \"%.*s\"\n", (int)dec_len, dec);

#ifdef AES_ERR_AUTH
    /* 3-1) 간단한 변조 탐지 데모 (옵션) */
    if (ct_len > 0) {
        uint8_t ct_tampered[2048];
        memcpy(ct_tampered, ct, ct_len);
        ct_tampered[0] ^= 0x01; /* 암호문 1바이트 변조 */
        size_t dummy_len = 0;
        AESStatus st2 = AES2_open_CTR_autoIV(&ctx,
                                             (const uint8_t*)"AAD", 3,
                                             nonce,
                                             ct_tampered, ct_len,
                                             tag, tag_len,
                                             dec, sizeof(dec), &dummy_len);
        if (st2 == AES_ERR_AUTH) {
            printf("[AES2] 암호문 변조 → AES_ERR_AUTH로 정상 차단.\n");
        }
    }
#endif

    /* 4) 10MiB 벤치마크 */
    printf("\n[AES2] 10MiB CTR+HMAC 암호화 성능 측정 중...\n");

    uint8_t* bench_pt  = (uint8_t*)malloc(BENCH_SIZE);
    uint8_t* bench_ct  = (uint8_t*)malloc(BENCH_SIZE);
    uint8_t* bench_tag = (uint8_t*)malloc(32);
    if (!bench_pt || !bench_ct || !bench_tag) {
        printf("[AES2] 10MiB 버퍼 할당 실패.\n");
        free(bench_pt);
        free(bench_ct);
        free(bench_tag);
        return;
    }

    for (size_t i = 0; i < BENCH_SIZE; i++) {
        bench_pt[i] = msg[i % msg_len];
    }

    double t0 = now_seconds();
    uint8_t bench_nonce[16];
    size_t bench_ct_len  = 0;
    size_t bench_tag_len = 0;

    st = AES2_seal_CTR_autoIV(&ctx,
                              NULL, 0,      /* AAD 없음 */
                              bench_nonce,
                              bench_pt, BENCH_SIZE,
                              bench_ct, BENCH_SIZE, &bench_ct_len,
                              bench_tag, 32, &bench_tag_len); /* 태그 버퍼 32바이트 */

    double t1 = now_seconds();

    if (st != AES_OK) {
        printf("[AES2] 10MiB 암호화 실패: %s\n", aes_status_str(st));
        free(bench_pt);
        free(bench_ct);
        free(bench_tag);
        return;
    }

    free(bench_pt);
    free(bench_ct);
    free(bench_tag);

    double elapsed = t1 - t0;
    if (elapsed <= 0.0) elapsed = 1e-9;
    double mb = (double)BENCH_SIZE / (1024.0 * 1024.0);
    double mbps = mb / elapsed;

    printf("[AES2] 10MiB 암호화 시간: %.4f 초\n", elapsed);
    printf("[AES2] 처리량: %.2f MB/s\n", mbps);
}

/* --------------------------------------------------------------------------
 * main: 평문 입력 + 프로파일 선택
 * -------------------------------------------------------------------------- */

int main(void) {
#ifdef _WIN32
    // 콘솔과 C 런타임을 UTF-8로 맞추기
    SetConsoleOutputCP(CP_UTF8);  // 출력
    SetConsoleCP(CP_UTF8);        // 입력
    setlocale(LC_ALL, ".UTF-8");
#endif
    printf("============================================================\n");
    printf("  AES1 (속도형) vs AES2 (보안형) 데모 + 10MiB 성능 측정\n");
    printf("============================================================\n\n");

    /* 0) 셀프 테스트 (SHA-512, AES2) */
    if (sha512_selftest() != 0) {
        printf("[SELFTEST] SHA-512 selftest 실패.\n");
        return 1;
    }
    AESStatus st = AES2_selftest();
    if (st != AES_OK) {
        printf("[SELFTEST] AES2_selftest 실패: %s\n", aes_status_str(st));
        return 1;
    }
    printf("[SELFTEST] SHA-512 / AES2 selftest: OK\n\n");

    /* 1) 평문 입력 */
    char line[2048];
    printf("평문을 입력하세요 (최대 2047바이트):\n> ");
    if (!fgets(line, sizeof(line), stdin)) {
        printf("입력을 읽지 못했습니다.\n");
        return 1;
    }
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
        len--;
    }
    if (len == 0) {
        printf("빈 평문입니다. 종료합니다.\n");
        return 0;
    }

    /* 2) 프로파일 선택 */
    printf("\n사용할 프로파일을 선택하세요:\n");
    printf("  [1] AES1 속도형 (CTR, 무결성 없음)\n");
    printf("  [2] AES2 보안형 (CTR + HKDF + HMAC-SHA-512)\n");
    printf("선택: ");

    char choice_buf[16];
    if (!fgets(choice_buf, sizeof(choice_buf), stdin)) {
        printf("입력을 읽지 못했습니다.\n");
        return 1;
    }
    int choice = atoi(choice_buf);

    if (choice == 1) {
        run_aes1_demo((const uint8_t*)line, len);
    } else if (choice == 2) {
        run_aes2_demo((const uint8_t*)line, len);
    } else {
        printf("잘못된 선택입니다. 1 또는 2를 입력해야 합니다.\n");
        return 1;
    }

    printf("\n프로그램을 종료합니다.\n");
    return 0;
}
