/* =========================================================================
 * test.c — AES1 vs AES2 기능/성능 테스트
 *
 *  - SHA-512 / HKDF / HMAC / AES2 selftest
 *  - AES2 CTR(EtM) 암·복호 기능 테스트
 *  - AES1 CTR vs AES2 CTR+HMAC 성능 비교 (MB/s)
 *
 * 빌드 예시 (macOS, clang):
 *   clang aes.c aes2.c sha512.c test.c -O3 -std=c99 -Wall -Wextra -pedantic -o test
 * ========================================================================= */

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

/* ---------- 공통 헬퍼 ---------- */

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
    /* CPU time 기준. 큰 반복 횟수로 평균낼 것이므로 대략적 비교용으로 충분. */
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

/* ---------- AES2 기능 테스트 (CTR EtM 왕복) ---------- */

static int test_aes2_ctr_functional(void) {
    printf("=== [AES2] 기능 테스트: CTR + HMAC-SHA-512(EtM) ===\n");

    /* 1) 마스터 키 / KDF 파라미터 (고정값, 재현 가능) */
    static const uint8_t master_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    static const uint8_t salt[] = "AES2-demo-salt";
    static const uint8_t info[] = "AES2-demo-info";

    AES2_KDFParams kdf = {
        salt, sizeof(salt) - 1,
        info, sizeof(info) - 1
    };

    AES2_SecCtx ctx;
    AESStatus st = AES2_init_hardened(&ctx,
                                      master_key, AES128,
                                      &kdf,
                                      AES2_F_MAC_ENABLE | AES2_F_NONCE_GUARD,
                                      AES2_TagLen_32);
    if (st != AES_OK) {
        printf("[FAIL] AES2_init_hardened: %s\n", aes_status_str(st));
        return 0;
    }

    /* 2) 평문 준비 */
    const char* msg = "Hello, AES2 CTR EtM! 보안형 프로파일 테스트";
    const uint8_t* pt = (const uint8_t*)msg;
    size_t pt_len = strlen(msg);

    uint8_t nonce[16];
    uint8_t ct[1024];
    uint8_t tag[32];
    size_t  ct_len = 0;
    size_t  tag_len = 0;

    /* 3) 자동 nonce + 암호화 */
    st = AES2_seal_CTR_autoIV(&ctx,
                              (const uint8_t*)"HDR", 3,   /* AAD (간단히 "HDR") */
                              nonce,                     /* out_nonce16 */
                              pt, pt_len,
                              ct, sizeof(ct), &ct_len,
                              tag, sizeof(tag), &tag_len);
    if (st != AES_OK) {
        printf("[FAIL] AES2_seal_CTR_autoIV: %s\n", aes_status_str(st));
        return 0;
    }

    print_hex("nonce", nonce, 16);
    print_hex("ct", ct, ct_len);
    print_hex("tag", tag, tag_len);

    /* 4) 복호화 + 태그 검증 */
    uint8_t dec[1024];
    size_t  dec_len = 0;
    memset(dec, 0, sizeof(dec));

    st = AES2_open_CTR_autoIV(&ctx,
                              (const uint8_t*)"HDR", 3,
                              nonce,
                              ct, ct_len,
                              tag, tag_len,
                              dec, sizeof(dec), &dec_len);
    if (st != AES_OK) {
        printf("[FAIL] AES2_open_CTR_autoIV: %s\n", aes_status_str(st));
        return 0;
    }

    /* 5) 원문 비교 */
    if (dec_len != pt_len || memcmp(dec, pt, pt_len) != 0) {
        printf("[FAIL] 복호화 결과가 원문과 다름.\n");
        print_hex("PT", pt, pt_len);
        print_hex("DEC", dec, dec_len);
        return 0;
    }

    printf("[OK] AES2 CTR EtM 기능 테스트 성공.\n");
    printf("     복호화 결과 문자열: \"%.*s\"\n\n", (int)dec_len, dec);
    return 1;
}

/* ---------- AES2 보안성 테스트: 데이터 위조 감지 ---------- */
static int test_aes2_tampering(void) {
    printf("=== [AES2] 보안성 테스트: 데이터 위조(Tampering) 감지 ===\n");

    /* 1. 초기화 및 정상 암호화 수행 */
    static const uint8_t mkey[16] = {0}; // Zero key
    static const uint8_t salt[] = "tamp-salt";
    static const uint8_t info[] = "tamp-info";
    AES2_KDFParams kdf = { salt, sizeof(salt)-1, info, sizeof(info)-1 };
    
    AES2_SecCtx ctx;
    AES2_init_hardened(&ctx, mkey, AES128, &kdf, AES2_F_MAC_ENABLE, AES2_TagLen_32);

    const uint8_t* pt = (const uint8_t*)"Secret Message";
    size_t pt_len = strlen((const char*)pt);
    
    uint8_t nonce[16];
    uint8_t ct[64]; size_t ct_len = 0;
    uint8_t tag[32]; size_t tag_len = 0;

    AES2_seal_CTR_autoIV(&ctx, NULL, 0, nonce, pt, pt_len, ct, sizeof(ct), &ct_len, tag, sizeof(tag), &tag_len);

    uint8_t dec[64];
    size_t dec_len = 0;

    /* 2. [CASE 1] 암호문(CT) 1비트 조작 -> 복호화 실패해야 함 */
    ct[0] ^= 0x01; // 비트 반전
    AESStatus st = AES2_open_CTR_autoIV(&ctx, NULL, 0, nonce, ct, ct_len, tag, tag_len, dec, sizeof(dec), &dec_len);
    
    if (st == AES_ERR_AUTH) {
        printf("[OK] 암호문 변조 감지 성공 (AES_ERR_AUTH 반환)\n");
    } else {
        printf("[FAIL] 암호문이 변조되었는데 복호화가 수행됨! (st=%s)\n", aes_status_str(st));
        return 0;
    }
    ct[0] ^= 0x01; // 원상복구

    /* 3. [CASE 2] 태그(Tag) 1비트 조작 -> 복호화 실패해야 함 */
    tag[0] ^= 0x80; // 비트 반전
    st = AES2_open_CTR_autoIV(&ctx, NULL, 0, nonce, ct, ct_len, tag, tag_len, dec, sizeof(dec), &dec_len);

    if (st == AES_ERR_AUTH) {
        printf("[OK] 태그 변조 감지 성공 (AES_ERR_AUTH 반환)\n");
    } else {
        printf("[FAIL] 태그가 변조되었는데 복호화가 수행됨! (st=%s)\n", aes_status_str(st));
        return 0;
    }

    /* 4. [CASE 3] Nonce 조작 -> 복호화 실패해야 함 (HMAC 입력에 Nonce가 포함되므로) */
    nonce[0] ^= 0xFF;
    tag[0] ^= 0x80; // 태그 원상복구
    st = AES2_open_CTR_autoIV(&ctx, NULL, 0, nonce, ct, ct_len, tag, tag_len, dec, sizeof(dec), &dec_len);
    
    if (st == AES_ERR_AUTH) {
        printf("[OK] Nonce 변조 감지 성공 (AES_ERR_AUTH 반환)\n");
    } else {
        printf("[FAIL] Nonce가 변조되었는데 복호화가 수행됨!\n");
        return 0;
    }

    printf("[OK] 모든 위조 공격 방어 확인 완료.\n\n");
    return 1;
}

/* ---------- 성능 측정: AES1 CTR vs AES2 CTR EtM ---------- */

static double benchmark_aes1_ctr(size_t msg_len, size_t iters) {
    /* AES1(속도형) CTR: HMAC 없음 */
    AES_ctx ctx;
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    AESStatus st = AES_init(&ctx, key, AES256);
    if (st != AES_OK) {
        printf("[AES1] AES_init 실패: %s\n", aes_status_str(st));
        return 0.0;
    }

    uint8_t* pt = (uint8_t*)malloc(msg_len);
    uint8_t* ct = (uint8_t*)malloc(msg_len);
    if (!pt || !ct) {
        free(pt); free(ct);
        return 0.0;
    }

    for (size_t i = 0; i < msg_len; i++) {
        pt[i] = (uint8_t)(i * 31u + 7u); // 간단한 패턴
    }

    double start = now_seconds();

    for (size_t i = 0; i < iters; i++) {
        uint8_t nonce[16] = {0}; /* 매 호출마다 동일 nonce 사용 (테스트용) */
        (void)AES_cryptCTR(&ctx, pt, msg_len, ct, nonce);
    }

    double end = now_seconds();
    double elapsed = end - start;

    free(pt);
    free(ct);

    if (elapsed <= 0.0) elapsed = 1e-9; // 0 나누기 방지
    double total_bytes = (double)msg_len * (double)iters;
    double mbps = (total_bytes / (1024.0 * 1024.0)) / elapsed;
    return mbps;
}

static double benchmark_aes2_ctr(size_t msg_len, size_t iters) {
    /* AES2(보안형) CTR + HMAC-SHA-512(EtM) */
    static const uint8_t master_key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    static const uint8_t salt[] = "AES2-bench-salt";
    static const uint8_t info[] = "AES2-bench-info";

    AES2_KDFParams kdf = {
        salt, sizeof(salt) - 1,
        info, sizeof(info) - 1
    };
    AES2_SecCtx ctx;
    AESStatus st = AES2_init_hardened(&ctx,
                                      master_key, AES256,
                                      &kdf,
                                      AES2_F_MAC_ENABLE | AES2_F_NONCE_GUARD,
                                      AES2_TagLen_16);
    if (st != AES_OK) {
        printf("[AES2] AES2_init_hardened 실패: %s\n", aes_status_str(st));
        return 0.0;
    }

    uint8_t* pt = (uint8_t*)malloc(msg_len);
    uint8_t* ct = (uint8_t*)malloc(msg_len);
    uint8_t* tag = (uint8_t*)malloc(32);
    if (!pt || !ct || !tag) {
        free(pt); free(ct); free(tag);
        return 0.0;
    }

    for (size_t i = 0; i < msg_len; i++) {
        pt[i] = (uint8_t)(i * 17u + 5u); // 간단한 패턴
    }

    double start = now_seconds();

    for (size_t i = 0; i < iters; i++) {
        uint8_t nonce[16];
        size_t ct_len = 0;
        size_t tag_len = 0;
        AESStatus rc = AES2_seal_CTR_autoIV(&ctx,
                                            NULL, 0,       /* AAD 없음 */
                                            nonce,        /* out_nonce16 */
                                            pt, msg_len,
                                            ct, msg_len, &ct_len,
                                            tag, 16, &tag_len);
        if (rc != AES_OK) {
            printf("[AES2] AES2_seal_CTR_autoIV 실패: %s\n", aes_status_str(rc));
            break;
        }
    }

    double end = now_seconds();
    double elapsed = end - start;

    free(pt);
    free(ct);
    free(tag);

    if (elapsed <= 0.0) elapsed = 1e-9;
    double total_bytes = (double)msg_len * (double)iters;
    double mbps = (total_bytes / (1024.0 * 1024.0)) / elapsed;
    return mbps;
}

/* ---------- 메인: 자가진단 + 기능 + 성능 ---------- */

int main(void) {
#ifdef _WIN32
    // 콘솔과 C 런타임을 UTF-8로 맞추기
    SetConsoleOutputCP(CP_UTF8);  // 출력
    SetConsoleCP(CP_UTF8);        // 입력
    setlocale(LC_ALL, ".UTF-8");
#endif
    printf("============================================================\n");
    printf("  AES1 (속도형) vs AES2 (보안형, CTR+HMAC-SHA-512) 테스트\n");
    printf("============================================================\n\n");

    /* 0) SHA-512 / AES2 selftest */
    printf("[SELFTEST] SHA-512 / HKDF / HMAC / AES2 컨텍스트\n");
    if (sha512_selftest() != 0) {
        printf("  - SHA-512 selftest: FAIL\n");
        return 1;
    } else {
        printf("  - SHA-512 selftest: OK\n");
    }

    AESStatus st = AES2_selftest();
    if (st != AES_OK) {
        printf("  - AES2_selftest: FAIL (%s)\n", aes_status_str(st));
        return 1;
    } else {
        printf("  - AES2_selftest: OK\n");
    }
    printf("\n");

    /* 1) AES2 CTR EtM 기능 테스트 */
    if (!test_aes2_ctr_functional()) {
        printf("[FAIL] AES2 CTR EtM 기능 테스트 실패.\n");
        return 1;
    }

    /* 2) AES2 위조 방어 테스트 */
    if (!test_aes2_tampering()) {
        printf("[FAIL] 위조 방어 테스트 실패.\n");
        return 1;
    }

    /* 3) 성능 테스트: AES1 CTR vs AES2 CTR EtM */
    printf("=== [BENCH] AES1 CTR vs AES2 CTR+HMAC (MB/s) ===\n");
    printf("  * 주의: AES2_autoIV 경로는 OS CSPRNG 호출 비용 포함\n");
    printf("          → 실제 환경에서의 '전체 암호화 비용'에 더 가까운 측정값\n\n");

    size_t sizes[] = {
        1024,        /* 1 KiB */
        4 * 1024,    /* 4 KiB */
        16 * 1024,   /* 16 KiB */
        64 * 1024,   /* 64 KiB */
        256 * 1024,  /* 256 KiB */
        1024 * 1024  /* 1 MiB */
    };
    size_t num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    size_t iters = 2000; /* 메시지를 반복 처리하는 횟수 (환경에 맞게 조절 가능) */

    printf("  msg_len  | AES1 CTR (MB/s) | AES2 CTR+MAC (MB/s)\n");
    printf(" ----------+------------------+--------------------\n");

    for (size_t i = 0; i < num_sizes; i++) {
        size_t len = sizes[i];

        /* 너무 큰 len * iters면 시간 많이 걸릴 수 있어서 적당히 조정 */
        size_t adj_iters = iters;
        if (len >= 1024 * 1024) {
            adj_iters = iters / 4; // 1MiB 이상은 반복 횟수 줄이기
            if (adj_iters == 0) adj_iters = 1;
        }

        double mbps1 = benchmark_aes1_ctr(len, adj_iters);
        double mbps2 = benchmark_aes2_ctr(len, adj_iters);

        printf(" %7zu | %16.2f | %18.2f\n",
               len, mbps1, mbps2);
    }

    printf("\n테스트 완료.\n");
    return 0;
}
