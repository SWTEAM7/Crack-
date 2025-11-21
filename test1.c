/**
 * test1.c — AES 테스트 드라이버
 * 
 * 이 프로그램은 AES 암호화 라이브러리의 기능을 테스트하고 성능을 측정합니다.
 * 
 * 주요 기능:
 *   - AES 암호화/복호화 테스트 (CTR, CBC, ECB 모드)
 *   - 패딩 방식 선택 (PKCS#7, ANSI X9.23, NONE)
 *   - 성능 벤치마크 (10MB 데이터 처리 시간 측정)
 * 
 * 빌드:
 *   Windows: cl /utf-8 /std:c17 /O2 /W4 /D_CRT_SECURE_NO_WARNINGS test1.c aes.c aes2.c sha512.c
 *   Linux/Mac: gcc -O2 -std=c17 -Wall test1.c aes.c aes2.c sha512.c -o test1
 * 
 * 실행: ./test1 (or test1.exe)
 */

#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#if defined(_WIN32)
  #include <windows.h>
  #include <locale.h>
#endif

/* ============================================================================
 * 유틸리티 함수들
 * ============================================================================ */

/**
 * rand_bytes - 암호학적으로 안전한 난수 생성
 * 
 * 운영체제의 CSPRNG를 사용하여 IV/nonce 생성에 필요한 난수를 생성합니다.
 * 
 * 플랫폼별 구현:
 *   - Windows: BCryptGenRandom (BCrypt API)
 *   - macOS: arc4random_buf
 *   - Linux/Unix: /dev/urandom
 * 
 * @param buf  난수 출력 버퍼
 * @param n    생성할 바이트 수
 * @return 0 성공, -1 실패
 */
static int rand_bytes(uint8_t* buf, size_t n) {
#if defined(_WIN32)
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0 ? 0 : -1;
#elif defined(__APPLE__)
    // macOS: stdlib.h에 선언된 arc4random_buf 사용
    arc4random_buf(buf, n);
    return 0;
#else
    // Linux/Unix
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(buf, 1, n, f);
    fclose(f);
    return (r == n) ? 0 : -1;
#endif
}

/**
 * now_seconds - 현재 시간을 초 단위로 반환 (고해상도 타이머)
 * 
 * 성능 측정을 위한 고해상도 타이머 함수입니다.
 * 
 * 플랫폼별 구현:
 *   - Windows: QueryPerformanceCounter (고해상도 카운터)
 *   - Linux/Unix: clock_gettime (CLOCK_MONOTONIC)
 * 
 * @return 현재 시간 (초, 부동소수점)
 */
static double now_seconds(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER t;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}

/**
 * hex_print - 바이너리 데이터를 16진수 문자열로 출력
 * 
 * @param p  출력할 데이터 포인터
 * @param n  출력할 바이트 수
 */
static void hex_print(const uint8_t* p, size_t n) {
    for (size_t i=0; i<n; ++i) printf("%02X", p[i]);
}

/**
 * ask_padding - 사용자로부터 패딩 방식 입력받기
 * 
 * CBC/ECB 모드에서 사용할 패딩 방식을 사용자에게 물어봅니다.
 * 
 * @return 선택된 패딩 방식
 */
static AESPadding ask_padding(void) {
    char line[16]={0};
    printf("패딩 선택: [1] PKCS#7 (권장), [2] ANSI X9.23, [0] NONE: ");
    if (!fgets(line, sizeof(line), stdin)) return AES_PADDING_PKCS7;
    int k = atoi(line);
    if (k==2) return AES_PADDING_ANSI_X923;
    if (k==0) return AES_PADDING_NONE; /* 주의: NONE이면 길이가 16의 배수여야 함 */
    return AES_PADDING_PKCS7;
}

/**
 * main - AES 테스트 드라이버 메인 함수
 * 
 * 프로그램의 진입점으로, 다음 작업을 수행합니다:
 *   1. 사용자 입력 받기 (평문, AES 버전, 운용 모드, 패딩)
 *   2. AES 컨텍스트 초기화
 *   3. 선택된 모드로 암호화/복호화 수행
 *   4. 결과 출력 및 검증
 *   5. 성능 벤치마크 (10MB 데이터 처리 시간)
 * 
 * @return 0 성공, 1 오류 발생
 */
int main(void) {
    /* Windows에서 UTF-8 콘솔 출력 설정 */
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);  /* 콘솔 출력 UTF-8 */
    SetConsoleCP(CP_UTF8);        /* 콘솔 입력 UTF-8 */
    setlocale(LC_ALL, ".UTF-8");  /* C 런타임 로케일 */
    #endif
    
    /* 사용자 입력 받기 */
    char msg[4096];            /* 데모용 버퍼(필요시 늘리세요) */
    char line[32]={0};

    printf("평문을 입력하세요: ");
    if (!fgets(msg, sizeof(msg), stdin)) { fprintf(stderr,"입력 오류\n"); return 1; }
    size_t msg_len = strlen(msg);
    /* 개행 문자 제거 */
    if (msg_len && msg[msg_len-1]=='\n') msg[--msg_len]='\0';

    /* AES 버전 선택 */
    printf("[1] AES #1 (속도형)\n[2] AES #2 (보안형)\n선택 (1/2): ");
    if (!fgets(line, sizeof(line), stdin)) { fprintf(stderr,"입력 오류\n"); return 1; }
    int ver = atoi(line);
    if (ver==2) { printf("AES #2는 아직 개발중입니다!\n"); return 0; }
    if (ver!=1) { printf("잘못된 선택입니다.\n"); return 0; }

    /* 운용모드 선택 */
    printf("운용모드 선택: [1] CTR  [2] CBC  [3] ECB : ");
    if (!fgets(line, sizeof(line), stdin)) { fprintf(stderr,"입력 오류\n"); return 1; }
    int mode = atoi(line);

    /* 패딩 방식 선택 (CBC/ECB 모드에서만 필요) */
    AESPadding padding = AES_PADDING_NONE;
    if (mode==2 || mode==3) { /* CBC/ECB는 패딩 필요(또는 길이 16배수) */
        padding = ask_padding();
        /* 패딩 NONE인데 길이가 16의 배수가 아니면 PKCS#7로 자동 변경 */
        if (padding==AES_PADDING_NONE && (msg_len % 16)!=0) {
            printf("※ 패딩 NONE은 평문 길이가 16의 배수여야 합니다. PKCS#7로 자동 변경합니다.\n");
            padding = AES_PADDING_PKCS7;
        }
    }

    /* AES 컨텍스트 초기화 */
    AES_ctx ctx;
    /* 주의: 데모용 고정 키 (실전에서는 절대 사용 금지!) */
    /* 실전에서는 사용자 입력 키나 암호학적으로 안전한 난수 키를 사용해야 합니다 */
    uint8_t key[16] = {0}; 
    if (AES_init(&ctx, key, AES128)!=AES_OK) { fprintf(stderr,"AES_init 실패\n"); return 1; }

    /* 암호화/복호화 버퍼 및 변수 초기화 */
    uint8_t *ct = NULL, *pt = NULL;
    size_t out_len = 0, back_len = 0;
    AESStatus st;

    if (mode==1) {
        /* ====================================================================
         * CTR 모드 (Counter Mode) - 패딩 불필요
         * ==================================================================== */
        /* IV(Initialization Vector) 생성: 암호학적으로 안전한 난수 */
        uint8_t iv[16];
        if (rand_bytes(iv, sizeof(iv))!=0) { fprintf(stderr,"난수 실패\n"); return 1; }

        /* 버퍼 할당: CTR 모드는 패딩이 없으므로 원문 길이와 동일 */
        ct = (uint8_t*)malloc(msg_len?msg_len:1);
        pt = (uint8_t*)malloc(msg_len?msg_len:1);
        if (!ct || !pt) { fprintf(stderr,"메모리 부족\n"); return 1; }

        /* CTR 암호화: IV를 카운터로 사용 */
        uint8_t iv_work[16];
        memcpy(iv_work, iv, 16);
        st = AES_cryptCTR(&ctx, (const uint8_t*)msg, msg_len, ct, iv_work);
        if (st!=AES_OK) { fprintf(stderr,"CTR 암호화 실패: %s\n", AES_strerror(st)); return 1; }

        /* 복호화 확인: 동일한 IV로 시작해야 올바르게 복호화됨 */
        memcpy(iv_work, iv, 16);
        st = AES_cryptCTR(&ctx, ct, msg_len, pt, iv_work);
        if (st!=AES_OK) { fprintf(stderr,"CTR 복호화 실패: %s\n", AES_strerror(st)); return 1; }
        back_len = msg_len;

        /* 결과 출력 */
        printf("\n[CTR] 암호문(hex, 앞 64B): ");
        hex_print(ct, msg_len<64?msg_len:64);
        if (msg_len>64) printf("... (+%zu bytes)", msg_len-64);
        printf("\n복호화 확인: %s\n", (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"성공":"실패");

    } else if (mode==2) {
        /* ====================================================================
         * CBC 모드 (Cipher Block Chaining) - 패딩 필요
         * ==================================================================== */
        /* IV 생성: 암호학적으로 안전한 난수 */
        uint8_t iv_enc[16], iv_dec[16];
        if (rand_bytes(iv_enc, sizeof(iv_enc))!=0) { fprintf(stderr,"난수 실패\n"); return 1; }
        /* 복호화 시 동일한 IV 사용 */
        memcpy(iv_dec, iv_enc, 16);

        /* 출력 버퍼 할당: 패딩 포함 최대 +16바이트 */
        ct = (uint8_t*)malloc(msg_len + 16);
        pt = (uint8_t*)malloc(msg_len + 16);
        if (!ct || !pt) { fprintf(stderr,"메모리 부족\n"); return 1; }

        /* CBC 암호화: 패딩이 자동으로 추가됨 */
        st = AES_encryptCBC(&ctx, (const uint8_t*)msg, msg_len, ct, msg_len+16, &out_len, iv_enc, padding);
        if (st!=AES_OK) { fprintf(stderr,"CBC 암호화 실패: %s\n", AES_strerror(st)); return 1; }

        /* CBC 복호화: 패딩이 자동으로 제거됨 */
        st = AES_decryptCBC(&ctx, ct, out_len, pt, msg_len+16, &back_len, iv_dec, padding);
        if (st!=AES_OK) { fprintf(stderr,"CBC 복호화 실패: %s\n", AES_strerror(st)); return 1; }

        /* 결과 출력 */
        printf("\n[CBC] 암호문(hex, 앞 64B): ");
        hex_print(ct, out_len<64?out_len:64);
        if (out_len>64) printf("... (+%zu bytes)", out_len-64);
        printf("\n복호화 확인: %s (원문길이=%zu)\n",
               (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"성공":"실패", back_len);

    } else if (mode==3) {
        /* ====================================================================
         * ECB 모드 (Electronic Codebook) - 테스트용 (실전 사용 비권장)
         * 
         * 주의: ECB 모드는 보안상 취약하므로 실전에서는 사용하지 않아야 합니다.
         *       동일한 평문 블록은 항상 동일한 암호문 블록으로 변환되어
         *       패턴이 노출될 수 있습니다.
         * ==================================================================== */
        /* 출력 버퍼 할당: 패딩 포함 최대 +16바이트 */
        ct = (uint8_t*)malloc(msg_len + 16);
        pt = (uint8_t*)malloc(msg_len + 16);
        if (!ct || !pt) { fprintf(stderr,"메모리 부족\n"); return 1; }

        /* ECB 암호화: IV 없이 각 블록을 독립적으로 암호화 */
        st = AES_encryptECB(&ctx, (const uint8_t*)msg, msg_len, ct, msg_len+16, &out_len, padding);
        if (st!=AES_OK) { fprintf(stderr,"ECB 암호화 실패: %s\n", AES_strerror(st)); return 1; }

        /* ECB 복호화 */
        st = AES_decryptECB(&ctx, ct, out_len, pt, msg_len+16, &back_len, padding);
        if (st!=AES_OK) { fprintf(stderr,"ECB 복호화 실패: %s\n", AES_strerror(st)); return 1; }

        /* 결과 출력 */
        printf("\n[ECB] (테스트용) 암호문(hex, 앞 64B): ");
        hex_print(ct, out_len<64?out_len:64);
        if (out_len>64) printf("... (+%zu bytes)", out_len-64);
        printf("\n복호화 확인: %s (원문길이=%zu)\n",
               (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"성공":"실패", back_len);
    } else {
        printf("잘못된 모드 선택입니다.\n");
        return 0;
    }

    /* ========================================================================
     * 성능 측정: 10MB 데이터 암호화 시간 측정
     * ======================================================================== */
    const size_t TEN_MB = 10u * 1024u * 1024u;  /* 10MB = 10 * 1024 * 1024 바이트 */
    uint8_t* bin  = (uint8_t*)malloc(TEN_MB + 16);  /* 입력 버퍼 */
    uint8_t* bout = (uint8_t*)malloc(TEN_MB + 32);  /* 출력 버퍼 (패딩 고려) */
    if (!bin || !bout) { fprintf(stderr,"벤치 버퍼 메모리 부족\n"); return 1; }
    memset(bin, 0, TEN_MB);  /* 입력 데이터 초기화 (제로 패딩) */

    double t0, t1;  /* 시작/종료 시간 */
    AESStatus bst;  /* 벤치마크 상태 */
    
    /* 선택된 모드에 따라 벤치마크 수행 */
    if (mode==1) {
        /* CTR 모드 벤치마크 */
        uint8_t iv_bench[16];
        rand_bytes(iv_bench, sizeof(iv_bench));
        t0 = now_seconds();
        bst = AES_cryptCTR(&ctx, bin, TEN_MB, bout, iv_bench);
        t1 = now_seconds();
    } else if (mode==2) {
        /* CBC 모드 벤치마크 */
        uint8_t iv_bench[16];
        rand_bytes(iv_bench, sizeof(iv_bench));
        size_t bout_len=0;
        t0 = now_seconds();
        bst = AES_encryptCBC(&ctx, bin, TEN_MB, bout, TEN_MB+16, &bout_len, iv_bench, AES_PADDING_PKCS7);
        t1 = now_seconds();
    } else {
        /* ECB 모드 벤치마크 */
        size_t bout_len=0;
        t0 = now_seconds();
        bst = AES_encryptECB(&ctx, bin, TEN_MB, bout, TEN_MB+16, &bout_len, AES_PADDING_PKCS7);
        t1 = now_seconds();
    }

    /* 성능 결과 출력 */
    if (bst!=AES_OK) {
        fprintf(stderr,"벤치마크 실패: %s\n", AES_strerror(bst));
    } else {
        double sec = t1 - t0;  /* 소요 시간 (초) */
        printf("\n[성능] 10MB 암호화 시간: %.6f 초\n", sec);
        if (sec>0.0) {
            double mbps = 10.0 / sec;  /* 처리량 (MB/s) */
            double gbps_bits = (10.0*8.0) / sec / 1000.0;  /* 처리량 (Gbps, 근사값) */
            printf("처리량: %.2f MB/s (약 %.2f Gbps)\n", mbps, gbps_bits);
        }
    }

    /* 메모리 해제 */
    free(ct); free(pt); free(bin); free(bout);
    return 0;
}
