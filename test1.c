// test.c — AES 테스트 드라이버 (모드 선택 가능: CTR/CBC/ECB)
// 빌드: clang test.c aes.c -O3 -std=c99 -o test   (또는 gcc)
// 실행: ./test

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


// ───────── 유틸: 안전 랜덤 바이트 (IV/nonce용) ─────────
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

// ───────── 유틸: 타이머(초) ─────────
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

static void hex_print(const uint8_t* p, size_t n) {
    for (size_t i=0; i<n; ++i) printf("%02X", p[i]);
}

static AESPadding ask_padding(void) {
    char line[16]={0};
    printf("패딩 선택: [1] PKCS#7 (권장), [2] ANSI X9.23, [0] NONE: ");
    if (!fgets(line, sizeof(line), stdin)) return AES_PADDING_PKCS7;
    int k = atoi(line);
    if (k==2) return AES_PADDING_ANSI_X923;
    if (k==0) return AES_PADDING_NONE; // 주: NONE이면 길이가 16의 배수여야 함
    return AES_PADDING_PKCS7;
}

int main(void) {
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);  // 콘솔 출력 UTF-8
    SetConsoleCP(CP_UTF8);        // 콘솔 입력 UTF-8
    setlocale(LC_ALL, ".UTF-8");  // C 런타임 로케일
    #endif
    // 입력
    char msg[4096];            // 데모용 버퍼(필요시 늘리세요)
    char line[32]={0};

    printf("평문을 입력하세요: ");
    if (!fgets(msg, sizeof(msg), stdin)) { fprintf(stderr,"입력 오류\n"); return 1; }
    size_t msg_len = strlen(msg);
    if (msg_len && msg[msg_len-1]=='\n') msg[--msg_len]='\0';

    // AES 버전 선택
    printf("[1] AES #1 (속도형)\n[2] AES #2 (보안형)\n선택 (1/2): ");
    if (!fgets(line, sizeof(line), stdin)) { fprintf(stderr,"입력 오류\n"); return 1; }
    int ver = atoi(line);
    if (ver==2) { printf("AES #2는 아직 개발중입니다!\n"); return 0; }
    if (ver!=1) { printf("잘못된 선택입니다.\n"); return 0; }

    // 운용모드 선택
    printf("운용모드 선택: [1] CTR  [2] CBC  [3] ECB : ");
    if (!fgets(line, sizeof(line), stdin)) { fprintf(stderr,"입력 오류\n"); return 1; }
    int mode = atoi(line);

    AESPadding padding = AES_PADDING_NONE;
    if (mode==2 || mode==3) { // CBC/ECB는 패딩 필요(또는 길이 16배수)
        padding = ask_padding();
        if (padding==AES_PADDING_NONE && (msg_len % 16)!=0) {
            printf("※ 패딩 NONE은 평문 길이가 16의 배수여야 합니다. PKCS#7로 자동 변경합니다.\n");
            padding = AES_PADDING_PKCS7;
        }
    }

    // AES 초기화
    AES_ctx ctx;
    uint8_t key[16] = {0}; // 데모키(실전 금지: 사용자 키/랜덤 키로 교체하세요)
    if (AES_init(&ctx, key, AES128)!=AES_OK) { fprintf(stderr,"AES_init 실패\n"); return 1; }

    // 암호화
    uint8_t *ct = NULL, *pt = NULL;
    size_t out_len = 0, back_len = 0;
    AESStatus st;

    if (mode==1) {
        // ───── CTR (패딩 불필요) ─────
        uint8_t iv[16];
        if (rand_bytes(iv, sizeof(iv))!=0) { fprintf(stderr,"난수 실패\n"); return 1; }

        ct = (uint8_t*)malloc(msg_len?msg_len:1);
        pt = (uint8_t*)malloc(msg_len?msg_len:1);
        if (!ct || !pt) { fprintf(stderr,"메모리 부족\n"); return 1; }

        uint8_t iv_work[16];
        memcpy(iv_work, iv, 16);
        st = AES_cryptCTR(&ctx, (const uint8_t*)msg, msg_len, ct, iv_work);
        if (st!=AES_OK) { fprintf(stderr,"CTR 암호화 실패: %s\n", AES_strerror(st)); return 1; }

        // 복호화 확인(IV 동일 시작값)
        memcpy(iv_work, iv, 16);
        st = AES_cryptCTR(&ctx, ct, msg_len, pt, iv_work);
        if (st!=AES_OK) { fprintf(stderr,"CTR 복호화 실패: %s\n", AES_strerror(st)); return 1; }
        back_len = msg_len;

        printf("\n[CTR] 암호문(hex, 앞 64B): ");
        hex_print(ct, msg_len<64?msg_len:64);
        if (msg_len>64) printf("... (+%zu bytes)", msg_len-64);
        printf("\n복호화 확인: %s\n", (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"성공":"실패");

    } else if (mode==2) {
        // ───── CBC ─────
        uint8_t iv_enc[16], iv_dec[16];
        if (rand_bytes(iv_enc, sizeof(iv_enc))!=0) { fprintf(stderr,"난수 실패\n"); return 1; }
        memcpy(iv_dec, iv_enc, 16);

        // 출력 버퍼(패딩 포함 최대 +16)
        ct = (uint8_t*)malloc(msg_len + 16);
        pt = (uint8_t*)malloc(msg_len + 16);
        if (!ct || !pt) { fprintf(stderr,"메모리 부족\n"); return 1; }

        st = AES_encryptCBC(&ctx, (const uint8_t*)msg, msg_len, ct, msg_len+16, &out_len, iv_enc, padding);
        if (st!=AES_OK) { fprintf(stderr,"CBC 암호화 실패: %s\n", AES_strerror(st)); return 1; }

        st = AES_decryptCBC(&ctx, ct, out_len, pt, msg_len+16, &back_len, iv_dec, padding);
        if (st!=AES_OK) { fprintf(stderr,"CBC 복호화 실패: %s\n", AES_strerror(st)); return 1; }

        printf("\n[CBC] 암호문(hex, 앞 64B): ");
        hex_print(ct, out_len<64?out_len:64);
        if (out_len>64) printf("... (+%zu bytes)", out_len-64);
        printf("\n복호화 확인: %s (원문길이=%zu)\n",
               (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"성공":"실패", back_len);

    } else if (mode==3) {
        // ───── ECB (테스트용) ─────
        ct = (uint8_t*)malloc(msg_len + 16);
        pt = (uint8_t*)malloc(msg_len + 16);
        if (!ct || !pt) { fprintf(stderr,"메모리 부족\n"); return 1; }

        st = AES_encryptECB(&ctx, (const uint8_t*)msg, msg_len, ct, msg_len+16, &out_len, padding);
        if (st!=AES_OK) { fprintf(stderr,"ECB 암호화 실패: %s\n", AES_strerror(st)); return 1; }

        st = AES_decryptECB(&ctx, ct, out_len, pt, msg_len+16, &back_len, padding);
        if (st!=AES_OK) { fprintf(stderr,"ECB 복호화 실패: %s\n", AES_strerror(st)); return 1; }

        printf("\n[ECB] (테스트용) 암호문(hex, 앞 64B): ");
        hex_print(ct, out_len<64?out_len:64);
        if (out_len>64) printf("... (+%zu bytes)", out_len-64);
        printf("\n복호화 확인: %s (원문길이=%zu)\n",
               (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"성공":"실패", back_len);
    } else {
        printf("잘못된 모드 선택입니다.\n");
        return 0;
    }

    // ───── 성능 측정: 10MB 암호화 시간 ─────
    const size_t TEN_MB = 10u * 1024u * 1024u;
    uint8_t* bin  = (uint8_t*)malloc(TEN_MB + 16);
    uint8_t* bout = (uint8_t*)malloc(TEN_MB + 32);
    if (!bin || !bout) { fprintf(stderr,"벤치 버퍼 메모리 부족\n"); return 1; }
    memset(bin, 0, TEN_MB);

    double t0, t1; AESStatus bst;
    if (mode==1) {
        uint8_t iv_bench[16];
        rand_bytes(iv_bench, sizeof(iv_bench));
        t0 = now_seconds();
        bst = AES_cryptCTR(&ctx, bin, TEN_MB, bout, iv_bench);
        t1 = now_seconds();
    } else if (mode==2) {
        uint8_t iv_bench[16];
        rand_bytes(iv_bench, sizeof(iv_bench));
        size_t bout_len=0;
        t0 = now_seconds();
        bst = AES_encryptCBC(&ctx, bin, TEN_MB, bout, TEN_MB+16, &bout_len, iv_bench, AES_PADDING_PKCS7);
        t1 = now_seconds();
    } else {
        size_t bout_len=0;
        t0 = now_seconds();
        bst = AES_encryptECB(&ctx, bin, TEN_MB, bout, TEN_MB+16, &bout_len, AES_PADDING_PKCS7);
        t1 = now_seconds();
    }

    if (bst!=AES_OK) {
        fprintf(stderr,"벤치마크 실패: %s\n", AES_strerror(bst));
    } else {
        double sec = t1 - t0;
        printf("\n[성능] 10MB 암호화 시간: %.6f 초\n", sec);
        if (sec>0.0) {
            double mbps = 10.0 / sec;
            double gbps_bits = (10.0*8.0) / sec / 1000.0; // 근사 Gbps
            printf("처리량: %.2f MB/s (약 %.2f Gbps)\n", mbps, gbps_bits);
        }
    }

    free(ct); free(pt); free(bin); free(bout);
    return 0;
}
