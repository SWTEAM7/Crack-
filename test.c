/**
 * @file test.c
 * @brief AES 암호화 라이브러리 테스트 및 벤치마크 프로그램
 * @details CTR, CBC, ECB 운용 모드를 테스트하고 성능을 측정합니다.
 * 
 * 빌드 방법:
 *   clang test.c aes.c -O3 -std=c99 -o test   (또는 gcc)
 * 
 * 실행 방법:
 *   ./test
 * 
 * 사용자 인터페이스:
 *   1. 평문 입력
 *   2. AES 버전 선택 (현재는 #1만 지원)
 *   3. 운용 모드 선택 (CTR/CBC/ECB)
 *   4. 패딩 방식 선택 (CBC/ECB만)
 *   5. 암호화/복호화 수행 및 결과 출력
 *   6. 성능 벤치마크 (10MB 데이터 처리 시간 측정)
 */

#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#if defined(_WIN32)
  #include <windows.h>  // Windows API (QueryPerformanceCounter 등)
  #include <locale.h>   // 로케일 설정
#endif

// ─────────────────────────────────────────────────────────────────────────────
// 유틸리티 함수
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief 암호학적으로 안전한 랜덤 바이트 생성
 * @param buf 출력 버퍼 포인터
 * @param n 생성할 바이트 수
 * @return 0 성공, -1 실패
 * @details 플랫폼별 암호학적으로 안전한 난수 생성기 사용:
 *          - Windows: BCryptGenRandom (Windows API)
 *          - macOS: arc4random_buf (BSD 라이브러리)
 *          - Linux/Unix: /dev/urandom (시스템 엔트로피)
 *          IV/nonce 생성에 사용 (매번 다른 값이 필요)
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
 * @brief 고정밀도 타이머 (초 단위)
 * @return 현재 시간 (초, double)
 * @details 성능 측정에 사용하는 고정밀도 타이머
 *          - Windows: QueryPerformanceCounter (마이크로초 정밀도)
 *          - Linux/Unix: clock_gettime (나노초 정밀도)
 *          벤치마크에서 경과 시간을 측정할 때 사용
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
 * @brief 바이트 배열을 16진수 문자열로 출력
 * @param p 바이트 배열 포인터
 * @param n 배열 길이
 * @details 각 바이트를 2자리 대문자 16진수로 출력 (예: "A1B2C3")
 *          암호문을 표시할 때 사용
 */
static void hex_print(const uint8_t* p, size_t n) {
    for (size_t i=0; i<n; ++i) printf("%02X", p[i]);
}

/**
 * @brief 사용자로부터 패딩 방식 입력받기
 * @return 선택된 패딩 방식
 * @details 대화형으로 패딩 방식을 선택받습니다:
 *          [1] PKCS#7 (권장)
 *          [2] ANSI X9.23
 *          [0] NONE (길이가 16의 배수여야 함)
 */
static AESPadding ask_padding(void) {
    char line[16]={0};
    printf("패딩 선택: [1] PKCS#7 (권장), [2] ANSI X9.23, [0] NONE: ");
    if (!fgets(line, sizeof(line), stdin)) return AES_PADDING_PKCS7;
    int k = atoi(line);
    if (k==2) return AES_PADDING_ANSI_X923;
    if (k==0) return AES_PADDING_NONE; // 주: NONE이면 길이가 16의 배수여야 함
    return AES_PADDING_PKCS7;
}

/**
 * @brief 메인 함수 - AES 테스트 및 벤치마크
 * @return 0 성공, 1 실패
 * @details 
 * 프로그램 흐름:
 * 1. 콘솔 인코딩 설정 (Windows UTF-8)
 * 2. 사용자 입력 받기 (평문)
 * 3. AES 버전 선택 (현재는 #1만 지원)
 * 4. 운용 모드 선택 (CTR/CBC/ECB)
 * 5. 패딩 방식 선택 (CBC/ECB만)
 * 6. AES 초기화
 * 7. 암호화/복호화 수행 및 결과 출력
 * 8. 성능 벤치마크 (10MB 데이터 처리)
 */
int main(void) {
    // Windows에서 UTF-8 콘솔 인코딩 설정
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);  // 콘솔 출력 UTF-8
    SetConsoleCP(CP_UTF8);        // 콘솔 입력 UTF-8
    setlocale(LC_ALL, ".UTF-8");  // C 런타임 로케일
    #endif
    
    // ─────────────────────────────────────────────────────────────────────
    // 1단계: 사용자 입력 받기
    // ─────────────────────────────────────────────────────────────────────
    char msg[4096];            // 평문 입력 버퍼 (최대 4096바이트)
    char line[32]={0};        // 메뉴 선택 입력 버퍼

    printf("평문을 입력하세요: ");
    if (!fgets(msg, sizeof(msg), stdin)) { 
        fprintf(stderr,"입력 오류\n"); 
        return 1; 
    }
    size_t msg_len = strlen(msg);
    // 개행 문자 제거
    if (msg_len && msg[msg_len-1]=='\n') msg[--msg_len]='\0';

    // ─────────────────────────────────────────────────────────────────────
    // 2단계: AES 버전 선택 (현재는 #1만 지원)
    // ─────────────────────────────────────────────────────────────────────
    printf("[1] AES #1 (속도형)\n[2] AES #2 (보안형)\n선택 (1/2): ");
    if (!fgets(line, sizeof(line), stdin)) { 
        fprintf(stderr,"입력 오류\n"); 
        return 1; 
    }
    int ver = atoi(line);
    if (ver==2) { 
        printf("AES #2는 아직 개발중입니다!\n"); 
        return 0; 
    }
    if (ver!=1) { 
        printf("잘못된 선택입니다.\n"); 
        return 0; 
    }

    // ─────────────────────────────────────────────────────────────────────
    // 3단계: 운용 모드 선택
    // ─────────────────────────────────────────────────────────────────────
    printf("운용모드 선택: [1] CTR  [2] CBC  [3] ECB : ");
    if (!fgets(line, sizeof(line), stdin)) { 
        fprintf(stderr,"입력 오류\n"); 
        return 1; 
    }
    int mode = atoi(line);

    // ─────────────────────────────────────────────────────────────────────
    // 4단계: 패딩 방식 선택 (CBC/ECB만 필요)
    // ─────────────────────────────────────────────────────────────────────
    AESPadding padding = AES_PADDING_NONE;
    if (mode==2 || mode==3) {  // CBC/ECB는 패딩 필요 (또는 길이 16의 배수)
        padding = ask_padding();
        // 패딩 NONE이면 길이가 16의 배수여야 함
        if (padding==AES_PADDING_NONE && (msg_len % 16)!=0) {
            printf("※ 패딩 NONE은 평문 길이가 16의 배수여야 합니다. PKCS#7로 자동 변경합니다.\n");
            padding = AES_PADDING_PKCS7;
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // 5단계: AES 컨텍스트 초기화
    // ─────────────────────────────────────────────────────────────────────
    AES_ctx ctx;
    uint8_t key[16] = {0};  // ⚠️ 데모용 키 (실전에서는 절대 사용 금지!)
                             // 실제 사용 시: 사용자 키 입력 또는 랜덤 키 생성 필요
    if (AES_init(&ctx, key, AES128)!=AES_OK) { 
        fprintf(stderr,"AES_init 실패\n"); 
        return 1; 
    }

    // ─────────────────────────────────────────────────────────────────────
    // 6단계: 암호화/복호화 수행
    // ─────────────────────────────────────────────────────────────────────
    uint8_t *ct = NULL, *pt = NULL;  // 암호문(ciphertext), 평문(plaintext) 버퍼
    size_t out_len = 0, back_len = 0;  // 출력 길이
    AESStatus st;  // AES 함수 반환 상태

    if (mode==1) {
        // ───── CTR 모드 (패딩 불필요) ─────
        uint8_t iv[16];  // 초기 nonce+카운터
        if (rand_bytes(iv, sizeof(iv))!=0) { 
            fprintf(stderr,"난수 생성 실패\n"); 
            return 1; 
        }

        // CTR 모드는 패딩이 필요 없으므로 입력 길이 그대로 사용
        ct = (uint8_t*)malloc(msg_len?msg_len:1);  // 최소 1바이트 할당
        pt = (uint8_t*)malloc(msg_len?msg_len:1);
        if (!ct || !pt) { 
            fprintf(stderr,"메모리 할당 실패\n"); 
            return 1; 
        }

        // 암호화: IV 복사하여 사용 (IV는 업데이트되므로)
        uint8_t iv_work[16];
        memcpy(iv_work, iv, 16);
        st = AES_cryptCTR(&ctx, (const uint8_t*)msg, msg_len, ct, iv_work);
        if (st!=AES_OK) { 
            fprintf(stderr,"CTR 암호화 실패: %s\n", AES_strerror(st)); 
            return 1; 
        }

        // 복호화: 원본 IV로 복원하여 복호화 (CTR은 대칭적으로 동작)
        memcpy(iv_work, iv, 16);
        st = AES_cryptCTR(&ctx, ct, msg_len, pt, iv_work);
        if (st!=AES_OK) { 
            fprintf(stderr,"CTR 복호화 실패: %s\n", AES_strerror(st)); 
            return 1; 
        }
        back_len = msg_len;  // CTR은 길이 변화 없음

        // 결과 출력
        printf("\n[CTR] 암호문(hex, 앞 64B): ");
        hex_print(ct, msg_len<64?msg_len:64);
        if (msg_len>64) printf("... (+%zu bytes)", msg_len-64);
        printf("\n복호화 확인: %s\n", 
               (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"✅ 성공":"❌ 실패");

    } else if (mode==2) {
        // ───── CBC 모드 ─────
        uint8_t iv_enc[16], iv_dec[16];  // 암호화용 IV, 복호화용 IV (복호화 시 원본 IV 필요)
        if (rand_bytes(iv_enc, sizeof(iv_enc))!=0) { 
            fprintf(stderr,"난수 생성 실패\n"); 
            return 1; 
        }
        memcpy(iv_dec, iv_enc, 16);  // 복호화 시 원본 IV 사용

        // 출력 버퍼 (패딩 포함 최대 +16바이트)
        ct = (uint8_t*)malloc(msg_len + 16);
        pt = (uint8_t*)malloc(msg_len + 16);
        if (!ct || !pt) { 
            fprintf(stderr,"메모리 할당 실패\n"); 
            return 1; 
        }

        // 암호화: 패딩 자동 적용
        st = AES_encryptCBC(&ctx, (const uint8_t*)msg, msg_len, ct, msg_len+16, &out_len, iv_enc, padding);
        if (st!=AES_OK) { 
            fprintf(stderr,"CBC 암호화 실패: %s\n", AES_strerror(st)); 
            return 1; 
        }

        // 복호화: 원본 IV 사용, 패딩 자동 제거
        st = AES_decryptCBC(&ctx, ct, out_len, pt, msg_len+16, &back_len, iv_dec, padding);
        if (st!=AES_OK) { 
            fprintf(stderr,"CBC 복호화 실패: %s\n", AES_strerror(st)); 
            return 1; 
        }

        // 결과 출력
        printf("\n[CBC] 암호문(hex, 앞 64B): ");
        hex_print(ct, out_len<64?out_len:64);
        if (out_len>64) printf("... (+%zu bytes)", out_len-64);
        printf("\n복호화 확인: %s (원문길이=%zu)\n",
               (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"✅ 성공":"❌ 실패", back_len);

    } else if (mode==3) {
        // ───── ECB 모드 (⚠️ 테스트/교육용만, 실무 사용 금지) ─────
        ct = (uint8_t*)malloc(msg_len + 16);
        pt = (uint8_t*)malloc(msg_len + 16);
        if (!ct || !pt) { 
            fprintf(stderr,"메모리 할당 실패\n"); 
            return 1; 
        }

        // 암호화: 패딩 자동 적용
        st = AES_encryptECB(&ctx, (const uint8_t*)msg, msg_len, ct, msg_len+16, &out_len, padding);
        if (st!=AES_OK) { 
            fprintf(stderr,"ECB 암호화 실패: %s\n", AES_strerror(st)); 
            return 1; 
        }

        // 복호화: 패딩 자동 제거
        st = AES_decryptECB(&ctx, ct, out_len, pt, msg_len+16, &back_len, padding);
        if (st!=AES_OK) { 
            fprintf(stderr,"ECB 복호화 실패: %s\n", AES_strerror(st)); 
            return 1; 
        }

        // 결과 출력
        printf("\n[ECB] (⚠️ 테스트용) 암호문(hex, 앞 64B): ");
        hex_print(ct, out_len<64?out_len:64);
        if (out_len>64) printf("... (+%zu bytes)", out_len-64);
        printf("\n복호화 확인: %s (원문길이=%zu)\n",
               (back_len==msg_len && memcmp(pt,msg,msg_len)==0)?"✅ 성공":"❌ 실패", back_len);
    } else {
        printf("잘못된 모드 선택입니다.\n");
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────
    // 7단계: 성능 벤치마크 (10MB 데이터 처리 시간 측정)
    // ─────────────────────────────────────────────────────────────────────
    const size_t TEN_MB = 10u * 1024u * 1024u;  // 10MB = 10 * 1024 * 1024 바이트
    uint8_t* bin  = (uint8_t*)malloc(TEN_MB + 16);   // 입력 버퍼 (패딩 여유 공간 포함)
    uint8_t* bout = (uint8_t*)malloc(TEN_MB + 32);   // 출력 버퍼 (여유 공간 포함)
    if (!bin || !bout) { 
        fprintf(stderr,"벤치마크 버퍼 메모리 할당 실패\n"); 
        return 1; 
    }
    memset(bin, 0, TEN_MB);  // 테스트 데이터 초기화 (0으로 채움)

    // 성능 측정 변수
    double t0, t1;  // 시작 시간, 종료 시간
    AESStatus bst;  // 벤치마크 상태
    
    // 선택된 모드에 따라 벤치마크 수행
    if (mode==1) {
        // CTR 모드 벤치마크
        uint8_t iv_bench[16];
        rand_bytes(iv_bench, sizeof(iv_bench));
        t0 = now_seconds();
        bst = AES_cryptCTR(&ctx, bin, TEN_MB, bout, iv_bench);
        t1 = now_seconds();
    } else if (mode==2) {
        // CBC 모드 벤치마크
        uint8_t iv_bench[16];
        rand_bytes(iv_bench, sizeof(iv_bench));
        size_t bout_len=0;
        t0 = now_seconds();
        bst = AES_encryptCBC(&ctx, bin, TEN_MB, bout, TEN_MB+16, &bout_len, iv_bench, AES_PADDING_PKCS7);
        t1 = now_seconds();
    } else {
        // ECB 모드 벤치마크
        size_t bout_len=0;
        t0 = now_seconds();
        bst = AES_encryptECB(&ctx, bin, TEN_MB, bout, TEN_MB+16, &bout_len, AES_PADDING_PKCS7);
        t1 = now_seconds();
    }

    // 벤치마크 결과 출력
    if (bst!=AES_OK) {
        fprintf(stderr,"벤치마크 실패: %s\n", AES_strerror(bst));
    } else {
        double sec = t1 - t0;  // 경과 시간 (초)
        printf("\n[성능 벤치마크] 10MB 암호화 시간: %.6f 초\n", sec);
        if (sec>0.0) {
            double mbps = 10.0 / sec;  // 처리량 (MB/s)
            double gbps_bits = (10.0*8.0) / sec / 1000.0;  // 처리량 (Gbps, 비트 단위)
            printf("처리량: %.2f MB/s (약 %.2f Gbps)\n", mbps, gbps_bits);
        }
    }

    // 메모리 해제
    free(ct); 
    free(pt); 
    free(bin); 
    free(bout);
    
    return 0;
}
