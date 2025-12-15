/* =========================================================================
 * test.c — AES 암호화 통신 시스템
 *
 * 기능:
 *   - [1] 로컬 암호화/복호화 테스트
 *   - [2] 소켓 통신 (서버/클라이언트) - 암호화된 메시지 송수신
 *
 * 빌드 (Windows):
 *   cl /utf-8 /std:c17 /O2 /W4 /D_CRT_SECURE_NO_WARNINGS call.c aes.c crack_aes.c sha512.c ws2_32.lib advapi32.lib
 * Linux / MacOS:
 *   clang -O2 -std=c17 call.c aes.c crack_aes.c sha512.c -pthread -o call
 * ------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "aes.h"
#include "crack_aes.h"

#ifdef _WIN32
    /* Winsock2를 windows.h보다 먼저 포함해야 충돌 방지 */
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <wincrypt.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "advapi32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>       // gethostbyname, gethostname
    #include <pthread.h>     // pthread 스레드/뮤텍스
    #include <sys/time.h>    // struct timeval
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

#ifndef _WIN32
#include <fcntl.h>  // ← 논블로킹 stdin 위해 추가
#endif

#ifdef _WIN32
    #define LOCK_PRINT()   EnterCriticalSection(&g_print_lock)
    #define UNLOCK_PRINT() LeaveCriticalSection(&g_print_lock)
#else
    #define LOCK_PRINT()   pthread_mutex_lock(&g_print_lock)
    #define UNLOCK_PRINT() pthread_mutex_unlock(&g_print_lock)
#endif

#define DEFAULT_PORT 12345
#define BUFFER_SIZE 4096

/* --------------------------------------------------------------------------
 * 스레드 기반 양방향 통신을 위한 전역 변수 및 구조체
 * -------------------------------------------------------------------------- */
static volatile int g_running = 1;            /* 통신 종료 플래그 */
static SOCKET g_comm_socket = INVALID_SOCKET; /* 현재 통신 중인 소켓 */

#ifdef _WIN32
static CRITICAL_SECTION g_print_lock;
#else
static pthread_mutex_t g_print_lock;
#endif


/* 암호화 모드 선택 */
typedef enum {
    CRYPTO_AES1_CTR = 1,
    CRYPTO_AES1_ECB = 2,
    CRYPTO_AES1_CBC = 3,
    CRYPTO_CRACK_AES = 4
} CryptoMode;

static CryptoMode g_crypto_mode = CRYPTO_CRACK_AES;  /* 기본값: CRACK_AES */
static AESPadding g_padding_mode = AES_PADDING_PKCS7;  /* 기본값: PKCS7 */

/* 통신용 고정 키/IV (데모용) */
static const uint8_t g_comm_key[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

/* 랜덤 바이트 생성 (Windows) */
static void generate_random_bytes(uint8_t* buf, size_t len) { /* 랜덤 바이트 생성 */
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, (DWORD)len, buf);
        CryptReleaseContext(hProv, 0);
    } else {
        /* 폴백: 시간 기반 랜덤 (암호학적으로 안전하지 않음) */
        srand((unsigned int)time(NULL) ^ (unsigned int)GetTickCount());
        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)(rand() & 0xFF);
        }
    }
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    }
#endif
}

/* 전방 선언 */
static int recv_encrypted_message(SOCKET sock, char* plaintext, size_t max_len, size_t* out_len); /* 암호화된 메시지 수신 */

#ifdef _WIN32
typedef DWORD THREAD_RET;
#define THREAD_CALLCONV WINAPI
typedef LPVOID THREAD_ARG;
#else
typedef void* THREAD_RET;
#define THREAD_CALLCONV
typedef void* THREAD_ARG;
#endif

/* 수신 스레드 함수 */
static THREAD_RET THREAD_CALLCONV receive_thread(THREAD_ARG param) { /* 수신 스레드 함수 */
    (void)param;
    char received[2048];
    size_t recv_len;

    while (g_running) {
        fd_set read_fds;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  /* 100ms */

        FD_ZERO(&read_fds);
        FD_SET(g_comm_socket, &read_fds);

        int sel = select((int)g_comm_socket + 1, &read_fds, NULL, NULL, &tv);
        if (sel > 0 && FD_ISSET(g_comm_socket, &read_fds)) {
            if (recv_encrypted_message(g_comm_socket, received, sizeof(received)-1, &recv_len) == 0) {
                LOCK_PRINT();
                printf("\n[상대방]: %s\n[나] > ", received);
                fflush(stdout);
                UNLOCK_PRINT();
            } else {
                /* 연결 종료 감지 */
                LOCK_PRINT();
                printf("\n[알림] 상대방이 연결을 종료했습니다.\n");
                fflush(stdout);
                UNLOCK_PRINT();
                g_running = 0;
                break;
            }
        }
    }

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}


/* --------------------------------------------------------------------------
 * Windows UTF-8 콘솔 입력 헬퍼 함수
 * -------------------------------------------------------------------------- */
#ifdef _WIN32
static int read_utf8_line(char* buf, size_t buf_size) { /* UTF-8 콘솔 입력 헬퍼 함수 */
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn == INVALID_HANDLE_VALUE) {
        buf[0] = '\0';
        return 0;
    }

    wchar_t wbuf[2048];
    DWORD wchars_read = 0;

    if (!ReadConsoleW(hIn, wbuf, (DWORD)(sizeof(wbuf)/sizeof(wchar_t) - 1), &wchars_read, NULL)) {
        buf[0] = '\0';
        return 0;
    }
    wbuf[wchars_read] = L'\0';

    // 줄바꿈 제거
    if (wchars_read > 0 && wbuf[wchars_read - 1] == L'\n') wbuf[--wchars_read] = L'\0';
    if (wchars_read > 0 && wbuf[wchars_read - 1] == L'\r') wbuf[--wchars_read] = L'\0';

    // UTF-16 → UTF-8 변환
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, (int)buf_size, NULL, NULL);
    if (utf8_len <= 0) {
        buf[0] = '\0';
        return 0;
    }

    return (int)strlen(buf);
}
#else
static int read_utf8_line(char* buf, size_t buf_size) { /* UTF-8 콘솔 입력 헬퍼 함수 */
    if (!fgets(buf, (int)buf_size, stdin)) {
        buf[0] = '\0';
        return 0;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';
    return (int)len;
}
#endif
#include "sha512.h"

#define BENCH_SIZE (10u * 1024u * 1024u) /* 10 MiB */

static void print_hex(const char* label, const uint8_t* buf, size_t len) { /* 바이너리 데이터를 16진수로 출력 */
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

static const char* aes_status_str(AESStatus st) { /* AES 상태 코드를 문자열로 변환 */
    switch (st) {
    case AES_OK:            return "AES_OK";
    case AES_ERR_BAD_PARAM: return "AES_ERR_BAD_PARAM";
    case AES_ERR_BUF_SMALL: return "AES_ERR_BUF_SMALL";
    case AES_ERR_PADDING:   return "AES_ERR_PADDING";
    case AES_ERR_OVERLAP:   return "AES_ERR_OVERLAP";
    case AES_ERR_STATE:     return "AES_ERR_STATE";
    case AES_ERR_LENGTH:    return "AES_ERR_LENGTH";
#ifdef AES_ERR_AUTH
#pragma warning(push)
#pragma warning(disable: 4063)  /* case 값이 열거형에 없을 수 있음 (조건부 정의) */
    case AES_ERR_AUTH:      return "AES_ERR_AUTH";
#pragma warning(pop)
#endif
    default:                return "AES_ERR_UNKNOWN";
    }
}

static double now_seconds(void) { /* 현재 시간을 초 단위로 반환 */
    return (double)clock() / (double)CLOCKS_PER_SEC;
}

/* 공통 데모용 키 (AES-256) */
static const uint8_t DEMO_KEY256[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};

/* --------------------------------------------------------------------------
 * AES1 — CTR 암호화 (시스템용)
 * -------------------------------------------------------------------------- */

static void aes1_ctr_encrypt(const uint8_t* msg, size_t msg_len) { /* AES1 CTR 모드 암호화 */
    printf("\n========================================\n");
    printf(" [AES1-CTR] 암호화\n");
    printf("========================================\n");

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[오류] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    uint8_t nonce[16];
    uint8_t ct[2048];
    
    if (msg_len > sizeof(ct)) {
        printf("[오류] 평문이 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    /* 랜덤 nonce 생성 */
    if (CRACK_AES_rand_bytes(nonce, sizeof(nonce)) != AES_OK) {
        memset(nonce, 0, sizeof(nonce));  /* 실패 시 0으로 초기화 */
    }

    uint8_t ctr[16];
    memcpy(ctr, nonce, 16);

    st = AES_cryptCTR(&ctx, msg, msg_len, ct, ctr);
    if (st != AES_OK) {
        printf("[오류] 암호화 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 전송할 정보 출력 */
    printf("\n[전송 정보]\n");
    print_hex("Nonce", nonce, 16);
    print_hex("암호문", ct, msg_len);
}

/* --------------------------------------------------------------------------
 * 패딩 선택 헬퍼 함수
 * -------------------------------------------------------------------------- */

static const char* padding_name(AESPadding pad) { /* 패딩 타입을 문자열로 변환 */
    switch (pad) {
        case AES_PADDING_NONE:      return "NONE (16바이트 배수 필수)";
        case AES_PADDING_PKCS7:     return "PKCS#7";
        case AES_PADDING_ANSI_X923: return "ANSI X9.23";
        default:                    return "UNKNOWN";
    }
}

static AESPadding select_padding(void) {
    printf("\n패딩 방식을 선택하세요:\n");
    printf("  [1] PKCS#7 (권장, 표준)\n");
    printf("  [2] ANSI X9.23\n");
    printf("  [3] NONE (입력이 16바이트 배수일 때만)\n");
    printf("선택: ");
    fflush(stdout);

    char buf[16];
#ifdef _WIN32
    read_utf8_line(buf, sizeof(buf));
#else
    if (!fgets(buf, sizeof(buf), stdin)) {
        return AES_PADDING_PKCS7;  // 기본값
    }
#endif

    int choice = atoi(buf);
    switch (choice) {
        case 1:  return AES_PADDING_PKCS7;
        case 2:  return AES_PADDING_ANSI_X923;
        case 3:  return AES_PADDING_NONE;
        default:
            printf("잘못된 선택. 기본값 PKCS#7 사용.\n");
            return AES_PADDING_PKCS7;
    }
}

/* --------------------------------------------------------------------------
 * AES1 — ECB 암호화 (시스템용)
 * -------------------------------------------------------------------------- */

static void aes1_ecb_encrypt(const uint8_t* msg, size_t msg_len) { /* AES1 ECB 모드 암호화 */
    printf("\n========================================\n");
    printf(" [AES1-ECB] 암호화\n");
    printf("========================================\n");

    /* 패딩 선택 */
    AESPadding padding = select_padding();

    /* NONE 패딩 선택 시 16바이트 배수 검사 */
    if (padding == AES_PADDING_NONE && (msg_len % 16) != 0) {
        printf("[오류] NONE 패딩은 입력이 16바이트 배수여야 합니다. (현재 %zu바이트)\n", msg_len);
        return;
    }

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[오류] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    uint8_t ct[2048];
    size_t ct_len = 0;

    if (msg_len > sizeof(ct)) {
        printf("[오류] 평문이 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    st = AES_encryptECB(&ctx, msg, msg_len, ct, sizeof(ct), &ct_len, padding);
    if (st != AES_OK) {
        printf("[오류] 암호화 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 전송할 정보 출력 */
    printf("\n[전송 정보]\n");
    printf("패딩: %s\n", padding_name(padding));
    print_hex("암호문", ct, ct_len);
}

/* --------------------------------------------------------------------------
 * AES1 — CBC 암호화 (시스템용)
 * -------------------------------------------------------------------------- */

static void aes1_cbc_encrypt(const uint8_t* msg, size_t msg_len) { /* AES1 CBC 모드 암호화 */
    printf("\n========================================\n");
    printf(" [AES1-CBC] 암호화\n");
    printf("========================================\n");

    /* 패딩 선택 */
    AESPadding padding = select_padding();

    /* NONE 패딩 선택 시 16바이트 배수 검사 */
    if (padding == AES_PADDING_NONE && (msg_len % 16) != 0) {
        printf("[오류] NONE 패딩은 입력이 16바이트 배수여야 합니다. (현재 %zu바이트)\n", msg_len);
        return;
    }

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[오류] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    uint8_t ct[2048];
    size_t ct_len = 0;

    if (msg_len > sizeof(ct)) {
        printf("[오류] 평문이 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    uint8_t iv[16];

    /* 랜덤 IV 생성 */
    if (CRACK_AES_rand_bytes(iv, sizeof(iv)) != AES_OK) {
        memset(iv, 0, sizeof(iv));
    }

    uint8_t iv_for_enc[16];
    memcpy(iv_for_enc, iv, 16);

    st = AES_encryptCBC(&ctx, msg, msg_len, ct, sizeof(ct), &ct_len, iv_for_enc, padding);
    if (st != AES_OK) {
        printf("[오류] 암호화 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 전송할 정보 출력 */
    printf("\n[전송 정보]\n");
    printf("패딩: %s\n", padding_name(padding));
    print_hex("IV", iv, 16);
    print_hex("암호문", ct, ct_len);
}

/* --------------------------------------------------------------------------
 * CRACK_AES(보안형) — 암호화 (시스템용)
 * -------------------------------------------------------------------------- */

static void crack_aes_encrypt(const uint8_t* msg, size_t msg_len) { /* CRACK_AES 보안형 암호화 */
    printf("\n========================================\n");
    printf(" [CRACK_AES] 보안형 암호화 (CTR + HMAC)\n");
    printf("========================================\n");

    /* 마스터 키 / KDF 파라미터 */
    static const uint8_t master_key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    static const uint8_t salt[] = "CRACK_AES-demo-salt";
    static const uint8_t info[] = "CRACK_AES-demo-info";

    CRACK_AES_KDFParams kdf = {
        salt, sizeof(salt) - 1,
        info, sizeof(info) - 1
    };

    CRACK_AES_SecCtx ctx;
    AESStatus st = CRACK_AES_init_hardened(&ctx,
                                      master_key, AES256,
                                      &kdf,
                                      CRACK_AES_F_MAC_ENABLE | CRACK_AES_F_NONCE_GUARD,
                                      CRACK_AES_TagLen_32);

    if (st != AES_OK) {
        printf("[오류] CRACK_AES_init_hardened 실패: %s\n", aes_status_str(st));
        return;
    }

    uint8_t nonce[16];
    uint8_t ct[2048];
    uint8_t tag[32];
    size_t  ct_len = 0;
    size_t  tag_len = 0;

    if (msg_len > sizeof(ct)) {
        printf("[오류] 평문이 버퍼(2048바이트)를 초과합니다.\n");
        return;
    }

    st = CRACK_AES_seal_CTR_autoIV(&ctx,
                              (const uint8_t*)"AAD", 3,
                              nonce,
                              msg, msg_len,
                              ct, sizeof(ct), &ct_len,
                              tag, sizeof(tag), &tag_len);
    if (st != AES_OK) {
        printf("[오류] 암호화 실패: %s\n", aes_status_str(st));
        return;
    }

    /* 전송할 정보 출력 */
    printf("\n[전송 정보]\n");
    print_hex("Nonce", nonce, 16);
    print_hex("암호문", ct, ct_len);
    print_hex("Tag", tag, tag_len);
}

/* --------------------------------------------------------------------------
 * Hex 문자열 → 바이트 배열 변환
 * -------------------------------------------------------------------------- */
static int hex_to_bytes(const char* hex, uint8_t* out, size_t out_cap, size_t* out_len) { /* 16진수 문자열을 바이트 배열로 변환 */
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;  /* 짝수 길이여야 함 */
    
    size_t byte_len = hex_len / 2;
    if (byte_len > out_cap) return -1;
    
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int val;
        if (sscanf(hex + 2*i, "%2x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    *out_len = byte_len;
    return 0;
}

/* --------------------------------------------------------------------------
 * AES1 복호화 전용 함수들
 * -------------------------------------------------------------------------- */
static void aes1_ecb_decrypt_only(void) { /* AES1 ECB 모드 복호화 전용 함수 */
    printf("\n========================================\n");
    printf(" [AES1] ECB 복호화\n");
    printf("========================================\n");

    /* 패딩 선택 */
    AESPadding padding = select_padding();
    printf("[AES1-ECB] 선택된 패딩: %s\n", padding_name(padding));

    /* 암호문 입력 (hex) */
    char hex_input[4096];
    printf("\n암호문을 HEX로 입력하세요:\n> ");
    fflush(stdout);
    if (read_utf8_line(hex_input, sizeof(hex_input)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t ct[2048];
    size_t ct_len = 0;
    if (hex_to_bytes(hex_input, ct, sizeof(ct), &ct_len) != 0) {
        printf("잘못된 HEX 형식입니다.\n");
        return;
    }

    if (ct_len % 16 != 0) {
        printf("오류: 암호문 길이가 16바이트 배수가 아닙니다. (%zu바이트)\n", ct_len);
        return;
    }

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[AES1-ECB] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    uint8_t dec[2048];
    size_t dec_len = 0;

    st = AES_decryptECB(&ctx, ct, ct_len, dec, sizeof(dec), &dec_len, padding);
    if (st != AES_OK) {
        printf("[AES1-ECB] AES_decryptECB 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES1-ECB] 복호화 결과 (%zu bytes): \"%.*s\"\n", dec_len, (int)dec_len, dec);
    print_hex("[AES1-ECB] 복호화 결과 (hex)", dec, dec_len);
}

static void aes1_cbc_decrypt_only(void) { /* AES1 CBC 모드 복호화 전용 함수 */
    printf("\n========================================\n");
    printf(" [AES1] CBC 복호화\n");
    printf("========================================\n");

    /* 패딩 선택 */
    AESPadding padding = select_padding();
    printf("[AES1-CBC] 선택된 패딩: %s\n", padding_name(padding));

    /* IV 입력 (hex) */
    char iv_hex[64];
    printf("\nIV를 HEX로 입력하세요 (32자 = 16바이트):\n> ");
    fflush(stdout);
    if (read_utf8_line(iv_hex, sizeof(iv_hex)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t iv[16];
    size_t iv_len = 0;
    if (hex_to_bytes(iv_hex, iv, sizeof(iv), &iv_len) != 0 || iv_len != 16) {
        printf("잘못된 IV입니다. 32자리 HEX여야 합니다.\n");
        return;
    }

    /* 암호문 입력 (hex) */
    char hex_input[4096];
    printf("\n암호문을 HEX로 입력하세요:\n> ");
    fflush(stdout);
    if (read_utf8_line(hex_input, sizeof(hex_input)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t ct[2048];
    size_t ct_len = 0;
    if (hex_to_bytes(hex_input, ct, sizeof(ct), &ct_len) != 0) {
        printf("잘못된 HEX 형식입니다.\n");
        return;
    }

    if (ct_len % 16 != 0) {
        printf("오류: 암호문 길이가 16바이트 배수가 아닙니다. (%zu바이트)\n", ct_len);
        return;
    }

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[AES1-CBC] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    uint8_t dec[2048];
    size_t dec_len = 0;

    st = AES_decryptCBC(&ctx, ct, ct_len, dec, sizeof(dec), &dec_len, iv, padding);
    if (st != AES_OK) {
        printf("[AES1-CBC] AES_decryptCBC 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES1-CBC] 복호화 결과 (%zu bytes): \"%.*s\"\n", dec_len, (int)dec_len, dec);
    print_hex("[AES1-CBC] 복호화 결과 (hex)", dec, dec_len);
}

static void aes1_ctr_decrypt_only(void) { /* AES1 CTR 모드 복호화 전용 함수 */
    printf("\n========================================\n");
    printf(" [AES1] CTR 복호화\n");
    printf("========================================\n");

    /* Nonce 입력 (hex) */
    char nonce_hex[64];
    printf("\nNonce를 HEX로 입력하세요 (32자 = 16바이트):\n> ");
    fflush(stdout);
    if (read_utf8_line(nonce_hex, sizeof(nonce_hex)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t nonce[16];
    size_t nonce_len = 0;
    if (hex_to_bytes(nonce_hex, nonce, sizeof(nonce), &nonce_len) != 0 || nonce_len != 16) {
        printf("잘못된 Nonce입니다. 32자리 HEX여야 합니다.\n");
        return;
    }

    /* 암호문 입력 (hex) */
    char hex_input[4096];
    printf("\n암호문을 HEX로 입력하세요:\n> ");
    fflush(stdout);
    if (read_utf8_line(hex_input, sizeof(hex_input)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t ct[2048];
    size_t ct_len = 0;
    if (hex_to_bytes(hex_input, ct, sizeof(ct), &ct_len) != 0) {
        printf("잘못된 HEX 형식입니다.\n");
        return;
    }

    AES_ctx ctx;
    AESStatus st = AES_init(&ctx, DEMO_KEY256, AES256);
    if (st != AES_OK) {
        printf("[AES1-CTR] AES_init 실패: %s\n", aes_status_str(st));
        return;
    }

    uint8_t dec[2048];
    st = AES_cryptCTR(&ctx, ct, ct_len, dec, nonce);
    if (st != AES_OK) {
        printf("[AES1-CTR] AES_cryptCTR 실패: %s\n", aes_status_str(st));
        return;
    }

    printf("[AES1-CTR] 복호화 결과 (%zu bytes): \"%.*s\"\n", ct_len, (int)ct_len, dec);
    print_hex("[AES1-CTR] 복호화 결과 (hex)", dec, ct_len);
}

/* --------------------------------------------------------------------------
 * CRACK_AES 복호화 전용 함수 (CTR + HMAC 검증)
 * -------------------------------------------------------------------------- */
static void crack_aes_decrypt_only(void) { /* CRACK_AES 복호화 전용 함수 */
    printf("\n=================================================\n");
    printf(" [CRACK_AES] 보안형 복호화 (CTR + HMAC 검증)\n");
    printf("=================================================\n");

    /* 마스터 키 / KDF 파라미터 (암호화와 동일해야 함) */
    static const uint8_t master_key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    static const uint8_t salt[] = "CRACK_AES-demo-salt";
    static const uint8_t info[] = "CRACK_AES-demo-info";

    CRACK_AES_KDFParams kdf = {
        salt, sizeof(salt) - 1,
        info, sizeof(info) - 1
    };

    CRACK_AES_SecCtx ctx;
    AESStatus st = CRACK_AES_init_hardened(&ctx,
                                      master_key, AES256,
                                      &kdf,
                                      CRACK_AES_F_MAC_ENABLE | CRACK_AES_F_NONCE_GUARD,
                                      CRACK_AES_TagLen_32);
    if (st != AES_OK) {
        printf("[CRACK_AES] CRACK_AES_init_hardened 실패: %s\n", aes_status_str(st));
        return;
    }

    /* Nonce 입력 (hex) */
    char nonce_hex[64];
    printf("\nNonce를 HEX로 입력하세요 (32자 = 16바이트):\n> ");
    fflush(stdout);
    if (read_utf8_line(nonce_hex, sizeof(nonce_hex)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t nonce[16];
    size_t nonce_len = 0;
    if (hex_to_bytes(nonce_hex, nonce, sizeof(nonce), &nonce_len) != 0 || nonce_len != 16) {
        printf("잘못된 Nonce입니다. 32자리 HEX여야 합니다.\n");
        return;
    }

    /* 암호문 입력 (hex) */
    char ct_hex[4096];
    printf("\n암호문을 HEX로 입력하세요:\n> ");
    fflush(stdout);
    if (read_utf8_line(ct_hex, sizeof(ct_hex)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t ct[2048];
    size_t ct_len = 0;
    if (hex_to_bytes(ct_hex, ct, sizeof(ct), &ct_len) != 0) {
        printf("잘못된 HEX 형식입니다.\n");
        return;
    }

    /* Tag 입력 (hex) */
    char tag_hex[128];
    printf("\nTag를 HEX로 입력하세요 (64자 = 32바이트):\n> ");
    fflush(stdout);
    if (read_utf8_line(tag_hex, sizeof(tag_hex)) <= 0) {
        printf("입력 오류.\n");
        return;
    }

    uint8_t tag[32];
    size_t tag_len = 0;
    if (hex_to_bytes(tag_hex, tag, sizeof(tag), &tag_len) != 0 || tag_len != 32) {
        printf("잘못된 Tag입니다. 64자리 HEX여야 합니다.\n");
        return;
    }

    /* 복호화 + 태그 검증 */
    uint8_t dec[2048];
    size_t dec_len = 0;

    st = CRACK_AES_open_CTR_autoIV(&ctx,
                              (const uint8_t*)"AAD", 3,
                              nonce,
                              ct, ct_len,
                              tag, tag_len,
                              dec, sizeof(dec), &dec_len);
    if (st != AES_OK) {
        printf("[CRACK_AES] 복호화 실패: %s\n", aes_status_str(st));
        if (st == AES_ERR_AUTH) {
            printf("[CRACK_AES] ⚠️ 태그 검증 실패! 암호문이 변조되었거나 키/nonce가 다릅니다.\n");
        }
        return;
    }

    printf("[CRACK_AES] 복호화 결과 (%zu bytes): \"%.*s\"\n", dec_len, (int)dec_len, dec);
    print_hex("[CRACK_AES] 복호화 결과 (hex)", dec, dec_len);
}

/* ==========================================================================
 * 소켓 통신 함수들
 * ========================================================================== */

/* Winsock 초기화 */
static int init_socket(void) { /* 소켓 초기화 */
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[오류] Winsock 초기화 실패.\n");
        return -1;
    }
#endif
    return 0;
}

/* Winsock 정리 */
static void cleanup_socket(void) { /* 소켓 정리 */
#ifdef _WIN32
    WSACleanup();
#endif
}

/* 암호화 방식 선택 메뉴 */
static void select_crypto_mode(void) { /* 암호화 모드 선택 */
    char buf[64];
    
    printf("\n========================================\n");
    printf(" 암호화 방식을 선택하세요\n");
    printf("========================================\n");
    printf(" [1] AES1-CTR (스트림 모드)\n");
    printf(" [2] AES1-ECB (블록 모드, 패딩 필요)\n");
    printf(" [3] AES1-CBC (블록 모드, IV + 패딩)\n");
    printf(" [4] CRACK_AES (보안형: CTR + HMAC-SHA512)\n");
    printf("========================================\n");
    printf("선택 (기본값 4): ");
    fflush(stdout);
    
    if (read_utf8_line(buf, sizeof(buf)) > 0) {
        int choice = atoi(buf);
        if (choice >= 1 && choice <= 4) {
            g_crypto_mode = (CryptoMode)choice;
        }
    }
    
    /* ECB/CBC의 경우 패딩 선택 */
    if (g_crypto_mode == CRYPTO_AES1_ECB || g_crypto_mode == CRYPTO_AES1_CBC) {
        printf("\n패딩 모드를 선택하세요:\n");
        printf(" [1] PKCS#7 (권장)\n");
        printf(" [2] ANSI X9.23\n");
        printf("선택 (기본값 1): ");
        fflush(stdout);
        
        if (read_utf8_line(buf, sizeof(buf)) > 0) {
            int pad_choice = atoi(buf);
            if (pad_choice == 2) {
                g_padding_mode = AES_PADDING_ANSI_X923;
            } else {
                g_padding_mode = AES_PADDING_PKCS7;
            }
        }
    }
    
    const char* mode_names[] = {"", "AES1-CTR", "AES1-ECB", "AES1-CBC", "CRACK_AES"};
    printf("\n✓ 선택된 암호화 방식: %s\n", mode_names[g_crypto_mode]);
    if (g_crypto_mode == CRYPTO_AES1_ECB || g_crypto_mode == CRYPTO_AES1_CBC) {
        printf("✓ 선택된 패딩 모드: %s\n", g_padding_mode == AES_PADDING_PKCS7 ? "PKCS#7" : "ANSI X9.23");
    }
    printf("\n");
}

/* 메시지 암호화 후 전송 (선택된 모드에 따라) */
static int send_encrypted_message(SOCKET sock, const char* plaintext, size_t len) { /* 암호화된 메시지 전송 */
    uint8_t packet[BUFFER_SIZE];
    size_t offset = 0;
    
    /* 패킷 첫 바이트: 암호화 모드 */
    packet[offset++] = (uint8_t)g_crypto_mode;
    
    if (g_crypto_mode == CRYPTO_CRACK_AES) {
        /* CRACK_AES 모드 */
        static const uint8_t salt[] = "CRACK_AES-socket-salt";
        static const uint8_t info[] = "CRACK_AES-socket-info";
        
        CRACK_AES_KDFParams kdf = { salt, sizeof(salt)-1, info, sizeof(info)-1 };
        CRACK_AES_SecCtx ctx;
        
        if (CRACK_AES_init_hardened(&ctx, g_comm_key, AES256, &kdf, 
                               CRACK_AES_F_MAC_ENABLE | CRACK_AES_F_NONCE_GUARD,
                               CRACK_AES_TagLen_32) != AES_OK) {
            return -1;
        }
        
        uint8_t nonce[16], ct[BUFFER_SIZE], tag[32];
        size_t ct_len = 0, tag_len = 0;
        
        if (CRACK_AES_seal_CTR_autoIV(&ctx, (const uint8_t*)"AAD", 3, nonce,
                                  (const uint8_t*)plaintext, len,
                                  ct, sizeof(ct), &ct_len,
                                  tag, sizeof(tag), &tag_len) != AES_OK) {
            return -1;
        }
        
        /* 패킷: [mode 1B][nonce 16B][tag 32B][ct_len 4B][ct] */
        memcpy(packet + offset, nonce, 16); offset += 16;
        memcpy(packet + offset, tag, 32); offset += 32;
        uint32_t ct_len32 = (uint32_t)ct_len;
        memcpy(packet + offset, &ct_len32, 4); offset += 4;
        memcpy(packet + offset, ct, ct_len); offset += ct_len;
        
    } else if (g_crypto_mode == CRYPTO_AES1_CTR) {
        /* AES1-CTR 모드 */
        AES_ctx ctx;
        AES_init(&ctx, g_comm_key, AES256);
        
        uint8_t nonce[16], nonce_copy[16], ct[BUFFER_SIZE];
        generate_random_bytes(nonce, 16);
        memcpy(nonce_copy, nonce, 16);  /* 복사본으로 암호화 (원본 보존) */
        
        AES_cryptCTR(&ctx, (const uint8_t*)plaintext, len, ct, nonce_copy);
        
        /* 패킷: [mode 1B][nonce 16B][ct_len 4B][ct] - 원본 nonce 사용 */
        memcpy(packet + offset, nonce, 16); offset += 16;
        uint32_t ct_len32 = (uint32_t)len;
        memcpy(packet + offset, &ct_len32, 4); offset += 4;
        memcpy(packet + offset, ct, len); offset += len;
        
    } else if (g_crypto_mode == CRYPTO_AES1_ECB) {
        /* AES1-ECB 모드 */
        AES_ctx ctx;
        AES_init(&ctx, g_comm_key, AES256);
        
        uint8_t ct[BUFFER_SIZE];
        size_t ct_len = 0;
        if (AES_encryptECB(&ctx, (const uint8_t*)plaintext, len, ct, sizeof(ct), &ct_len, g_padding_mode) != AES_OK) {
            return -1;
        }
        
        /* 패킷: [mode 1B][padding 1B][ct_len 4B][ct] */
        packet[offset++] = (uint8_t)g_padding_mode;
        uint32_t ct_len32 = (uint32_t)ct_len;
        memcpy(packet + offset, &ct_len32, 4); offset += 4;
        memcpy(packet + offset, ct, ct_len); offset += ct_len;
        
    } else if (g_crypto_mode == CRYPTO_AES1_CBC) {
        /* AES1-CBC 모드 */
        AES_ctx ctx;
        AES_init(&ctx, g_comm_key, AES256);
        
        uint8_t iv[16], ct[BUFFER_SIZE];
        size_t ct_len = 0;
        generate_random_bytes(iv, 16);
        
        uint8_t iv_copy[16];
        memcpy(iv_copy, iv, 16);
        if (AES_encryptCBC(&ctx, (const uint8_t*)plaintext, len, ct, sizeof(ct), &ct_len, iv_copy, g_padding_mode) != AES_OK) {
            return -1;
        }
        
        /* 패킷: [mode 1B][padding 1B][iv 16B][ct_len 4B][ct] */
        packet[offset++] = (uint8_t)g_padding_mode;
        memcpy(packet + offset, iv, 16); offset += 16;
        uint32_t ct_len32 = (uint32_t)ct_len;
        memcpy(packet + offset, &ct_len32, 4); offset += 4;
        memcpy(packet + offset, ct, ct_len); offset += ct_len;
    }
    
    if (send(sock, (const char*)packet, (int)offset, 0) == SOCKET_ERROR) {
        return -1;
    }
    
    printf("[송신] 암호화된 메시지 전송 완료 (%zu bytes)\n", offset);
    return 0;
}

/* 암호화된 메시지 수신 후 복호화 (모드 자동 감지) */
static int recv_encrypted_message(SOCKET sock, char* plaintext, size_t max_len, size_t* out_len) { /* 암호화된 메시지 수신 */
    uint8_t packet[BUFFER_SIZE];
    int received = recv(sock, (char*)packet, sizeof(packet), 0);
    if (received <= 0) return -1;
    
    /* 첫 바이트: 암호화 모드 */
    size_t offset = 0;
    CryptoMode mode = (CryptoMode)packet[offset++];
    
    if (mode == CRYPTO_CRACK_AES) {
        /* CRACK_AES 모드 */
        static const uint8_t salt[] = "CRACK_AES-socket-salt";
        static const uint8_t info[] = "CRACK_AES-socket-info";
        
        CRACK_AES_KDFParams kdf = { salt, sizeof(salt)-1, info, sizeof(info)-1 };
        CRACK_AES_SecCtx ctx;
        
        if (CRACK_AES_init_hardened(&ctx, g_comm_key, AES256, &kdf,
                               CRACK_AES_F_MAC_ENABLE | CRACK_AES_F_NONCE_GUARD,
                               CRACK_AES_TagLen_32) != AES_OK) {
            return -1;
        }
        
        uint8_t nonce[16], tag[32];
        uint32_t ct_len32;
        
        if ((size_t)received < offset + 16 + 32 + 4) return -1;
        
        memcpy(nonce, packet + offset, 16); offset += 16;
        memcpy(tag, packet + offset, 32); offset += 32;
        memcpy(&ct_len32, packet + offset, 4); offset += 4;
        
        size_t ct_len = ct_len32;
        if (offset + ct_len > (size_t)received) return -1;
        
        uint8_t* ct = packet + offset;
        
        size_t dec_len = 0;
        AESStatus st = CRACK_AES_open_CTR_autoIV(&ctx, (const uint8_t*)"AAD", 3, nonce,
                                             ct, ct_len, tag, 32,
                                             (uint8_t*)plaintext, max_len, &dec_len);
    if (st != AES_OK) {
            if (st == AES_ERR_AUTH) {
                printf("[오류] 메시지 무결성 검증 실패! 변조된 메시지입니다.\n");
            }
            return -1;
        }
        
        plaintext[dec_len] = '\0';
        *out_len = dec_len;
        
    } else if (mode == CRYPTO_AES1_CTR) {
        /* AES1-CTR 모드 */
        AES_ctx ctx;
        AES_init(&ctx, g_comm_key, AES256);
        
        uint8_t nonce[16], nonce_copy[16];
        uint32_t ct_len32;
        
        if ((size_t)received < offset + 16 + 4) return -1;
        
        memcpy(nonce, packet + offset, 16); offset += 16;
        memcpy(&ct_len32, packet + offset, 4); offset += 4;
        
        size_t ct_len = ct_len32;
        if (offset + ct_len > (size_t)received) return -1;
        
        if (ct_len > max_len) return -1;
        
        memcpy(nonce_copy, nonce, 16);  /* 복사본으로 복호화 */
        AES_cryptCTR(&ctx, packet + offset, ct_len, (uint8_t*)plaintext, nonce_copy);
        
        plaintext[ct_len] = '\0';
        *out_len = ct_len;
        
    } else if (mode == CRYPTO_AES1_ECB) {
        /* AES1-ECB 모드 */
        AES_ctx ctx;
        AES_init(&ctx, g_comm_key, AES256);
        
        AESPadding pad_mode = (AESPadding)packet[offset++];
        uint32_t ct_len32;
        
        if ((size_t)received < offset + 4) return -1;
        
        memcpy(&ct_len32, packet + offset, 4); offset += 4;
        
        size_t ct_len = ct_len32;
        if (offset + ct_len > (size_t)received) return -1;
        
        size_t dec_len = 0;
        if (AES_decryptECB(&ctx, packet + offset, ct_len, (uint8_t*)plaintext, max_len, &dec_len, pad_mode) != AES_OK) {
            return -1;
        }
        
        plaintext[dec_len] = '\0';
        *out_len = dec_len;
        
    } else if (mode == CRYPTO_AES1_CBC) {
        /* AES1-CBC 모드 */
        AES_ctx ctx;
        AES_init(&ctx, g_comm_key, AES256);
        
        AESPadding pad_mode = (AESPadding)packet[offset++];
        uint8_t iv[16];
        uint32_t ct_len32;
        
        if ((size_t)received < offset + 16 + 4) return -1;
        
        memcpy(iv, packet + offset, 16); offset += 16;
        memcpy(&ct_len32, packet + offset, 4); offset += 4;
        
        size_t ct_len = ct_len32;
        if (offset + ct_len > (size_t)received) return -1;
        
        size_t dec_len = 0;
        if (AES_decryptCBC(&ctx, packet + offset, ct_len, (uint8_t*)plaintext, max_len, &dec_len, iv, pad_mode) != AES_OK) {
            return -1;
        }
        
        plaintext[dec_len] = '\0';
        *out_len = dec_len;
        
    } else {
        return -1;
    }
    
    printf("[수신] 복호화 완료 (%zu bytes)\n", *out_len);
    return 0;
}

/* 로컬 IP 주소 출력 (같은 와이파이 네트워크용) */
static void print_local_ip(void) { /* 로컬 IP 주소 출력 */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* host = gethostbyname(hostname);
        if (host != NULL) {
            printf("\n[내 IP 주소 목록] - 상대방에게 이 주소를 알려주세요:\n");
            for (int i = 0; host->h_addr_list[i] != NULL; i++) {
                struct in_addr addr;
                memcpy(&addr, host->h_addr_list[i], sizeof(struct in_addr));
                char* ip = inet_ntoa(addr);
                /* 로컬 네트워크 IP만 표시 (192.168.x.x, 10.x.x.x, 172.16-31.x.x) */
                if (strncmp(ip, "192.168.", 8) == 0 ||
                    strncmp(ip, "10.", 3) == 0 ||
                    strncmp(ip, "172.", 4) == 0) {
                    printf("  → %s (로컬 네트워크)\n", ip);
                } else if (strcmp(ip, "127.0.0.1") != 0) {
                    printf("  → %s\n", ip);
                }
            }
            printf("\n");
        }
    }
}

/* 서버 모드 */
static void run_server(int port) { /* 서버 모드 실행 */
    printf("\n========================================\n");
    printf(" [서버 모드] 포트 %d\n", port);
    printf("========================================\n");

    if (init_socket() != 0) return;

    /* 로컬 IP 주소 표시 */
    print_local_ip();

    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET) {
        printf("[오류] 소켓 생성 실패.\n");
        cleanup_socket();
        return;
    }

    /* SO_REUSEADDR 옵션 설정 (포트 재사용 허용) */
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((unsigned short)port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("[오류] 바인드 실패. 포트 %d가 이미 사용 중일 수 있습니다.\n", port);
        closesocket(server_sock);
        cleanup_socket();
        return;
    }

    if (listen(server_sock, 1) == SOCKET_ERROR) {
        printf("[오류] 리슨 실패.\n");
        closesocket(server_sock);
        cleanup_socket();
        return;
    }

    printf("[서버] 클라이언트 연결 대기 중...\n");
    printf("[서버] 상대방이 클라이언트 모드로 접속하면 통신이 시작됩니다.\n\n");

    struct sockaddr_in client_addr;
    int client_len = sizeof(client_addr);
    SOCKET client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
    if (client_sock == INVALID_SOCKET) {
        printf("[오류] 연결 수락 실패.\n");
        closesocket(server_sock);
        cleanup_socket();
        return;
    }

    printf("[서버] 클라이언트 연결됨!\n");
    
    /* 연결 완료 후 암호화 방식 선택 */
    select_crypto_mode();
    
    printf("[서버] 'quit' 입력 시 종료\n\n");

    /* 양방향 통신 시작 (수신 스레드 생성) */
        g_comm_socket = client_sock;
    g_running = 1;

#ifdef _WIN32
    InitializeCriticalSection(&g_print_lock);
    HANDLE recv_thread = CreateThread(NULL, 0, receive_thread, NULL, 0, NULL);
    if (recv_thread == NULL) {
        printf("[오류] 수신 스레드 생성 실패.\n");
        closesocket(client_sock);
        closesocket(server_sock);
        cleanup_socket();
        return;
    }
#else
    if (pthread_mutex_init(&g_print_lock, NULL) != 0) {
        printf("[오류] 뮤텍스 초기화 실패.\n");
        closesocket(client_sock);
        closesocket(server_sock);
        cleanup_socket();
        return;
    }
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_thread, NULL) != 0) {
        printf("[오류] 수신 스레드 생성 실패.\n");
        pthread_mutex_destroy(&g_print_lock);
        closesocket(client_sock);
        closesocket(server_sock);
        cleanup_socket();
        return;
    }
#endif

    /* 메인 스레드: 송신 전용 */
    char input[2048];
    printf("[나] > ");
    fflush(stdout);

    while (g_running) {
        int r = read_utf8_line(input, sizeof(input));
        if (r <= 0) continue;   // 입력 없으면 다시 루프 (블록되지 않음)


        if (strcmp(input, "quit") == 0) {
            printf("[서버] 종료합니다.\n");
            g_running = 0;
            break;
        }

        if (send_encrypted_message(client_sock, input, strlen(input)) != 0) {
            printf("[오류] 메시지 전송 실패.\n");
            g_running = 0;
            break;
        }

        LOCK_PRINT();
        printf("[나] > ");
        fflush(stdout);
        UNLOCK_PRINT();
    }

    /* 정리 */
    g_running = 0;
#ifdef _WIN32
    WaitForSingleObject(recv_thread, 1000);
    CloseHandle(recv_thread);
    DeleteCriticalSection(&g_print_lock);
#else
    pthread_join(recv_thread, NULL);
    pthread_mutex_destroy(&g_print_lock);
#endif
    closesocket(client_sock);
    closesocket(server_sock);
    cleanup_socket();

}

/* 클라이언트 모드 */
static void run_client(const char* server_ip, int port) { /* 클라이언트 모드 실행 */
    printf("\n========================================\n");
    printf(" [클라이언트 모드] %s:%d 연결 중...\n", server_ip, port);
    printf("========================================\n");

    if (init_socket() != 0) return;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("[오류] 소켓 생성 실패.\n");
        cleanup_socket();
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short)port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        printf("[오류] 잘못된 IP 주소입니다.\n");
        closesocket(sock);
        cleanup_socket();
        return;
    }

    printf("[클라이언트] %s:%d 연결 시도 중...\n", server_ip, port);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("\n[오류] 서버 연결 실패!\n");
        printf("  확인사항:\n");
        printf("  1. 서버가 먼저 실행되어 있는지 확인하세요.\n");
        printf("  2. IP 주소가 올바른지 확인하세요. (서버의 로컬 IP)\n");
        printf("  3. 포트 번호가 서버와 동일한지 확인하세요.\n");
        printf("  4. 방화벽이 차단하고 있는지 확인하세요.\n");
        printf("  5. 같은 와이파이 네트워크에 연결되어 있는지 확인하세요.\n");
        closesocket(sock);
        cleanup_socket();
        return;
    }

    printf("[클라이언트] 서버에 연결 성공!\n");
    
    /* 연결 완료 후 암호화 방식 선택 */
    select_crypto_mode();
    
    printf("[클라이언트] 메시지를 입력하면 암호화되어 전송됩니다.\n");
    printf("[클라이언트] 'quit' 입력 시 종료\n\n");

    /* 양방향 통신 시작 (수신 스레드 생성) */
        g_comm_socket = sock;
    g_running = 1;
#ifdef _WIN32
    InitializeCriticalSection(&g_print_lock);
    HANDLE recv_thread = CreateThread(NULL, 0, receive_thread, NULL, 0, NULL);
    if (recv_thread == NULL) {
        printf("[오류] 수신 스레드 생성 실패.\n");
        closesocket(sock);
        cleanup_socket();
        return;
    }
#else
    if (pthread_mutex_init(&g_print_lock, NULL) != 0) {
        printf("[오류] 뮤텍스 초기화 실패.\n");
        closesocket(sock);
        cleanup_socket();
        return;
    }
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, receive_thread, NULL) != 0) {
        printf("[오류] 수신 스레드 생성 실패.\n");
        pthread_mutex_destroy(&g_print_lock);
        closesocket(sock);
        cleanup_socket();
        return;
    }
#endif


    /* 메인 스레드: 송신 전용 */
    char input[2048];
    printf("[나] > ");
    fflush(stdout);

    while (g_running) {
        int r = read_utf8_line(input, sizeof(input));
        if (r <= 0) continue;   // 입력 없으면 다시 루프 (블록되지 않음)

        if (strcmp(input, "quit") == 0) {
            printf("[클라이언트] 종료합니다.\n");
            g_running = 0;
            break;
        }

        if (send_encrypted_message(sock, input, strlen(input)) != 0) {
            printf("[오류] 메시지 전송 실패.\n");
            g_running = 0;
            break;
        }

        LOCK_PRINT();
        printf("[나] > ");
        fflush(stdout);
        UNLOCK_PRINT();

    }

       /* 정리 */
    g_running = 0;
#ifdef _WIN32
    WaitForSingleObject(recv_thread, 1000);
    CloseHandle(recv_thread);
    DeleteCriticalSection(&g_print_lock);
#else
    pthread_join(recv_thread, NULL);
    pthread_mutex_destroy(&g_print_lock);
#endif
    closesocket(sock);
    cleanup_socket();

}

/* --------------------------------------------------------------------------
 * 로컬 암호화/복호화 테스트 (기존 기능)
 * -------------------------------------------------------------------------- */
static void run_local_test(void) { /* 로컬 암호화/복호화 테스트 */
    /* 암호화/복호화 선택 */
    printf("\n작업을 선택하세요:\n");
    printf("  [1] 암호화 (평문 → 암호문)\n");
    printf("  [2] 복호화 (암호문 → 평문)\n");
    printf("선택: ");
    fflush(stdout);

    char op_buf[16];
    if (read_utf8_line(op_buf, sizeof(op_buf)) <= 0) {
        printf("입력을 읽지 못했습니다.\n");
        return;
    }
    int operation = atoi(op_buf);

    if (operation == 1) {
        /* ============== 암호화 모드 ============== */
        char line[2048];
        printf("\n평문을 입력하세요 (최대 2047바이트):\n> ");
        fflush(stdout);
        int input_len = read_utf8_line(line, sizeof(line));
        if (input_len <= 0) {
            printf("빈 평문입니다.\n");
            return;
        }
        size_t len = (size_t)input_len;

        printf("\n사용할 프로파일을 선택하세요:\n");
        printf("  [1] AES1 속도형 (CTR / ECB / CBC)\n");
        printf("  [2] CRACK_AES 보안형 (CTR + HKDF + HMAC-SHA-512)\n");
        printf("선택: ");
        fflush(stdout);

        char choice_buf[16];
        if (read_utf8_line(choice_buf, sizeof(choice_buf)) <= 0) return;
        int choice = atoi(choice_buf);

        if (choice == 1) {
            printf("\n[AES1] 운용 모드를 선택하세요:\n");
            printf("  [1] CTR\n");
            printf("  [2] ECB\n");
            printf("  [3] CBC\n");
            printf("선택: ");
            fflush(stdout);

            char mode_buf[16];
            if (read_utf8_line(mode_buf, sizeof(mode_buf)) <= 0) return;
            int mode = atoi(mode_buf);

            if (mode == 1) aes1_ctr_encrypt((const uint8_t*)line, len);
            else if (mode == 2) aes1_ecb_encrypt((const uint8_t*)line, len);
            else if (mode == 3) aes1_cbc_encrypt((const uint8_t*)line, len);
            else printf("잘못된 모드 선택입니다.\n");
        } else if (choice == 2) {
            crack_aes_encrypt((const uint8_t*)line, len);
        } else {
            printf("잘못된 프로파일 선택입니다.\n");
        }

    } else if (operation == 2) {
        /* ============== 복호화 모드 ============== */
        printf("\n복호화할 프로파일을 선택하세요:\n");
        printf("  [1] AES1 속도형 (CTR / ECB / CBC)\n");
        printf("  [2] CRACK_AES 보안형 (CTR + HMAC 검증)\n");
        printf("선택: ");
        fflush(stdout);

        char profile_buf[16];
        if (read_utf8_line(profile_buf, sizeof(profile_buf)) <= 0) return;
        int profile = atoi(profile_buf);

        if (profile == 1) {
            printf("\n[AES1] 복호화할 운용 모드를 선택하세요:\n");
            printf("  [1] CTR\n");
            printf("  [2] ECB\n");
            printf("  [3] CBC\n");
            printf("선택: ");
            fflush(stdout);

            char mode_buf[16];
            if (read_utf8_line(mode_buf, sizeof(mode_buf)) <= 0) return;
            int mode = atoi(mode_buf);

            if (mode == 1) aes1_ctr_decrypt_only();
            else if (mode == 2) aes1_ecb_decrypt_only();
            else if (mode == 3) aes1_cbc_decrypt_only();
            else printf("잘못된 모드 선택입니다.\n");
        } else if (profile == 2) {
            crack_aes_decrypt_only();
        } else {
            printf("잘못된 프로파일 선택입니다.\n");
        }
    } else {
        printf("잘못된 선택입니다.\n");
    }
}

/* --------------------------------------------------------------------------
 * main: 모드 선택 (로컬/서버/클라이언트)
 * -------------------------------------------------------------------------- */

int main(void) { /* 프로그램 진입점 */
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif

    printf("============================================================\n");
    printf("       AES 암호화 통신 시스템\n");
    printf("============================================================\n\n");

    /* 셀프 테스트 */
    if (sha512_selftest() != 0) {
        printf("[SELFTEST] SHA-512 selftest 실패.\n");
        return 1;
    }
    AESStatus st = CRACK_AES_selftest();
    if (st != AES_OK) {
        printf("[SELFTEST] CRACK_AES_selftest 실패: %s\n", aes_status_str(st));
        return 1;
    }
    printf("[SELFTEST] OK\n\n");

    /* 모드 선택 */
    printf("모드를 선택하세요:\n");
    printf("  [1] 로컬 테스트 (암호화/복호화)\n");
    printf("  [2] 서버 모드 (연결 대기)\n");
    printf("  [3] 클라이언트 모드 (서버에 연결)\n");
    printf("선택: ");
    fflush(stdout);

    char mode_buf[16];
    if (read_utf8_line(mode_buf, sizeof(mode_buf)) <= 0) {
        printf("입력을 읽지 못했습니다.\n");
        return 1;
    }
    int mode = atoi(mode_buf);

    if (mode == 1) {
        /* 로컬 테스트 */
        run_local_test();

    } else if (mode == 2) {
        /* 서버 모드 */
        printf("\n포트 번호를 입력하세요 (기본값: %d):\n> ", DEFAULT_PORT);
        fflush(stdout);
        char port_buf[16];
        int port = DEFAULT_PORT;
        if (read_utf8_line(port_buf, sizeof(port_buf)) > 0 && atoi(port_buf) > 0) {
            port = atoi(port_buf);
        }
        run_server(port);

    } else if (mode == 3) {
        /* 클라이언트 모드 */
        printf("\n========================================\n");
        printf(" [클라이언트 모드]\n");
        printf("========================================\n");
        printf("서버의 IP 주소를 입력하세요.\n");
        printf("(같은 와이파이: 서버에서 표시된 192.168.x.x 형식의 IP)\n");
        printf("(같은 컴퓨터: 127.0.0.1)\n");
        printf("> ");
        fflush(stdout);
        char ip_buf[64] = "127.0.0.1";
        int ip_len = read_utf8_line(ip_buf, sizeof(ip_buf));
        if (ip_len <= 0 || strlen(ip_buf) == 0) {
            strcpy(ip_buf, "127.0.0.1");
        }

        printf("\n포트 번호를 입력하세요 (서버와 동일해야 함, 기본값: %d):\n> ", DEFAULT_PORT);
        fflush(stdout);
        char port_buf[16];
        int port = DEFAULT_PORT;
        if (read_utf8_line(port_buf, sizeof(port_buf)) > 0 && atoi(port_buf) > 0) {
            port = atoi(port_buf);
        }
        run_client(ip_buf, port);

    } else {
        printf("잘못된 선택입니다.\n");
        return 1;
    }

    printf("\n프로그램을 종료합니다.\n");
    return 0;
}