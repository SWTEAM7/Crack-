/**
 * @file aes.c
 * @brief AES (Advanced Encryption Standard) 암호화/복호화 구현
 * @details FIPS-197 표준을 따르는 AES-128/192/256 구현
 *          ECB, CBC, CTR 운용 모드 지원
 */

#include "aes.h"
#include <string.h>

/** @brief AES 블록 크기 (바이트) - 항상 16바이트 */
#define AES_BLOCK 16

// ─────────────────────────────────────────────────────────────────────────────
// 내부 상수/테이블 (FIPS-197)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief S-box (Substitution box) - 전방향 대체 테이블
 * @details AES의 SubBytes 변환에서 사용되는 8비트 대체 테이블
 *          각 바이트는 GF(2^8) 유한체에서 역원을 구한 후 아핀 변환을 적용
 *          총 256개의 엔트리 (0x00 ~ 0xFF)
 *          FIPS-197 표준 문서의 Table 5.1 참조
 */
static const uint8_t sbox[256] = {
  // 0x00 .. 0x0F
  0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
  // 0x10 .. 0x1F
  0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
  // 0x20 .. 0x2F
  0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
  // 0x30 .. 0x3F
  0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
  // 0x40 .. 0x4F
  0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
  // 0x50 .. 0x5F
  0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
  // 0x60 .. 0x6F
  0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
  // 0x70 .. 0x7F
  0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
  // 0x80 .. 0x8F
  0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
  // 0x90 .. 0x9F
  0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
  // 0xA0 .. 0xAF
  0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
  // 0xB0 .. 0xBF
  0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
  // 0xC0 .. 0xCF
  0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
  // 0xD0 .. 0xDF
  0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
  // 0xE0 .. 0xEF
  0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
  // 0xF0 .. 0xFF
  0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

/**
 * @brief 역 S-box (Inverse Substitution box) - 역방향 대체 테이블
 * @details AES의 InvSubBytes 변환에서 사용되는 역 대체 테이블
 *          복호화 시 sbox의 역변환을 수행
 *          FIPS-197 표준 문서의 Table 5.2 참조
 */
static const uint8_t inv_sbox[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

/**
 * @brief 라운드 상수 (Round Constants) 배열
 * @details 키 확장(key expansion) 과정에서 사용되는 라운드 상수
 *          Rcon[i] = x^(i-1) mod (x^8 + x^4 + x^3 + x + 1)
 *          인덱스 0은 사용하지 않음, 인덱스 1~10 사용 (AES-128/192/256)
 *          FIPS-197 표준 문서의 Table 5.3 참조
 */
static const uint8_t Rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// ─────────────────────────────────────────────────────────────────────────────
// GF(2^8) 유한체 연산 헬퍼 함수
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief GF(2^8)에서 x를 곱하는 함수 (xtime)
 * @param x 입력 바이트
 * @return x * 2 (mod 0x11B) 결과
 * @details GF(2^8)에서 곱셈은 시프트 연산으로 구현
 *          최상위 비트가 1이면 기약다항식 0x11B (x^8 + x^4 + x^3 + x + 1)와 XOR
 *          MixColumns와 키 확장에서 사용
 */
static inline uint8_t xtime(uint8_t x){ 
    return (uint8_t)((x<<1) ^ ((x&0x80)?0x1B:0x00)); 
}
/**
 * @brief GF(2^8)에서 두 바이트를 곱하는 함수
 * @param x 첫 번째 피연산자
 * @param y 두 번째 피연산자
 * @return x * y (mod 0x11B) 결과
 * @details 러시안 곱셈 알고리즘 사용 (Russian Peasant Algorithm)
 *          비트 단위로 곱셈을 수행하여 효율적
 *          InvMixColumns에서 사용 (복잡한 계수 곱셈)
 */
static inline uint8_t mul(uint8_t x, uint8_t y) {
    uint8_t r = 0;
    while (y) { 
        if (y & 1) r ^= x;  // y의 최하위 비트가 1이면 r에 x를 더함 (XOR)
        x = xtime(x);       // x를 2배로 만듦 (x * 2)
        y >>= 1;            // y를 오른쪽으로 1비트 시프트
    }
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// 에러 처리 및 유틸리티 함수
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief AES 컨텍스트에 에러 상태를 설정하고 콜백 호출
 * @param ctx AES 컨텍스트 포인터 (NULL 가능)
 * @param code 에러 코드
 * @param msg 에러 메시지
 * @details 컨텍스트가 유효하면 last_err를 설정하고,
 *          에러 콜백이 등록되어 있으면 호출
 */
static void aes_set_error(AES_ctx* ctx, AESStatus code, const char* msg) {
    if (ctx) ctx->last_err = code;
    if (ctx && ctx->on_error) ctx->on_error(code, msg, ctx->err_ud);
}

/**
 * @brief 두 메모리 영역이 겹치지 않는지 확인
 * @param p1 첫 번째 메모리 영역 시작 주소
 * @param n1 첫 번째 메모리 영역 크기
 * @param p2 두 번째 메모리 영역 시작 주소
 * @param n2 두 번째 메모리 영역 크기
 * @return 겹치지 않으면 1, 겹치면 0
 * @details ECB/CBC 모드에서 입력과 출력 버퍼가 겹치는 것을 방지
 *          두 영역이 완전히 분리되어 있으면 안전
 */
static int no_forbidden_overlap(const void* p1, size_t n1,
                                const void* p2, size_t n2) {
    const uint8_t* a=(const uint8_t*)p1; 
    const uint8_t* b=(const uint8_t*)p2;
    // a 영역이 b 영역의 앞에 완전히 있거나, b 영역이 a 영역의 앞에 완전히 있으면 OK
    return (a+n1<=b) || (b+n2<=a);
}

/**
 * @brief 에러 코드를 문자열로 변환
 * @param code AESStatus 에러 코드
 * @return 에러 코드에 해당하는 문자열
 * @details 사용자에게 에러 메시지를 표시할 때 사용
 */
const char* AES_strerror(AESStatus code) {
    switch (code) {
        case AES_OK: return "AES_OK";
        case AES_ERR_BAD_PARAM: return "AES_ERR_BAD_PARAM";
        case AES_ERR_BUF_SMALL: return "AES_ERR_BUF_SMALL";
        case AES_ERR_PADDING: return "AES_ERR_PADDING";
        case AES_ERR_OVERLAP: return "AES_ERR_OVERLAP";
        case AES_ERR_STATE: return "AES_ERR_STATE";
        case AES_ERR_LENGTH: return "AES_ERR_LENGTH";
        default: return "AES_ERR_UNKNOWN";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 키 확장 (Key Expansion) - FIPS-197 표준
// ─────────────────────────────────────────────────────────────────────────────
// 키 확장은 원본 키를 여러 라운드 키로 확장하는 과정입니다.
// AES-128: 10라운드, AES-192: 12라운드, AES-256: 14라운드
// 각 라운드마다 4워드(16바이트)의 라운드 키가 필요하므로
// 총 4*(Nr+1) 워드가 필요합니다 (초기 AddRoundKey 포함)
// roundKeys는 big-endian 워드로 저장됩니다.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief 4바이트 배열을 big-endian 32비트 워드로 변환
 * @param b 4바이트 배열 (big-endian 순서)
 * @return 32비트 워드 값
 * @details 키 확장에서 바이트 배열을 워드로 변환할 때 사용
 */
static inline uint32_t pack_be(const uint8_t b[4]) {
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}

/**
 * @brief 32비트 워드를 big-endian 4바이트 배열로 변환
 * @param w 32비트 워드 값
 * @param b 출력 4바이트 배열 (big-endian 순서)
 * @details 워드를 바이트 배열로 분해할 때 사용
 */
static inline void unpack_be(uint32_t w, uint8_t b[4]) {
    b[0]=(uint8_t)(w>>24); b[1]=(uint8_t)(w>>16); b[2]=(uint8_t)(w>>8); b[3]=(uint8_t)w;
}

/**
 * @brief 워드의 각 바이트에 S-box를 적용
 * @param w 입력 32비트 워드
 * @return 각 바이트에 sbox를 적용한 결과 워드
 * @details 키 확장에서 사용되며, 최적화를 위해 unpack/pack 없이 직접 처리
 */
static inline uint32_t SubWord(uint32_t w) {
    // 최적화: unpack/pack 제거하고 직접 sbox 적용
    return ((uint32_t)sbox[(uint8_t)(w>>24)]<<24) |
           ((uint32_t)sbox[(uint8_t)(w>>16)]<<16) |
           ((uint32_t)sbox[(uint8_t)(w>>8)]<<8) |
           ((uint32_t)sbox[(uint8_t)w]);
}

/**
 * @brief 워드를 왼쪽으로 1바이트 순환 시프트
 * @param w 입력 32비트 워드
 * @return 순환 시프트된 워드
 * @details 키 확장에서 사용 (예: [a,b,c,d] -> [b,c,d,a])
 */
static inline uint32_t RotWord(uint32_t w) {
    return (w<<8) | (w>>24);
}

/**
 * @brief 키 확장 함수 - 원본 키를 라운드 키로 확장
 * @param ctx AES 컨텍스트 포인터
 * @param key 원본 키 (16/24/32 바이트)
 * @param keyLen 키 길이 (AES128/AES192/AES256)
 * @details FIPS-197 표준의 키 확장 알고리즘 구현
 * 
 * 알고리즘:
 * 1. 원본 키를 워드로 변환하여 초기 라운드 키로 저장
 * 2. 나머지 라운드 키 생성:
 *    - i가 Nk의 배수면: RotWord -> SubWord -> Rcon XOR
 *    - AES-256이고 i%Nk==4면: SubWord만 적용
 *    - 그 외: 이전 워드 그대로 사용
 * 3. 생성된 라운드 키는 ctx->roundKeys에 저장
 */
static void key_expansion(AES_ctx* ctx, const uint8_t* key, AESKeyLength keyLen) {
    int Nk = (int)keyLen/4;                 // 키 워드 수: AES128=4, AES192=6, AES256=8
    ctx->Nr = (Nk==4)?10:((Nk==6)?12:14);   // 라운드 수: AES128=10, AES192=12, AES256=14
    int Nb = 4;                              // 블록 크기 (워드 단위, 항상 4)
    int W  = Nb*(ctx->Nr+1);                 // 총 필요한 워드 수: (라운드+1) * 4

    uint32_t* rk = ctx->roundKeys;
    
    // 1단계: 원본 키를 워드로 변환하여 초기 라운드 키로 저장
    for (int i=0;i<Nk;i++) rk[i] = pack_be(key + 4*i);

    // 2단계: 나머지 라운드 키 생성
    for (int i=Nk;i<W;i++) {
        uint32_t temp = rk[i-1];  // 이전 워드
        if (i % Nk == 0) {
            // i가 Nk의 배수: RotWord -> SubWord -> Rcon XOR
            temp = SubWord(RotWord(temp)) ^ ((uint32_t)Rcon[i/Nk]<<24);
        } else if (Nk>6 && (i%Nk)==4) {
            // AES-256이고 i%Nk==4: SubWord만 적용
            temp = SubWord(temp);
        }
        // 이전 워드와 XOR하여 새로운 라운드 키 생성
        rk[i] = rk[i-Nk] ^ temp;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AES 라운드 변환 함수들 (FIPS-197 표준)
// ─────────────────────────────────────────────────────────────────────────────
// AES는 4가지 기본 변환을 조합하여 암호화/복호화를 수행합니다:
// 1. SubBytes/InvSubBytes: 바이트 단위 대체
// 2. ShiftRows/InvShiftRows: 행 단위 시프트
// 3. MixColumns/InvMixColumns: 열 단위 혼합
// 4. AddRoundKey: 라운드 키와 XOR
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief 라운드 키 추가 (AddRoundKey)
 * @param s 상태 행렬 (16바이트, 4x4 행렬)
 * @param rk 라운드 키 포인터 (4워드 = 16바이트)
 * @details 상태 행렬의 각 바이트를 라운드 키와 XOR 연산
 *          최적화: unpack 제거하고 직접 XOR 수행
 */
static inline void AddRoundKey(uint8_t s[16], const uint32_t* rk) {
    // 최적화: unpack 제거하고 직접 XOR 수행
    for (int c=0;c<4;c++){  // 각 열(column)에 대해
        uint32_t w = rk[c];  // 라운드 키 워드 가져오기
        // 상태 행렬의 해당 열과 XOR
        s[4*c+0] ^= (uint8_t)(w>>24);  // 첫 번째 행
        s[4*c+1] ^= (uint8_t)(w>>16);  // 두 번째 행
        s[4*c+2] ^= (uint8_t)(w>>8);   // 세 번째 행
        s[4*c+3] ^= (uint8_t)w;         // 네 번째 행
    }
}
/**
 * @brief 바이트 대체 (SubBytes) - 암호화용
 * @param s 상태 행렬 (16바이트)
 * @details 각 바이트를 sbox 테이블을 통해 대체
 *          비선형 변환으로 암호 강도 제공
 *          최적화: 컴파일러가 루프 언롤링 가능
 */
static inline void SubBytes(uint8_t s[16]) {
    for(int i=0;i<16;i++) s[i]=sbox[s[i]];
}

/**
 * @brief 역 바이트 대체 (InvSubBytes) - 복호화용
 * @param s 상태 행렬 (16바이트)
 * @details 각 바이트를 inv_sbox 테이블을 통해 역 대체
 *          SubBytes의 역변환
 */
static inline void InvSubBytes(uint8_t s[16]) {
    for(int i=0;i<16;i++) s[i]=inv_sbox[s[i]];
}
/**
 * @brief 행 시프트 (ShiftRows) - 암호화용
 * @param s 상태 행렬 (16바이트, 4x4 행렬로 해석)
 * @details 각 행을 왼쪽으로 순환 시프트:
 *          - 0행: 시프트 없음
 *          - 1행: 1바이트 왼쪽 시프트
 *          - 2행: 2바이트 왼쪽 시프트
 *          - 3행: 3바이트 왼쪽 시프트
 *          상태 행렬은 열 우선 순서로 저장됨: s[4*c+r] = 행 r, 열 c
 */
static inline void ShiftRows(uint8_t s[16]) {
    uint8_t t1, t2;
    // 1행 (인덱스 1,5,9,13): 1바이트 왼쪽 시프트
    t1=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t1;
    // 2행 (인덱스 2,6,10,14): 2바이트 왼쪽 시프트 (서로 교환)
    t1=s[2]; s[2]=s[10]; s[10]=t1;
    t2=s[6]; s[6]=s[14]; s[14]=t2;
    // 3행 (인덱스 3,7,11,15): 3바이트 왼쪽 시프트 (역순)
    t1=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t1;
}
/**
 * @brief 역 행 시프트 (InvShiftRows) - 복호화용
 * @param s 상태 행렬 (16바이트)
 * @details ShiftRows의 역변환: 각 행을 오른쪽으로 순환 시프트
 *          - 1행: 3바이트 오른쪽 시프트 (1바이트 왼쪽 시프트의 역)
 *          - 2행: 2바이트 오른쪽 시프트 (2바이트 왼쪽 시프트의 역)
 *          - 3행: 1바이트 오른쪽 시프트 (3바이트 왼쪽 시프트의 역)
 */
static inline void InvShiftRows(uint8_t s[16]) {
    uint8_t t1, t2;
    // 1행: 3바이트 오른쪽 시프트
    t1=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t1;
    // 2행: 2바이트 오른쪽 시프트 (서로 교환, 자기 역변환)
    t1=s[2]; s[2]=s[10]; s[10]=t1;
    t2=s[6]; s[6]=s[14]; s[14]=t2;
    // 3행: 1바이트 오른쪽 시프트
    t1=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t1;
}
/**
 * @brief 열 혼합 (MixColumns) - 암호화용
 * @param s 상태 행렬 (16바이트)
 * @details 각 열을 GF(2^8)에서 행렬 곱셈으로 혼합
 *          각 열 [a0, a1, a2, a3]^T를 다음 행렬로 곱함:
 *          [02 03 01 01]   [a0]
 *          [01 02 03 01] * [a1]
 *          [01 01 02 03]   [a2]
 *          [03 01 01 02]   [a3]
 *          최적화: xtime(x) = x*2, x*3 = xtime(x) ^ x
 */
static inline void MixColumns(uint8_t s[16]) {
    for (int c=0;c<4;c++){  // 각 열에 대해
        uint8_t *a=&s[4*c];  // 열 시작 주소
        uint8_t a0=a[0],a1=a[1],a2=a[2],a3=a[3];  // 열의 4바이트
        // xtime 계산: x*2
        uint8_t a0x2=xtime(a0), a1x2=xtime(a1), a2x2=xtime(a2), a3x2=xtime(a3);
        // 행렬 곱셈 결과 (x*3 = xtime(x) ^ x)
        a[0]= (uint8_t)(a0x2 ^ a1x2 ^ a1 ^ a2 ^ a3);      // 2*a0 + 3*a1 + a2 + a3
        a[1]= (uint8_t)(a0 ^ a1x2 ^ a2x2 ^ a2 ^ a3);      // a0 + 2*a1 + 3*a2 + a3
        a[2]= (uint8_t)(a0 ^ a1 ^ a2x2 ^ a3x2 ^ a3);      // a0 + a1 + 2*a2 + 3*a3
        a[3]= (uint8_t)(a0x2 ^ a0 ^ a1 ^ a2 ^ a3x2);      // 3*a0 + a1 + a2 + 2*a3
    }
}
/**
 * @brief 역 열 혼합 (InvMixColumns) - 복호화용
 * @param s 상태 행렬 (16바이트)
 * @details MixColumns의 역변환, 더 복잡한 계수 사용:
 *          [0E 0B 0D 09]   [a0]
 *          [09 0E 0B 0D] * [a1]
 *          [0D 09 0E 0B]   [a2]
 *          [0B 0D 09 0E]   [a3]
 *          복잡한 계수(14,11,13,9) 때문에 mul 함수 직접 사용
 */
static inline void InvMixColumns(uint8_t s[16]) {
    for (int c=0;c<4;c++){
        uint8_t *a=&s[4*c];
        uint8_t a0=a[0],a1=a[1],a2=a[2],a3=a[3];
        // 역 행렬 곱셈 결과
        a[0]= (uint8_t)(mul(a0,14)^mul(a1,11)^mul(a2,13)^mul(a3,9));  // 14=0x0E, 11=0x0B, 13=0x0D, 9=0x09
        a[1]= (uint8_t)(mul(a0,9)^mul(a1,14)^mul(a2,11)^mul(a3,13));
        a[2]= (uint8_t)(mul(a0,13)^mul(a1,9)^mul(a2,14)^mul(a3,11));
        a[3]= (uint8_t)(mul(a0,11)^mul(a1,13)^mul(a2,9)^mul(a3,14));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 공개 API: 초기화 및 블록 단위 암호화/복호화
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief AES 컨텍스트 초기화
 * @param ctx AES 컨텍스트 포인터
 * @param key 암호화 키 (16/24/32 바이트)
 * @param keyLen 키 길이 (AES128/AES192/AES256)
 * @return AES_OK 성공, 그 외 에러 코드
 * @details 키 확장을 수행하고 컨텍스트를 초기화합니다.
 *          이 함수를 먼저 호출해야 암호화/복호화가 가능합니다.
 */
AESStatus AES_init(AES_ctx* ctx, const uint8_t* key, AESKeyLength keyLen){
    if (!ctx || !key) { 
        aes_set_error(ctx, AES_ERR_BAD_PARAM, "null ctx/key"); 
        return AES_ERR_BAD_PARAM; 
    }
    if (keyLen!=AES128 && keyLen!=AES192 && keyLen!=AES256) {
        aes_set_error(ctx, AES_ERR_BAD_PARAM, "invalid key length"); 
        return AES_ERR_BAD_PARAM;
    }
    key_expansion(ctx, key, keyLen);  // 키 확장 수행
    ctx->encrypt_block = AES_encryptBlock;  // 암호화 함수 포인터 설정
    ctx->decrypt_block = AES_decryptBlock;  // 복호화 함수 포인터 설정
    ctx->last_err = AES_OK; 
    ctx->on_error=NULL; 
    ctx->err_ud=NULL;
    return AES_OK;
}

/**
 * @brief 단일 블록 암호화 (16바이트)
 * @param ctx AES 컨텍스트 포인터 (AES_init으로 초기화 필요)
 * @param in 입력 평문 블록 (16바이트)
 * @param out 출력 암호문 블록 (16바이트)
 * @details AES 암호화 알고리즘:
 *          1. 초기 AddRoundKey
 *          2. Nr-1번의 라운드 (SubBytes -> ShiftRows -> MixColumns -> AddRoundKey)
 *          3. 마지막 라운드 (SubBytes -> ShiftRows -> AddRoundKey, MixColumns 없음)
 */
void AES_encryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]){
    if (!ctx || !in || !out) { 
        aes_set_error(ctx, AES_ERR_BAD_PARAM, "null block io"); 
        return; 
    }
    uint8_t s[16];  // 상태 행렬
    memcpy(s,in,16);  // 입력 블록 복사
    
    const uint32_t* rk = ctx->roundKeys;  // 라운드 키 포인터

    // 초기 라운드 키 추가
    AddRoundKey(s, rk); 
    rk += 4;  // 다음 라운드 키로 이동
    
    // 중간 라운드들 (MixColumns 포함)
    for (int r=1; r<ctx->Nr; ++r){
        SubBytes(s);      // 바이트 대체
        ShiftRows(s);     // 행 시프트
        MixColumns(s);     // 열 혼합
        AddRoundKey(s, rk);  // 라운드 키 추가
        rk += 4;
    }
    
    // 마지막 라운드 (MixColumns 없음)
    SubBytes(s); 
    ShiftRows(s); 
    AddRoundKey(s, rk);
    
    memcpy(out,s,16);  // 결과 출력
}

/**
 * @brief 단일 블록 복호화 (16바이트)
 * @param ctx AES 컨텍스트 포인터
 * @param in 입력 암호문 블록 (16바이트)
 * @param out 출력 평문 블록 (16바이트)
 * @details AES 복호화 알고리즘 (암호화의 역순):
 *          1. 초기 AddRoundKey (마지막 라운드 키 사용)
 *          2. Nr-1번의 라운드 (InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns)
 *          3. 마지막 라운드 (InvShiftRows -> InvSubBytes -> AddRoundKey, InvMixColumns 없음)
 *          라운드 키를 역순으로 사용
 */
void AES_decryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]){
    if (!ctx || !in || !out) { 
        aes_set_error(ctx, AES_ERR_BAD_PARAM, "null block io"); 
        return; 
    }
    uint8_t s[16];
    memcpy(s,in,16);
    const uint32_t* rk = ctx->roundKeys + 4*ctx->Nr;  // 마지막 라운드 키부터 시작

    // 초기 라운드 키 추가
    AddRoundKey(s, rk); 
    rk -= 4;  // 이전 라운드 키로 이동
    
    // 중간 라운드들 (InvMixColumns 포함)
    for (int r=1; r<ctx->Nr; ++r){
        InvShiftRows(s);      // 역 행 시프트
        InvSubBytes(s);       // 역 바이트 대체
        AddRoundKey(s, rk);   // 라운드 키 추가
        rk -= 4;              // 이전 라운드 키로 이동
        InvMixColumns(s);     // 역 열 혼합
    }
    
    // 마지막 라운드 (InvMixColumns 없음)
    InvShiftRows(s); 
    InvSubBytes(s); 
    AddRoundKey(s, rk);
    
    memcpy(out,s,16);
}

// ─────────────────────────────────────────────────────────────────────────────
// 패딩 유틸리티 함수
// ─────────────────────────────────────────────────────────────────────────────
// AES는 블록 암호이므로 입력 데이터가 16바이트의 배수여야 합니다.
// 패딩은 데이터 길이를 16바이트의 배수로 맞추기 위해 추가하는 바이트입니다.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief 패딩 적용 함수
 * @param in 입력 데이터 포인터
 * @param in_len 입력 데이터 길이 (바이트)
 * @param out 출력 버퍼 포인터
 * @param out_cap 출력 버퍼 용량 (바이트)
 * @param padding 패딩 방식 (PKCS#7, ANSI X9.23, NONE)
 * @param out_len 출력 데이터 길이 (바이트, 패딩 포함)
 * @return AES_OK 성공, 그 외 에러 코드
 * @details 
 * - PKCS#7: 마지막 바이트에 패딩 길이 N(1~16), 나머지도 모두 N으로 채움
 * - ANSI X9.23: 마지막 바이트에 패딩 길이 N, 나머지는 0x00으로 채움
 * - NONE: 패딩 없음, 입력 길이가 16의 배수여야 함
 */
AESStatus AES_applyPadding(const uint8_t* in, size_t in_len,
                           uint8_t* out, size_t out_cap,
                           AESPadding padding, size_t* out_len){
    if (!in || !out || !out_len) return AES_ERR_BAD_PARAM;
    if (padding == AES_PADDING_ZERO_FORBIDDEN) return AES_ERR_BAD_PARAM;

    if (padding == AES_PADDING_NONE){
        if (in_len % AES_BLOCK) return AES_ERR_LENGTH;
        if (out_cap < in_len)   return AES_ERR_BUF_SMALL;
        memcpy(out,in,in_len); *out_len=in_len; return AES_OK;
    }

    size_t rem = in_len % AES_BLOCK;
    size_t pad = (rem==0)?AES_BLOCK:(AES_BLOCK-rem);
    size_t need = in_len + pad;
    if (out_cap < need) return AES_ERR_BUF_SMALL;

    memcpy(out,in,in_len);
    if (padding == AES_PADDING_PKCS7){
        memset(out+in_len,(int)pad,pad);
    } else {
        memset(out+in_len,0x00,pad);
        out[in_len+pad-1]=(uint8_t)pad;
    }
    *out_len = need;
    return AES_OK;
}

/**
 * @brief 패딩 제거 함수
 * @param in 입력 데이터 포인터 (패딩 포함)
 * @param in_len 입력 데이터 길이 (바이트, 16의 배수)
 * @param padding 패딩 방식
 * @param out_plain_len 출력 평문 길이 (바이트, 패딩 제외)
 * @return AES_OK 성공, 그 외 에러 코드
 * @details 패딩 검증 후 실제 평문 길이를 반환합니다.
 *          패딩이 유효하지 않으면 AES_ERR_PADDING 반환
 */
AESStatus AES_stripPadding(const uint8_t* in, size_t in_len,
                           AESPadding padding, size_t* out_plain_len){
    if (!in || !out_plain_len) return AES_ERR_BAD_PARAM;
    if ((in_len==0) || (in_len % AES_BLOCK)) return AES_ERR_LENGTH;

    if (padding == AES_PADDING_NONE){ 
        *out_plain_len=in_len; 
        return AES_OK; 
    }
    if (padding == AES_PADDING_ZERO_FORBIDDEN) return AES_ERR_BAD_PARAM;

    // 마지막 바이트에서 패딩 길이 추출
    uint8_t last = in[in_len-1];
    size_t pad = (size_t)last;
    if (pad==0 || pad> AES_BLOCK) return AES_ERR_PADDING;  // 패딩 길이 유효성 검사

    // 패딩 검증: 모든 패딩 바이트가 올바른지 확인
    if (padding == AES_PADDING_PKCS7){
        // PKCS#7: 모든 패딩 바이트가 패딩 길이와 일치해야 함
        for (size_t i=0;i<pad;i++) {
            if (in[in_len-1-i]!=last) return AES_ERR_PADDING;
        }
    } else {
        // ANSI X9.23: 마지막 바이트(패딩 길이) 제외하고 모두 0x00이어야 함
        for (size_t i=1;i<pad;i++) {
            if (in[in_len-1-i]!=0x00) return AES_ERR_PADDING;
        }
    }
    *out_plain_len = in_len - pad;  // 패딩 제거한 실제 평문 길이
    return AES_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// 운용 모드 (Mode of Operation) 구현
// ─────────────────────────────────────────────────────────────────────────────
// 운용 모드는 블록 암호를 사용하여 임의 길이 데이터를 암호화하는 방법입니다.
// 각 모드는 서로 다른 특성과 보안 특성을 가집니다.
// ─────────────────────────────────────────────────────────────────────────────

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
 * @warning ⚠️ ECB 모드는 실무에서 사용하지 않기를 권장합니다!
 *          - 동일한 평문 블록은 항상 동일한 암호문 블록을 생성 (패턴 누설)
 *          - 이미지나 반복적인 데이터에서 구조가 그대로 드러남
 *          - 교육/테스트 목적으로만 사용 권장
 */
AESStatus AES_encryptECB(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         AESPadding padding){
    if (!ctx || !in || !out || !out_len) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null param"); return AES_ERR_BAD_PARAM; }
    if (!no_forbidden_overlap(in,in_len,out,out_cap)) { aes_set_error(ctx, AES_ERR_OVERLAP, "in/out overlap"); return AES_ERR_OVERLAP; }

    size_t plen=0; AESStatus st = AES_applyPadding(in,in_len,out,out_cap,padding,&plen);
    if (st!=AES_OK){ aes_set_error(ctx, st, "padding fail"); return st; }

    for (size_t i=0;i<plen;i+=AES_BLOCK) AES_encryptBlock(ctx, out+i, out+i);
    *out_len = plen; return AES_OK;
}

AESStatus AES_decryptECB(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         AESPadding padding){
    if (!ctx || !in || !out || !out_len) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null param"); return AES_ERR_BAD_PARAM; }
    if (in_len % AES_BLOCK) { aes_set_error(ctx, AES_ERR_LENGTH, "not block-aligned"); return AES_ERR_LENGTH; }
    if (out_cap < in_len)   { aes_set_error(ctx, AES_ERR_BUF_SMALL, "out small"); return AES_ERR_BUF_SMALL; }
    if (!no_forbidden_overlap(in,in_len,out,out_cap)) { aes_set_error(ctx, AES_ERR_OVERLAP, "in/out overlap"); return AES_ERR_OVERLAP; }

    for (size_t i=0;i<in_len;i+=AES_BLOCK) AES_decryptBlock(ctx, in+i, out+i);
    if (padding == AES_PADDING_NONE){ *out_len=in_len; return AES_OK; }
    AESStatus st = AES_stripPadding(out, in_len, padding, out_len);
    if (st!=AES_OK) aes_set_error(ctx, st, "strip padding fail");
    return st;
}

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
 * - 각 블록을 이전 블록의 암호문과 XOR한 후 암호화 (체인 방식)
 * - 첫 번째 블록은 IV와 XOR
 * - 장점: 동일한 평문 블록도 다른 암호문 생성 (ECB 문제 해결)
 * - 단점: 
 *   * 직렬 의존성 (병렬화 어려움)
 *   * 패딩 오라클 공격 위험
 *   * IV 재사용 시 보안 위험
 * - 주의: IV는 매번 랜덤하게 생성되어야 함!
 */
AESStatus AES_encryptCBC(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         uint8_t iv[16], AESPadding padding){
    if (!ctx || !in || !out || !out_len || !iv) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null param"); return AES_ERR_BAD_PARAM; }
    if (!no_forbidden_overlap(in,in_len,out,out_cap)) { aes_set_error(ctx, AES_ERR_OVERLAP, "in/out overlap"); return AES_ERR_OVERLAP; }

    size_t plen=0; AESStatus st = AES_applyPadding(in,in_len,out,out_cap,padding,&plen);
    if (st!=AES_OK){ aes_set_error(ctx, st, "padding fail"); return st; }

    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t i=0;i<plen;i+=AES_BLOCK){
        // XOR 최적화: 컴파일러가 자동 벡터화/언롤링
        for (int b=0;b<16;b++) out[i+b]^=prev[b];
        AES_encryptBlock(ctx, out+i, out+i);
        memcpy(prev, out+i, 16);
    }
    memcpy(iv, prev, 16); // iv 업데이트: 마지막 CT
    *out_len = plen; return AES_OK;
}

AESStatus AES_decryptCBC(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         uint8_t iv[16], AESPadding padding){
    if (!ctx || !in || !out || !out_len || !iv) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null param"); return AES_ERR_BAD_PARAM; }
    if (in_len % AES_BLOCK) { aes_set_error(ctx, AES_ERR_LENGTH, "not block-aligned"); return AES_ERR_LENGTH; }
    if (out_cap < in_len)   { aes_set_error(ctx, AES_ERR_BUF_SMALL, "out small"); return AES_ERR_BUF_SMALL; }
    if (!no_forbidden_overlap(in,in_len,out,out_cap)) { aes_set_error(ctx, AES_ERR_OVERLAP, "in/out overlap"); return AES_ERR_OVERLAP; }

    uint8_t prev[16], cur[16];
    memcpy(prev, iv, 16);
    for (size_t i=0;i<in_len;i+=AES_BLOCK){
        memcpy(cur, in+i, 16);
        AES_decryptBlock(ctx, in+i, out+i);
        for (int b=0;b<16;b++) out[i+b]^=prev[b];
        memcpy(prev, cur, 16);
    }
    memcpy(iv, prev, 16); // 입력 마지막 CT

    if (padding == AES_PADDING_NONE){ *out_len=in_len; return AES_OK; }
    AESStatus st = AES_stripPadding(out, in_len, padding, out_len);
    if (st!=AES_OK) aes_set_error(ctx, st, "strip padding fail");
    return st;
}

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
 * - 스트림 XOR 방식이라 변조가 쉬움 → 반드시 MAC/AEAD(GCM)로 무결성 보강 필요
 */
AESStatus AES_cryptCTR(AES_ctx* ctx,
                       const uint8_t* in, size_t len,
                       uint8_t* out,
                       uint8_t nonce_counter[16]){
    if (!ctx || !in || !out || !nonce_counter) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null param"); return AES_ERR_BAD_PARAM; }

    uint8_t ctr[16];
    memcpy(ctr, nonce_counter, 16);
    uint8_t ks[16];
    size_t i=0;
    while (i<len){
        AES_encryptBlock(ctx, ctr, ks);
        size_t chunk = (len-i>16)?16:(len-i);
        // XOR 최적화: 컴파일러가 벡터화 가능
        for (size_t b=0;b<chunk;b++) out[i+b] = in[i+b] ^ ks[b];

        // counter++ (big-endian) - 최적화: 조기 종료
        for (int p=15;p>=0;p--){ ctr[p]++; if (ctr[p]!=0) break; }
        i += chunk;
    }
    memcpy(nonce_counter, ctr, 16);
    return AES_OK;
}
