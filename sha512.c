/* =========================================================================
 * sha512.c - SHA-512, HMAC-SHA-512, HKDF-SHA-512 구현 (RFC 6234 / RFC 4231 / RFC 5869)
 * 
 * C99 순수 구현 (동적 할당 없음). 라이선스: 퍼블릭 도메인/CC0 유사.
 *
 * 목적: AES2(보안형)에서
 * - SHA-512: 해시 기본 원시
 * - HMAC-SHA-512: 무결성 태그 생성
 * - HKDF-SHA-512: 라운드키/ MAC 키 독립 파생(Extract + Expand)
 *
 * 빌드 예시:
 * clang -O3 -std=c99 -Wall -Wextra -pedantic sha512.c aes.c test.c -o test
 * cl /O2 /W4 /D_CRT_SECURE_NO_WARNINGS sha512.c aes.c test.c
 * ------------------------------------------------------------------------- */
#pragma execution_character_set("utf-8")

#include "sha512.h"

/* =========================================================================
 * sha512.c — 구현부
 * ========================================================================= */
#include <string.h>
#ifdef _WIN32
  #include <windows.h> /* SecureZeroMemory 힌트 */
#endif

/* ============================================================================
 * 내부 헬퍼 함수들
 * ============================================================================ */

/**
 * rotr64 - 64비트 값 우측 순환 시프트 (Right Rotate)
 * 
 * SHA-512 알고리즘에서 사용되는 비트 회전 연산입니다.
 * 
 * @param x  회전할 64비트 값
 * @param r  회전할 비트 수 (0-63, 자동으로 모듈로 처리)
 * @return 우측으로 r비트 회전한 값
 */
static inline uint64_t rotr64(uint64_t x, unsigned r){ 
    r &= 63u;  /* 64비트 회전이므로 63으로 모듈로 */
    return (x>>r) | (x<<(64u-r)); 
}

/**
 * bswap64 - 64비트 값의 바이트 순서 반전 (Big-Endian 변환)
 * 
 * 리틀엔디안 시스템에서 big-endian 형식으로 변환하기 위해 사용됩니다.
 * SHA-512는 big-endian 형식을 요구하므로, 리틀엔디안 시스템에서는
 * 이 함수를 사용하여 변환합니다.
 * 
 * @param x  변환할 64비트 값
 * @return 바이트 순서가 반전된 64비트 값
 */
static inline uint64_t bswap64(uint64_t x){
    /* 엔디안 독립성을 위한 64비트 바이트 스왑 */
    return ((x & 0x00000000000000FFull) << 56) |
           ((x & 0x000000000000FF00ull) << 40) |
           ((x & 0x0000000000FF0000ull) << 24) |
           ((x & 0x00000000FF000000ull) << 8)  |
           ((x & 0x000000FF00000000ull) >> 8)  |
           ((x & 0x0000FF0000000000ull) >> 24) |
           ((x & 0x00FF000000000000ull) >> 40) |
           ((x & 0xFF00000000000000ull) >> 56);
}

/* ============================================================================
 * SHA-512 라운드 상수
 * ============================================================================ */

/**
 * K[80] - SHA-512 라운드 상수 배열
 * 
 * 각 상수는 처음 80개 소수의 세제곱근의 분수부에서 추출된 64비트 값입니다.
 * 이 상수들은 SHA-512의 80라운드 압축 함수에서 각 라운드마다 사용되어
 * 해시의 확산과 혼돈을 보장합니다.
 * 
 * 상수 생성 방법:
 *   K[i] = floor(2^64 * (prime[i]^(1/3) - floor(prime[i]^(1/3))))
 *   여기서 prime[i]는 i번째 소수입니다.
 */
static const uint64_t K[80] = {
  0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
  0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
  0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
  0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

/* ============================================================================
 * SHA-512 핵심 압축 함수
 * ============================================================================ */

/**
 * sha512_compress - 단일 1024비트 블록을 압축하여 상태를 업데이트
 * 
 * SHA-512의 핵심 압축 함수로, 1024비트(128바이트) 입력 블록을 처리하여
 * 512비트(64바이트) 상태를 업데이트합니다.
 * 
 * 알고리즘:
 *   1. 입력 블록을 16개의 64비트 워드로 분할 (big-endian 변환)
 *   2. 메시지 스케줄 확장: 16개 워드를 80개로 확장
 *   3. 80라운드 압축: 각 라운드에서 상태 변수 업데이트
 *   4. 상태 누산: 라운드 결과를 기존 상태에 더함
 * 
 * @param state  8개의 64비트 워드로 구성된 해시 상태 (입력/출력)
 * @param block  128바이트 입력 블록
 */
static void sha512_compress(uint64_t state[8], const uint8_t block[128]){
    uint64_t w[80];  /* 메시지 스케줄 (80개 워드) */
    
    /* 입력을 16개의 64비트 big-endian 워드로 적재 */
    for (int i=0;i<16;i++){
        uint64_t t;
        memcpy(&t, block + 8*i, 8);
/* MSVC 윈도우 호환성을 위해 _WIN32 추가 */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
        w[i] = bswap64(t); /* 리틀엔디안 호스트(윈도우 포함)에서 변환 */
#else
        w[i] = t;  /* 빅엔디안 호스트에서는 변환 불필요 */
#endif
    }
    
    /* 메시지 스케줄 확장: 16개 워드를 80개로 확장 (W[16] ~ W[79]) */
    for (int i=16;i<80;i++){
        /* σ0: W[i-15]의 순환 시프트 및 XOR */
        uint64_t s0 = rotr64(w[i-15],1) ^ rotr64(w[i-15],8) ^ (w[i-15]>>7);
        /* σ1: W[i-2]의 순환 시프트 및 XOR */
        uint64_t s1 = rotr64(w[i-2],19) ^ rotr64(w[i-2],61) ^ (w[i-2]>>6);
        /* W[i] = W[i-16] + σ0(W[i-15]) + W[i-7] + σ1(W[i-2]) */
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    /* 작업 변수 초기화 (현재 상태 값으로) */
    uint64_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint64_t e=state[4], f=state[5], g=state[6], h=state[7];

    /* 80 라운드 압축 (FIPS 180-4 표준) */
    for (int i=0;i<80;i++){
        /* Σ1: E의 순환 시프트 및 XOR */
        uint64_t S1 = rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41);
        /* Ch: Choose 함수 (e & f) ^ (~e & g) */
        uint64_t ch = (e & f) ^ ((~e) & g);
        /* Temp1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i] */
        uint64_t temp1 = h + S1 + ch + K[i] + w[i];
        
        /* Σ0: A의 순환 시프트 및 XOR */
        uint64_t S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
        /* Maj: Majority 함수 (a & b) ^ (a & c) ^ (b & c) */
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        /* Temp2 = Σ0(a) + Maj(a,b,c) */
        uint64_t temp2 = S0 + maj;

        /* 상태 변수 업데이트 (라운드 함수) */
        h = g; g = f; f = e; e = d + temp1; 
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    /* 상태 누산: 라운드 결과를 기존 상태에 더함 */
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

/**
 * add_length - 총 처리 길이를 128비트 카운터에 더함
 * 
 * SHA-512는 최대 2^128-1 비트까지 처리할 수 있으므로,
 * 총 길이를 128비트(상위 64비트 + 하위 64비트)로 관리합니다.
 * 
 * @param c    SHA-512 컨텍스트
 * @param add  추가할 바이트 수
 */
static void add_length(SHA512_CTX* c, uint64_t add){
    uint64_t lo = c->tot_len_lo + add;
    /* 오버플로우(캐리) 발생 시 상위 64비트 증가 */
    c->tot_len_hi += (lo < c->tot_len_lo);
    c->tot_len_lo  = lo;
}

/**
 * sha512_init - SHA-512 해시 컨텍스트 초기화
 * 
 * SHA-512 해시 계산을 시작하기 위해 컨텍스트를 초기 상태로 설정합니다.
 * 초기화 벡터(IV)는 FIPS 180-4 표준에 따라 처음 8개 소수의 제곱근의
 * 분수부에서 추출된 값입니다.
 * 
 * @param c  초기화할 SHA-512 컨텍스트 포인터
 */
void sha512_init(SHA512_CTX* c){
    /* 초기화 벡터(FIPS 180-4 표준) */
    /* 각 값은 처음 8개 소수의 제곱근 분수부에서 추출 */
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };
    memcpy(c->h, iv, sizeof(iv));
    c->tot_len_hi = c->tot_len_lo = 0;  /* 총 길이 초기화 */
    c->buf_len = 0;  /* 버퍼 길이 초기화 */
}

/**
 * sha512_update - SHA-512 해시에 데이터 추가
 * 
 * 주어진 데이터를 해시 계산에 포함시킵니다. 이 함수는 여러 번 호출될 수 있으며,
 * 각 호출마다 데이터가 누적되어 해시에 반영됩니다.
 * 
 * 처리 과정:
 *   1. 이전에 남은 부분 블록이 있으면 먼저 채움
 *   2. 완전한 블록(128바이트)을 압축 함수로 처리
 *   3. 남은 미달 블록은 버퍼에 저장 (다음 호출 또는 final에서 처리)
 * 
 * @param c     SHA-512 컨텍스트 포인터
 * @param data  해시에 포함할 데이터
 * @param len   데이터 길이 (바이트)
 */
void sha512_update(SHA512_CTX* c, const void* data, size_t len){
    const uint8_t* p = (const uint8_t*)data;
    if (!len) return;

    /* 부분 블록이 남아 있으면 먼저 채우기 */
    if (c->buf_len){
        size_t take = SHA512_BLOCK_LEN - c->buf_len;  /* 버퍼에 채울 수 있는 바이트 수 */
        if (take > len) take = len;  /* 입력이 부족하면 입력 길이만큼만 */
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take; p += take; len -= take;
        
        /* 버퍼가 가득 차면 압축 */
        if (c->buf_len == SHA512_BLOCK_LEN){
            sha512_compress(c->h, c->buf);
            add_length(c, SHA512_BLOCK_LEN);
            c->buf_len = 0;
        }
    }

    /* 정수 개수의 완전한 블록 처리 (128바이트 단위) */
    while (len >= SHA512_BLOCK_LEN){
        sha512_compress(c->h, p);
        add_length(c, SHA512_BLOCK_LEN);
        p += SHA512_BLOCK_LEN; len -= SHA512_BLOCK_LEN;
    }

    /* 꼬리(미달 블록) 보관: 다음 update나 final에서 처리 */
    if (len){
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }
}

/**
 * sha512_final - SHA-512 해시 계산 완료 및 결과 출력
 * 
 * 모든 데이터가 추가된 후 최종 해시 값을 계산하고 출력합니다.
 * 
 * 처리 과정:
 *   1. 총 길이에 현재 버퍼 길이 추가
 *   2. 패딩 추가: 0x80 바이트 추가 후 0으로 채움
 *   3. 마지막 16바이트에 총 길이(비트 단위) 저장
 *   4. 마지막 블록 압축
 *   5. 최종 해시 값을 big-endian 형식으로 출력
 *   6. 컨텍스트 안전 삭제
 * 
 * @param c    SHA-512 컨텍스트 포인터
 * @param out  해시 결과 출력 버퍼 (64바이트)
 */
void sha512_final(SHA512_CTX* c, uint8_t out[SHA512_DIGEST_LEN]){
    /* 지금까지 처리된 총 길이에 현재 버퍼 길이 더하기 */
    add_length(c, (uint64_t)c->buf_len);

    /* 패딩 추가: 0x80 바이트 추가 (FIPS 180-4 표준) */
    c->buf[c->buf_len++] = 0x80;
    
    /* 마지막 16바이트는 길이 저장용이므로, 길이를 넣을 공간이 없으면 새 블록 필요 */
    if (c->buf_len > SHA512_BLOCK_LEN - 16){
        /* 현재 블록을 0으로 채워 압축 */
        memset(c->buf + c->buf_len, 0, SHA512_BLOCK_LEN - c->buf_len);
        sha512_compress(c->h, c->buf);
        c->buf_len = 0;
    }
    
    /* 나머지 공간을 0으로 채움 (길이 저장 공간 제외) */
    memset(c->buf + c->buf_len, 0, (SHA512_BLOCK_LEN - 16) - c->buf_len);

    /* 총 길이(바이트)를 비트로 변환해 128비트 big-endian으로 저장 */
    uint64_t hi = c->tot_len_hi; /* 바이트 단위 상위 64비트 */
    uint64_t lo = c->tot_len_lo; /* 바이트 단위 하위 64비트 */
    /* 비트 단위로 변환: 바이트 * 8 = 비트 */
    uint64_t bits_hi = (hi << 3) | (lo >> 61);  /* 상위 비트 */
    uint64_t bits_lo = (lo << 3);               /* 하위 비트 */
    
/* MSVC 윈도우 호환성을 위해 _WIN32 추가 */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
    bits_hi = bswap64(bits_hi);
    bits_lo = bswap64(bits_lo);
#endif
    /* 마지막 16바이트에 길이 저장 (big-endian) */
    memcpy(c->buf + SHA512_BLOCK_LEN - 16, &bits_hi, 8);
    memcpy(c->buf + SHA512_BLOCK_LEN - 8,  &bits_lo, 8);
    
    /* 마지막 블록 압축 */
    sha512_compress(c->h, c->buf);

    /* 최종 해시를 big-endian으로 출력 */
    for (int i=0;i<8;i++){
        uint64_t w = c->h[i];
/* MSVC 윈도우 호환성을 위해 _WIN32 추가 */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
        w = bswap64(w);  /* 리틀엔디안 시스템에서 변환 */
#endif
        memcpy(out + 8*i, &w, 8);
    }

    /* 컨텍스트 안전 삭제 (민감 정보 제거) */
    secure_zero(c, sizeof(*c));
}

/**
 * sha512 - 단일 호출로 SHA-512 해시 계산
 * 
 * 데이터를 한 번에 해시하는 편의 함수입니다.
 * 내부적으로 init, update, final을 순차적으로 호출합니다.
 * 
 * @param data  해시할 데이터
 * @param len   데이터 길이 (바이트)
 * @param out   해시 결과 출력 버퍼 (64바이트)
 */
void sha512(const void* data, size_t len, uint8_t out[SHA512_DIGEST_LEN]){
    SHA512_CTX c; 
    sha512_init(&c); 
    sha512_update(&c, data, len); 
    sha512_final(&c, out);
}

/* ============================================================================
 * HMAC-SHA-512 구현 (RFC 4231)
 * ============================================================================ */

/**
 * hmac_sha512 - HMAC-SHA-512 메시지 인증 코드 계산
 * 
 * HMAC (Hash-based Message Authentication Code) 알고리즘을 사용하여
 * 메시지의 무결성과 인증을 위한 태그를 생성합니다.
 * 
 * 알고리즘 (RFC 4231):
 *   HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
 * 
 * 처리 과정:
 *   1. 키 정규화: 키가 블록보다 길면 해시로 축약, 짧으면 0으로 패딩
 *   2. 내부 해시: H((K' ⊕ ipad) || msg) 계산
 *   3. 외부 해시: H((K' ⊕ opad) || inner_hash) 계산
 * 
 * @param key      MAC 키
 * @param key_len  키 길이 (바이트)
 * @param msg      인증할 메시지
 * @param msg_len  메시지 길이 (바이트)
 * @param out      HMAC 출력 버퍼 (64바이트)
 */
void hmac_sha512(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[HMAC_SHA512_LEN]){
    uint8_t kopad[SHA512_BLOCK_LEN]; /* K' ⊕ opad (0x5c) */
    uint8_t kipad[SHA512_BLOCK_LEN]; /* K' ⊕ ipad (0x36) */
    uint8_t khash[SHA512_DIGEST_LEN];/* 키 축약용 임시 버퍼 */

    /* 키가 블록보다 길면 해시로 축약 (RFC 4231) */
    if (key_len > SHA512_BLOCK_LEN){
        sha512(key, key_len, khash);
        key = khash; key_len = SHA512_DIGEST_LEN;
    }
    
    /* 패딩 초기화: opad(0x5c), ipad(0x36) */
    memset(kopad, 0x5c, sizeof(kopad));
    memset(kipad, 0x36, sizeof(kipad));
    
    /* 키와 패딩 XOR 연산 */
    for (size_t i=0;i<key_len;i++){ 
        kopad[i]^=key[i]; 
        kipad[i]^=key[i]; 
    }

    /* 내부 해시: H((K' ⊕ ipad) || msg) */
    SHA512_CTX c; 
    sha512_init(&c);
    sha512_update(&c, kipad, sizeof(kipad));
    sha512_update(&c, msg, msg_len);
    sha512_final(&c, khash);

    /* 외부 해시: H((K' ⊕ opad) || inner_hash) */
    sha512_init(&c);
    sha512_update(&c, kopad, sizeof(kopad));
    sha512_update(&c, khash, sizeof(khash));
    sha512_final(&c, out);

    /* 임시 버퍼 안전 삭제 */
    secure_zero(kopad, sizeof(kopad));
    secure_zero(kipad, sizeof(kipad));
    secure_zero(khash, sizeof(khash));
}

/* ============================================================================
 * HKDF-SHA-512 구현 (RFC 5869)
 * ============================================================================ */

/**
 * hkdf_sha512_extract - HKDF Extract 단계 수행
 * 
 * HKDF (HMAC-based Key Derivation Function)의 Extract 단계를 수행합니다.
 * 입력 키 재료(IKM)와 솔트(salt)로부터 의사 난수 키(PRK)를 생성합니다.
 * 
 * 알고리즘 (RFC 5869):
 *   PRK = HMAC-SHA-512(salt, IKM)
 * 
 * 주의사항:
 *   - salt가 NULL이거나 길이가 0이면, 64바이트 제로 패딩을 사용
 *   - 이는 RFC 5869 표준에 따른 동작입니다
 * 
 * @param salt      솔트 (선택적, NULL이면 제로 패딩 사용)
 * @param salt_len  솔트 길이 (바이트)
 * @param ikm       입력 키 재료 (Input Keying Material)
 * @param ikm_len   IKM 길이 (바이트)
 * @param prk       출력 PRK 버퍼 (64바이트)
 */
void hkdf_sha512_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[HKDF_SHA512_PRK_LEN])
{
    /* RFC 5869: salt가 없으면 HashLen (64바이트) 길이의 0을 사용 */
    static const uint8_t zeros[SHA512_DIGEST_LEN] = {0};
    const uint8_t* s;
    size_t s_len;

    if (salt_len == 0) {
        s = zeros;
        s_len = SHA512_DIGEST_LEN; /* 0이 아닌 64로 설정 */
    } else {
        s = salt;
        s_len = salt_len;
    }
    /* PRK = HMAC-SHA-512(salt, IKM) */
    hmac_sha512(s, s_len, ikm, ikm_len, prk);
}

/**
 * hkdf_sha512_expand - HKDF Expand 단계 수행
 * 
 * HKDF의 Expand 단계를 수행합니다. PRK와 정보 문자열(info)을 사용하여
 * 원하는 길이의 출력 키 재료(OKM)를 생성합니다.
 * 
 * 알고리즘 (RFC 5869):
 *   OKM = T(1) || T(2) || ... || T(L)
 *   T(i) = HMAC-SHA-512(PRK, T(i-1) || info || i)
 *   (T(0)는 빈 문자열)
 * 
 * 제한사항:
 *   - 최대 OKM 길이: 255 * 64 = 16,320 바이트 (RFC 5869 제한)
 * 
 * @param prk       PRK (Extract 단계에서 생성, 64바이트)
 * @param info      정보 문자열 (도메인 분리용, 선택적)
 * @param info_len  정보 문자열 길이 (바이트)
 * @param okm       출력 키 재료 버퍼
 * @param okm_len   원하는 OKM 길이 (바이트, 최대 255*64)
 * 
 * @return HKDF_SHA512_OK 성공, HKDF_SHA512_ERR 실패 (길이 제한 초과)
 */
int hkdf_sha512_expand(const uint8_t* prk,
                       const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len){
    if (okm_len == 0) return HKDF_SHA512_OK;
    if (okm_len > 255u*SHA512_DIGEST_LEN) return HKDF_SHA512_ERR; /* RFC 제한 */

    uint8_t t[SHA512_DIGEST_LEN];  /* T(i) 임시 버퍼 */
    size_t tlen = 0;                /* 이전 T(i-1) 길이 */
    uint8_t counter = 1;            /* 라운드 카운터 (1부터 시작) */
    size_t pos = 0;                 /* OKM 출력 위치 */
    
    while (pos < okm_len){
        /* T(i) = HMAC-SHA-512(PRK, T(i-1) || info || counter) */
        SHA512_CTX c; 
        sha512_init(&c);
        
        /* 매 라운드마다 HMAC 수동 구성(동적 할당 회피) */
        uint8_t kopad[SHA512_BLOCK_LEN];  /* PRK ⊕ opad */
        uint8_t kipad[SHA512_BLOCK_LEN];  /* PRK ⊕ ipad */
        memset(kopad, 0x5c, sizeof(kopad)); 
        memset(kipad, 0x36, sizeof(kipad));
        for (size_t i=0;i<SHA512_DIGEST_LEN;i++){ 
            kopad[i]^=prk[i]; 
            kipad[i]^=prk[i]; 
        }

        /* 내부 해시: H((PRK ⊕ ipad) || T(i-1) || info || counter) */
        sha512_update(&c, kipad, sizeof(kipad));
        if (tlen) sha512_update(&c, t, tlen);  /* T(i-1) 추가 (i>1인 경우) */
        if (info && info_len) sha512_update(&c, info, info_len);  /* info 추가 */
        sha512_update(&c, &counter, 1);  /* 카운터 추가 */
        sha512_final(&c, t);

        /* 외부 해시: H((PRK ⊕ opad) || inner_hash) */
        sha512_init(&c);
        sha512_update(&c, kopad, sizeof(kopad));
        sha512_update(&c, t, SHA512_DIGEST_LEN);
        sha512_final(&c, t);

        /* T(i)를 OKM에 복사 (필요한 만큼만) */
        size_t remain = okm_len - pos;
        size_t take   = (remain > SHA512_DIGEST_LEN) ? SHA512_DIGEST_LEN : remain;
        memcpy(okm + pos, t, take);
        pos += take;
        tlen = SHA512_DIGEST_LEN;  /* 다음 라운드를 위해 T(i) 길이 저장 */
        counter++;
        
        /* 임시 버퍼 안전 삭제 */
        secure_zero(kopad, sizeof(kopad)); 
        secure_zero(kipad, sizeof(kipad));
    }
    secure_zero(t, sizeof(t));
    return HKDF_SHA512_OK;
}

/**
 * hkdf_sha512 - HKDF 전체 과정 수행 (Extract + Expand)
 * 
 * HKDF의 Extract와 Expand 단계를 한 번에 수행하는 편의 함수입니다.
 * 
 * 처리 과정:
 *   1. Extract: PRK = HMAC-SHA-512(salt, IKM)
 *   2. Expand: OKM = HKDF-Expand(PRK, info, okm_len)
 * 
 * @param salt      솔트 (선택적)
 * @param salt_len  솔트 길이 (바이트)
 * @param ikm       입력 키 재료
 * @param ikm_len   IKM 길이 (바이트)
 * @param info      정보 문자열 (도메인 분리용)
 * @param info_len  정보 문자열 길이 (바이트)
 * @param okm       출력 키 재료 버퍼
 * @param okm_len   원하는 OKM 길이 (바이트)
 * 
 * @return HKDF_SHA512_OK 성공, HKDF_SHA512_ERR 실패
 */
int hkdf_sha512(const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm,  size_t ikm_len,
                const uint8_t* info, size_t info_len,
                uint8_t* okm, size_t okm_len){
    uint8_t prk[HKDF_SHA512_PRK_LEN];
    hkdf_sha512_extract(salt, salt_len, ikm, ikm_len, prk);
    int rc = hkdf_sha512_expand(prk, info, info_len, okm, okm_len);
    secure_zero(prk, sizeof(prk));  /* PRK 안전 삭제 */
    return rc;
}

/* ============================================================================
 * 보안 유틸리티 함수
 * ============================================================================ */

/**
 * secure_zero - 메모리 영역을 안전하게 제로화
 * 
 * 민감한 데이터(키, 중간값 등)를 메모리에서 완전히 제거합니다.
 * 컴파일러 최적화로 인한 제거를 방지하기 위해 플랫폼별 안전한 방법을 사용합니다.
 * 
 * 플랫폼별 구현:
 *   - Windows: SecureZeroMemory (Windows API)
 *   - C11: memset_s (표준 라이브러리 확장)
 *   - 기타: volatile 포인터 사용 (최적화 방지)
 * 
 * @param p  제로화할 메모리 영역의 시작 주소
 * @param n  제로화할 바이트 수
 */
void secure_zero(void* p, size_t n){
#ifdef _WIN32
    SecureZeroMemory(p, n);  /* Windows API 사용 */
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);  /* C11 표준 확장 사용 */
#else
    /* volatile 포인터로 최적화 방지 */
    volatile uint8_t* v = (volatile uint8_t*)p; 
    while (n--) *v++ = 0;
#endif
}

/**
 * ct_memcmp - 상수시간 메모리 비교
 * 
 * 두 메모리 영역을 상수시간에 비교합니다. 타이밍 공격을 방지하기 위해
 * 비교 결과와 무관하게 항상 동일한 시간이 소요됩니다.
 * 
 * 구현 방식:
 *   - 모든 바이트를 XOR 연산으로 비교
 *   - 결과를 OR 연산으로 누적
 *   - 일치하면 0, 불일치하면 0이 아닌 값 반환
 * 
 * @param a  첫 번째 메모리 영역
 * @param b  두 번째 메모리 영역
 * @param n  비교할 바이트 수
 * 
 * @return 0 두 영역이 동일, 0이 아니면 다름
 */
int ct_memcmp(const void* a, const void* b, size_t n){
    const uint8_t* x=(const uint8_t*)a; 
    const uint8_t* y=(const uint8_t*)b; 
    uint8_t r=0;
    for (size_t i=0;i<n;i++) r |= (uint8_t)(x[i]^y[i]);
    return r; /* 같으면 0, 다르면 !=0 */
}

/* ============================================================================
 * 자가진단 함수
 * ============================================================================ */

/**
 * hex_nibble - 16진수 문자를 숫자로 변환
 * 
 * @param c  16진수 문자 ('0'-'9', 'a'-'f', 'A'-'F')
 * @return 0-15 숫자, 유효하지 않은 문자면 -1
 */
static int hex_nibble(char c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

/**
 * check_hex - 바이너리 데이터와 16진수 문자열 비교
 * 
 * 바이너리 데이터와 16진수 문자열을 비교하여 일치 여부를 확인합니다.
 * 
 * @param got  비교할 바이너리 데이터
 * @param hex  16진수 문자열 (2글자 = 1바이트)
 * @return 0 일치, -1 불일치 또는 형식 오류
 */
static int check_hex(const uint8_t* got, const char* hex){
    /* got(바이너리)와 hex(문자열)를 비교. hex는 연속된 2글자=1바이트 */
    for (size_t i=0; hex[2*i] && hex[2*i+1]; ++i){
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i+1]);
        if (hi<0||lo<0) return -1;  /* 잘못된 16진수 문자 */
        if (got[i] != (uint8_t)((hi<<4)|lo)) return -1;  /* 불일치 */
    }
    return 0;
}

/**
 * sha512_selftest - SHA-512 구현 자가진단 테스트
 * 
 * SHA-512, HMAC-SHA-512, HKDF-SHA-512 구현의 정확성을 검증하기 위한
 * Known Answer Test(KAT)를 수행합니다. 표준 테스트 벡터를 사용하여
 * 각 함수가 올바르게 동작하는지 확인합니다.
 * 
 * 테스트 내용:
 *   1. SHA-512("") - 빈 문자열 해시 (FIPS 180-4)
 *   2. HMAC-SHA-512 Test Case 1 (RFC 4231)
 *   3. HKDF-SHA-512 간단 검증 (RFC 5869)
 * 
 * @return 0 모든 테스트 통과, 음수 테스트 실패 (반환값으로 실패한 테스트 식별)
 */
int sha512_selftest(void){
    /* SHA-512("") 공백 문자열 테스트(FIPS 180-4 표준) */
    static const char* empty_full =
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    uint8_t d[64]; 
    sha512("", 0, d);
    if (check_hex(d, empty_full)) return -1;  /* SHA-512 테스트 실패 */

    /* RFC 4231 HMAC-SHA-512: Test Case 1 */
    /* 키: 20바이트, 모두 0x0b */
    uint8_t key_tc1[20];
    memset(key_tc1, 0x0b, sizeof(key_tc1));
    const char* data_tc1 = "Hi There"; /* 길이 8 */
    const char* mac_tc1_hex =
      "87aa7cdea5ef619d4ff0b4241a1d6cb0"
      "2379f4e2ce4ec2787ad0b30545e17cde"
      "daa833b7d6b8a702038b274eaea3f4e4"
      "be9d914eeb61f1702e696c203a126854";
    hmac_sha512(key_tc1, sizeof(key_tc1), (const uint8_t*)data_tc1, 8, d);
    if (check_hex(d, mac_tc1_hex)) return -2;  /* HMAC 테스트 실패 */

    /* HKDF-SHA-512 RFC 5869 일부 스팟 체크: 구현 검증용 간단 검증 */
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));  /* IKM: 22바이트, 모두 0x0b */
    const uint8_t salt[13] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c };
    const uint8_t info[10] = { 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };
    uint8_t okm[42];
    hkdf_sha512(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm, sizeof(okm));
    /* 첫 바이트/중간/마지막 간단 점검(정식 전체 비교는 프로젝트 테스트에 위임) */
    if (okm[0]!=0x83 || okm[31]!=0x93 || okm[41]!=0xcb) return -3;  /* HKDF 테스트 실패 */
    
    /* 테스트용 데이터 안전 삭제 */
    secure_zero(key_tc1, sizeof(key_tc1)); 
    secure_zero(ikm, sizeof(ikm));

    return 0;  /* 모든 테스트 통과 */
}