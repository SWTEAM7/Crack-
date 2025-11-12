/* =========================================================================
 * sha512.h - SHA-512, HMAC-SHA-512, HKDF-SHA-512 (RFC 6234 / RFC 4231 / RFC 5869)
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

/* --- 내부 헬퍼 ---------------------------------------------------------- */
static inline uint64_t rotr64(uint64_t x, unsigned r){ r &= 63u; return (x>>r) | (x<<(64u-r)); }
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

/* SHA-512 라운드 상수(소수의 세제곱근 분수부) */
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

/* 단일 1024비트 블록 압축 함수 */
static void sha512_compress(uint64_t state[8], const uint8_t block[128]){
    uint64_t w[80];
    /* 입력을 16개의 64비트 big-endian 워드로 적재 */
    for (int i=0;i<16;i++){
        uint64_t t;
        memcpy(&t, block + 8*i, 8);
/* MSVC 윈도우 호환성을 위해 _WIN32 추가 */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
        w[i] = bswap64(t); /* 리틀엔디안 호스트(윈도우 포함)에서 변환 */
#else
        w[i] = t;
#endif
    }
    /* 메시지 스케줄 확장(80워드) */
    for (int i=16;i<80;i++){
        uint64_t s0 = rotr64(w[i-15],1) ^ rotr64(w[i-15],8) ^ (w[i-15]>>7);
        uint64_t s1 = rotr64(w[i-2],19) ^ rotr64(w[i-2],61) ^ (w[i-2]>>6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    /* 작업 변수 초기화 */
    uint64_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint64_t e=state[4], f=state[5], g=state[6], h=state[7];

    /* 80 라운드 */
    for (int i=0;i<80;i++){
        uint64_t S1 = rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = h + S1 + ch + K[i] + w[i];
        uint64_t S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }

    /* 상태 누산 */
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

/* 총 길이(바이트)를 128비트 카운터에 더함 */
static void add_length(SHA512_CTX* c, uint64_t add){
    uint64_t lo = c->tot_len_lo + add;
    c->tot_len_hi += (lo < c->tot_len_lo); /* 캐리 발생 시 상위 증가 */
    c->tot_len_lo  = lo;
}

void sha512_init(SHA512_CTX* c){
    /* 초기화 벡터(FIPS 180-4) */
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };
    memcpy(c->h, iv, sizeof(iv));
    c->tot_len_hi = c->tot_len_lo = 0;
    c->buf_len = 0;
}

void sha512_update(SHA512_CTX* c, const void* data, size_t len){
    const uint8_t* p = (const uint8_t*)data;
    if (!len) return;

    /* 부분 블록이 남아 있으면 채우기 */
    if (c->buf_len){
        size_t take = SHA512_BLOCK_LEN - c->buf_len;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take; p += take; len -= take;
        if (c->buf_len == SHA512_BLOCK_LEN){
            sha512_compress(c->h, c->buf);
            add_length(c, SHA512_BLOCK_LEN);
            c->buf_len = 0;
        }
    }

    /* 정수 개수의 블록 처리 */
    while (len >= SHA512_BLOCK_LEN){
        sha512_compress(c->h, p);
        add_length(c, SHA512_BLOCK_LEN);
        p += SHA512_BLOCK_LEN; len -= SHA512_BLOCK_LEN;
    }

    /* 꼬리(미달 블록) 보관 */
    if (len){
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }
}

void sha512_final(SHA512_CTX* c, uint8_t out[SHA512_DIGEST_LEN]){
    /* 지금까지 처리된 총 길이에 현재 버퍼 길이 더하기 */
    add_length(c, (uint64_t)c->buf_len);

    /* 0x80 추가 후 0 패딩, 마지막 16바이트는 길이(비트단위) 저장용 */
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > SHA512_BLOCK_LEN - 16){
        /* 길이를 이 블록에 못 넣으면 0으로 채워 압축 */
        memset(c->buf + c->buf_len, 0, SHA512_BLOCK_LEN - c->buf_len);
        sha512_compress(c->h, c->buf);
        c->buf_len = 0;
    }
    memset(c->buf + c->buf_len, 0, (SHA512_BLOCK_LEN - 16) - c->buf_len);

    /* 총 길이(바이트)를 비트로 변환해 128비트 big-endian으로 저장 */
    uint64_t hi = c->tot_len_hi; /* 바이트 */
    uint64_t lo = c->tot_len_lo;
    uint64_t bits_hi = (hi << 3) | (lo >> 61);
    uint64_t bits_lo = (lo << 3);
/* MSVC 윈도우 호환성을 위해 _WIN32 추가 */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
    bits_hi = bswap64(bits_hi);
    bits_lo = bswap64(bits_lo);
#endif
    memcpy(c->buf + SHA512_BLOCK_LEN - 16, &bits_hi, 8);
    memcpy(c->buf + SHA512_BLOCK_LEN - 8,  &bits_lo, 8);
    sha512_compress(c->h, c->buf);

    /* 최종 해시를 big-endian으로 출력 */
    for (int i=0;i<8;i++){
        uint64_t w = c->h[i];
/* MSVC 윈도우 호환성을 위해 _WIN32 추가 */
#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_WIN32)
        w = bswap64(w);
#endif
        memcpy(out + 8*i, &w, 8);
    }

    secure_zero(c, sizeof(*c));
}

void sha512(const void* data, size_t len, uint8_t out[SHA512_DIGEST_LEN]){
    SHA512_CTX c; sha512_init(&c); sha512_update(&c, data, len); sha512_final(&c, out);
}

/* --- HMAC --------------------------------------------------------------- */
void hmac_sha512(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[HMAC_SHA512_LEN]){
    uint8_t kopad[SHA512_BLOCK_LEN]; /* K ⊕ opad (0x5c) */
    uint8_t kipad[SHA512_BLOCK_LEN]; /* K ⊕ ipad (0x36) */
    uint8_t khash[SHA512_DIGEST_LEN];/* 키 축약용 임시 버퍼 */

    /* 키가 블록보다 길면 해시로 축약 */
    if (key_len > SHA512_BLOCK_LEN){
        sha512(key, key_len, khash);
        key = khash; key_len = SHA512_DIGEST_LEN;
    }
    memset(kopad, 0x5c, sizeof(kopad));
    memset(kipad, 0x36, sizeof(kipad));
    for (size_t i=0;i<key_len;i++){ kopad[i]^=key[i]; kipad[i]^=key[i]; }

    /* inner: H( (K⊕ipad) || msg ) */
    SHA512_CTX c; sha512_init(&c);
    sha512_update(&c, kipad, sizeof(kipad));
    sha512_update(&c, msg, msg_len);
    sha512_final(&c, khash);

    /* outer: H( (K⊕opad) || inner ) */
    sha512_init(&c);
    sha512_update(&c, kopad, sizeof(kopad));
    sha512_update(&c, khash, sizeof(khash));
    sha512_final(&c, out);

    secure_zero(kopad, sizeof(kopad));
    secure_zero(kipad, sizeof(kipad));
    secure_zero(khash, sizeof(khash));
}

/* --- HKDF --------------------------------------------------------------- */
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
    hmac_sha512(s, s_len, ikm, ikm_len, prk);
}

int hkdf_sha512_expand(const uint8_t* prk,
                       const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len){
    if (okm_len == 0) return HKDF_SHA512_OK;
    if (okm_len > 255u*SHA512_DIGEST_LEN) return HKDF_SHA512_ERR; /* RFC 제한 */

    uint8_t t[SHA512_DIGEST_LEN]; size_t tlen = 0; uint8_t counter = 1;
    size_t pos = 0;
    while (pos < okm_len){
        /* T(i) = HMAC(PRK, T(i-1) | info | counter) */
        SHA512_CTX c; sha512_init(&c);
        /* 매 라운드마다 HMAC 수동 구성(할당 회피) */
        uint8_t kopad[SHA512_BLOCK_LEN];
        uint8_t kipad[SHA512_BLOCK_LEN];
        memset(kopad, 0x5c, sizeof(kopad)); memset(kipad, 0x36, sizeof(kipad));
        for (size_t i=0;i<SHA512_DIGEST_LEN;i++){ kopad[i]^=prk[i]; kipad[i]^=prk[i]; }

        /* inner */
        sha512_update(&c, kipad, sizeof(kipad));
        if (tlen) sha512_update(&c, t, tlen);
        if (info && info_len) sha512_update(&c, info, info_len);
        sha512_update(&c, &counter, 1);
        sha512_final(&c, t);

        /* outer */
        sha512_init(&c);
        sha512_update(&c, kopad, sizeof(kopad));
        sha512_update(&c, t, SHA512_DIGEST_LEN);
        sha512_final(&c, t);

        size_t remain = okm_len - pos;
				size_t take   = (remain > SHA512_DIGEST_LEN) ? SHA512_DIGEST_LEN : remain;
				memcpy(okm + pos, t, take);
				pos += take;
				tlen = SHA512_DIGEST_LEN;
				counter++;
        secure_zero(kopad, sizeof(kopad)); secure_zero(kipad, sizeof(kipad));
    }
    secure_zero(t, sizeof(t));
    return HKDF_SHA512_OK;
}

int hkdf_sha512(const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm,  size_t ikm_len,
                const uint8_t* info, size_t info_len,
                uint8_t* okm, size_t okm_len){
    uint8_t prk[HKDF_SHA512_PRK_LEN];
    hkdf_sha512_extract(salt, salt_len, ikm, ikm_len, prk);
    int rc = hkdf_sha512_expand(prk, info, info_len, okm, okm_len);
    secure_zero(prk, sizeof(prk));
    return rc;
}

/* --- 유틸 --------------------------------------------------------------- */
void secure_zero(void* p, size_t n){
#ifdef _WIN32
    SecureZeroMemory(p, n);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile uint8_t* v = (volatile uint8_t*)p; while (n--) *v++ = 0; /* 최적화 제거용 */
#endif
}

int ct_memcmp(const void* a, const void* b, size_t n){
    const uint8_t* x=(const uint8_t*)a; const uint8_t* y=(const uint8_t*)b; uint8_t r=0;
    for (size_t i=0;i<n;i++) r |= (uint8_t)(x[i]^y[i]);
    return r; /* 같으면 0, 다르면 !=0 */
}

/* --- 간단 자기진단 ------------------------------------------------------ */
static int hex_nibble(char c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

static int check_hex(const uint8_t* got, const char* hex){
    /* got(바이너리)와 hex(문자열)를 비교. hex는 연속된 2글자=1바이트 */
    for (size_t i=0; hex[2*i] && hex[2*i+1]; ++i){
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i+1]);
        if (hi<0||lo<0) return -1;
        if (got[i] != (uint8_t)((hi<<4)|lo)) return -1;
    }
    return 0;
}

int sha512_selftest(void){
    /* SHA-512("") 공백 문자열 테스트(FIPS 180-4) */
    static const char* empty_full =
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    uint8_t d[64]; sha512("", 0, d);
    if (check_hex(d, empty_full)) return -1;

    /* RFC 4231 HMAC-SHA-512: Test Case 1 */
    /* const uint8_t key_tc1[20] = { [0 ... 19] = 0x0b }; */ /* MSVC 호환성을 위해 memset 사용 */
    uint8_t key_tc1[20];
    memset(key_tc1, 0x0b, sizeof(key_tc1));
    const char* data_tc1 = "Hi There"; /* 길이 8 */
    const char* mac_tc1_hex =
      "87aa7cdea5ef619d4ff0b4241a1d6cb0"
      "2379f4e2ce4ec2787ad0b30545e17cde"
      "daa833b7d6b8a702038b274eaea3f4e4"
      "be9d914eeb61f1702e696c203a126854";
    hmac_sha512(key_tc1, sizeof(key_tc1), (const uint8_t*)data_tc1, 8, d);
    if (check_hex(d, mac_tc1_hex)) return -2;

    /* (선택) HKDF-SHA-512 RFC 5869 일부 스팟 체크: 구현 검증용 간단 검증 */
    /* const uint8_t ikm[22] = { [0 ... 21] = 0x0b }; */ /* MSVC 호환성을 위해 memset 사용 */
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    const uint8_t salt[13] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c };
    const uint8_t info[10] = { 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };
    uint8_t okm[42];
    hkdf_sha512(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm, sizeof(okm));
    /* 첫 바이트/중간/마지막 간단 점검(정식 전체 비교는 프로젝트 테스트에 위임) */
    if (okm[0]!=0x83 || okm[31]!=0x93 || okm[41]!=0xcb) return -3;
    
    secure_zero(key_tc1, sizeof(key_tc1)); /* 테스트용 키 정리 */
    secure_zero(ikm, sizeof(ikm));         /* 테스트용 ikm 정리 */

    return 0;
}