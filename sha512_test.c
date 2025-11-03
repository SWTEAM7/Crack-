// test.c — SHA-512 / HMAC-SHA-512 / (옵션) HKDF-SHA-512 테스트 드라이버
// 빌드 예시:
//   clang -O3 -std=c99 -Wall -Wextra sha512.c test.c -o test
//   cl /O2 /W4 /D_CRT_SECURE_NO_WARNINGS sha512.c test.c
//
// OpenSSL로 HKDF 교차검증을 하고 싶다면 (선택):
//   clang -O3 -std=c99 -Wall -Wextra sha512.c test.c -DTEST_WITH_OPENSSL -lcrypto -o test
//   (Windows) cl /O2 /W4 /DTEST_WITH_OPENSSL sha512.c test.c /link libcrypto.lib
//
// 실행 결과가 모두 OK면 0을 리턴합니다.

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sha512.h"

static void dump_hex(const uint8_t* p, size_t n){
    for(size_t i=0;i<n;i++) printf("%02x", p[i]);
    puts("");
}

static int expect_hex_eq(const uint8_t* got, size_t n, const char* hex){
    // hex는 공백없이 2글자=1바이트
    for(size_t i=0;i<n;i++){
        char h0 = hex[2*i], h1 = hex[2*i+1];
        if(!h0 || !h1) return -1; // 길이 불일치
        int v0 = (h0>='0'&&h0<='9')? h0-'0' : (h0>='a'&&h0<='f')? h0-'a'+10 : (h0>='A'&&h0<='F')? h0-'A'+10 : -1;
        int v1 = (h1>='0'&&h1<='9')? h1-'0' : (h1>='a'&&h1<='f')? h1-'a'+10 : (h1>='A'&&h1<='F')? h1-'A'+10 : -1;
        if (v0<0 || v1<0) return -1;
        uint8_t exp = (uint8_t)((v0<<4)|v1);
        if (got[i] != exp) return -1;
    }
    return 0;
}

static int test_selftest(void){
    int rc = sha512_selftest();
    printf("[selftest] rc=%d — %s\n", rc, rc==0?"OK":"FAIL");
    return rc==0 ? 0 : -1;
}

static int test_sha512_vectors(void){
    int ok = 1;
    uint8_t d[SHA512_DIGEST_LEN];

    // SHA-512("")
    static const char* empty_hex =
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    sha512("", 0, d);
    if (expect_hex_eq(d, 64, empty_hex)!=0){ puts("[SHA-512 \"\"] FAIL"); ok=0; }

    // SHA-512("abc")
    static const char* abc_hex =
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    sha512("abc", 3, d);
    if (expect_hex_eq(d, 64, abc_hex)!=0){ puts("[SHA-512 \"abc\"] FAIL"); ok=0; }

    printf("[sha512 vectors] %s\n", ok?"OK":"FAIL");
    return ok?0:-1;
}

static int test_hmac_rfc4231_tc1(void){
    // RFC 4231, Test Case 1:
    // key = 0x0b * 20, data = "Hi There"
    // expected mac =
    // 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde
    // daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
    uint8_t key[20]; memset(key, 0x0b, sizeof(key));
    const char* msg = "Hi There";
    uint8_t mac[HMAC_SHA512_LEN];
    static const char* mac_hex =
      "87aa7cdea5ef619d4ff0b4241a1d6cb0"
      "2379f4e2ce4ec2787ad0b30545e17cde"
      "daa833b7d6b8a702038b274eaea3f4e4"
      "be9d914eeb61f1702e696c203a126854";
    hmac_sha512(key, sizeof(key), (const uint8_t*)msg, 8, mac);
    int rc = expect_hex_eq(mac, 64, mac_hex);
    printf("[hmac rfc4231 tc1] %s\n", rc==0?"OK":"FAIL");
    return rc==0 ? 0 : -1;
}

static int test_streaming_equivalence(void){
    // 입력을 여러 조각으로 update했을 때 결과가 원샷과 동일해야 함
    const uint8_t bigmsg[] =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs. "
        "Sphinx of black quartz, judge my vow.";

    uint8_t d1[SHA512_DIGEST_LEN], d2[SHA512_DIGEST_LEN];

    // 원샷
    sha512(bigmsg, sizeof(bigmsg)-1, d1);

    // 스트리밍: 1) 13바이트씩, 2) 1바이트씩
    SHA512_CTX c; sha512_init(&c);
    size_t pos=0, n=sizeof(bigmsg)-1;
    while (pos<n){
        size_t take = 13; if (take > n-pos) take = n-pos;
        sha512_update(&c, bigmsg+pos, take);
        pos += take;
    }
    sha512_final(&c, d2);

    int ok = (ct_memcmp(d1,d2,SHA512_DIGEST_LEN)==0);
    if (!ok){ puts("[streaming eq 13B] FAIL"); return -1; }

    // 1바이트씩
    sha512_init(&c);
    for (size_t i=0;i<n;i++) sha512_update(&c, bigmsg+i, 1);
    sha512_final(&c, d2);
    ok = (ct_memcmp(d1,d2,SHA512_DIGEST_LEN)==0);
    printf("[streaming equivalence] %s\n", ok?"OK":"FAIL");
    return ok?0:-1;
}

#ifdef TEST_WITH_OPENSSL
// OpenSSL로 HKDF-SHA-512 교차검증 (선택)
#include <openssl/evp.h>
static int test_hkdf_openssl_crosscheck(void){
    // RFC 5869 Test Case 1의 파라미터를 그대로 사용(OKM 길이는 42바이트)
    // 단, RFC5869 본문 테스트 벡터는 HMAC-SHA-256 기준이지만
    // 여기서는 '같은 파라미터'로 HMAC-SHA-512를 돌려 교차검증만 수행한다.
    uint8_t ikm[22]; memset(ikm, 0x0b, sizeof(ikm));
    const uint8_t salt[13] = {0,1,2,3,4,5,6,7,8,9,10,11,12};
    const uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    uint8_t okm_my[42], okm_ssl[42];

    // 내 구현
    if (hkdf_sha512(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm_my, sizeof(okm_my)) != 0){
        puts("[hkdf my] FAIL(expand)"); return -1;
    }

    // OpenSSL HKDF (SHA-512)
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) { puts("[openssl hkdf] FAIL(ctx)"); return -1; }
    int rc = EVP_PKEY_derive_init(pctx);
    rc &= EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512());
    rc &= EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)sizeof(salt));
    rc &= EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)sizeof(ikm));
    rc &= EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)sizeof(info));
    size_t outlen = sizeof(okm_ssl);
    rc &= EVP_PKEY_derive(pctx, okm_ssl, &outlen);
    EVP_PKEY_CTX_free(pctx);
    if (!rc || outlen != sizeof(okm_ssl)){ puts("[openssl hkdf] FAIL(derive)"); return -1; }

    int same = (ct_memcmp(okm_my, okm_ssl, sizeof(okm_ssl))==0);
    printf("[hkdf sha512 x-check openssl] %s\n", same?"OK":"FAIL");
    if (!same){
        puts("mine:"); dump_hex(okm_my, sizeof(okm_my));
        puts("ossl:"); dump_hex(okm_ssl, sizeof(okm_ssl));
        return -1;
    }
    return 0;
}
#endif

int main(void){
    int rc = 0;
    rc |= test_selftest();
    rc |= test_sha512_vectors();
    rc |= test_hmac_rfc4231_tc1();
    rc |= test_streaming_equivalence();
#ifdef TEST_WITH_OPENSSL
    rc |= test_hkdf_openssl_crosscheck();
#endif
    puts(rc==0? "\nALL TESTS: OK" : "\nSOME TESTS FAILED");
    return rc==0 ? 0 : 1;
}
