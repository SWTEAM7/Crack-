#include "aes.h"
#include <string.h>

#define AES_BLOCK 16

// ─────────────────────────────────────────────────────────────────────────────
// 내부 상수/테이블 (FIPS-197)
// ─────────────────────────────────────────────────────────────────────────────

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

static const uint8_t Rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// GF(2^8) helpers
static inline uint8_t xtime(uint8_t x){ return (uint8_t)((x<<1) ^ ((x&0x80)?0x1B:0x00)); }
static inline uint8_t mul(uint8_t x, uint8_t y) {
    // 러시안 곱 (작고 빠름)
    uint8_t r = 0;
    while (y) { if (y & 1) r ^= x; x = xtime(x); y >>= 1; }
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// 에러/헬퍼
// ─────────────────────────────────────────────────────────────────────────────

static void aes_set_error(AES_ctx* ctx, AESStatus code, const char* msg) {
    if (ctx) ctx->last_err = code;
    if (ctx && ctx->on_error) ctx->on_error(code, msg, ctx->err_ud);
}

static int no_forbidden_overlap(const void* p1, size_t n1,
                                const void* p2, size_t n2) {
    const uint8_t* a=(const uint8_t*)p1; const uint8_t* b=(const uint8_t*)p2;
    return (a+n1<=b) || (b+n2<=a);
}

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
// 키 스케줄 (FIPS-197)
// roundKeys: 4*(Nr+1) words. ctx->roundKeys에 big-endian 워드로 저장.
// ─────────────────────────────────────────────────────────────────────────────

static inline uint32_t pack_be(const uint8_t b[4]) {
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}
static inline void unpack_be(uint32_t w, uint8_t b[4]) {
    b[0]=(uint8_t)(w>>24); b[1]=(uint8_t)(w>>16); b[2]=(uint8_t)(w>>8); b[3]=(uint8_t)w;
}

static inline uint32_t SubWord(uint32_t w) {
    uint8_t b[4]; unpack_be(w,b);
    b[0]=sbox[b[0]]; b[1]=sbox[b[1]]; b[2]=sbox[b[2]]; b[3]=sbox[b[3]];
    return pack_be(b);
}
static inline uint32_t RotWord(uint32_t w) {
    return (w<<8) | (w>>24);
}

static void key_expansion(AES_ctx* ctx, const uint8_t* key, AESKeyLength keyLen) {
    int Nk = (int)keyLen/4;                 // 4,6,8
    ctx->Nr = (Nk==4)?10:((Nk==6)?12:14);   // 10,12,14
    int Nb = 4;
    int W  = Nb*(ctx->Nr+1);

    uint32_t* rk = ctx->roundKeys;
    for (int i=0;i<Nk;i++) rk[i] = pack_be(key + 4*i);

    for (int i=Nk;i<W;i++) {
        uint32_t temp = rk[i-1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ ((uint32_t)Rcon[i/Nk]<<24);
        } else if (Nk>6 && (i%Nk)==4) {
            temp = SubWord(temp);
        }
        rk[i] = rk[i-Nk] ^ temp;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 라운드 변환
// ─────────────────────────────────────────────────────────────────────────────

static inline void AddRoundKey(uint8_t s[16], const uint32_t* rk) {
    for (int c=0;c<4;c++){
        uint8_t t[4]; unpack_be(rk[c], t);
        s[4*c+0]^=t[0]; s[4*c+1]^=t[1]; s[4*c+2]^=t[2]; s[4*c+3]^=t[3];
    }
}
static inline void SubBytes(uint8_t s[16]) {
    for(int i=0;i<16;i++) s[i]=sbox[s[i]];
}
static inline void InvSubBytes(uint8_t s[16]) {
    for(int i=0;i<16;i++) s[i]=inv_sbox[s[i]];
}
static inline void ShiftRows(uint8_t s[16]) {
    uint8_t t;
    // row1: shift1
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    // row2: shift2
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    // row3: shift3
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static inline void InvShiftRows(uint8_t s[16]) {
    uint8_t t;
    // row1: shift3
    t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    // row2: shift2
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    // row3: shift1
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
}
static inline void MixColumns(uint8_t s[16]) {
    for (int c=0;c<4;c++){
        uint8_t *a=&s[4*c];
        uint8_t a0=a[0],a1=a[1],a2=a[2],a3=a[3];
        a[0]= (uint8_t)(mul(a0,2) ^ mul(a1,3) ^ a2 ^ a3);
        a[1]= (uint8_t)(a0 ^ mul(a1,2) ^ mul(a2,3) ^ a3);
        a[2]= (uint8_t)(a0 ^ a1 ^ mul(a2,2) ^ mul(a3,3));
        a[3]= (uint8_t)(mul(a0,3) ^ a1 ^ a2 ^ mul(a3,2));
    }
}
static inline void InvMixColumns(uint8_t s[16]) {
    for (int c=0;c<4;c++){
        uint8_t *a=&s[4*c];
        uint8_t a0=a[0],a1=a[1],a2=a[2],a3=a[3];
        a[0]= (uint8_t)(mul(a0,14)^mul(a1,11)^mul(a2,13)^mul(a3,9));
        a[1]= (uint8_t)(mul(a0,9)^mul(a1,14)^mul(a2,11)^mul(a3,13));
        a[2]= (uint8_t)(mul(a0,13)^mul(a1,9)^mul(a2,14)^mul(a3,11));
        a[3]= (uint8_t)(mul(a0,11)^mul(a1,13)^mul(a2,9)^mul(a3,14));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 공개 API: 초기화/블록
// ─────────────────────────────────────────────────────────────────────────────

AESStatus AES_init(AES_ctx* ctx, const uint8_t* key, AESKeyLength keyLen){
    if (!ctx || !key) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null ctx/key"); return AES_ERR_BAD_PARAM; }
    if (keyLen!=AES128 && keyLen!=AES192 && keyLen!=AES256) {
        aes_set_error(ctx, AES_ERR_BAD_PARAM, "invalid key length"); return AES_ERR_BAD_PARAM;
    }
    key_expansion(ctx, key, keyLen);
    ctx->encrypt_block = AES_encryptBlock;
    ctx->decrypt_block = AES_decryptBlock;
    ctx->last_err = AES_OK; ctx->on_error=NULL; ctx->err_ud=NULL;
    return AES_OK;
}

void AES_encryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]){
    if (!ctx || !in || !out) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null block io"); return; }
    uint8_t s[16]; memcpy(s,in,16);
    const uint32_t* rk = ctx->roundKeys;

    AddRoundKey(s, rk); rk += 4;
    for (int r=1; r<ctx->Nr; ++r){
        SubBytes(s); ShiftRows(s); MixColumns(s); AddRoundKey(s, rk); rk += 4;
    }
    SubBytes(s); ShiftRows(s); AddRoundKey(s, rk);
    memcpy(out,s,16);
}

void AES_decryptBlock(AES_ctx* ctx, const uint8_t in[16], uint8_t out[16]){
    if (!ctx || !in || !out) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null block io"); return; }
    uint8_t s[16]; memcpy(s,in,16);
    const uint32_t* rk = ctx->roundKeys + 4*ctx->Nr;

    AddRoundKey(s, rk); rk -= 4;
    for (int r=1; r<ctx->Nr; ++r){
        InvShiftRows(s); InvSubBytes(s); AddRoundKey(s, rk); rk -= 4; InvMixColumns(s);
    }
    InvShiftRows(s); InvSubBytes(s); AddRoundKey(s, rk);
    memcpy(out,s,16);
}

// ─────────────────────────────────────────────────────────────────────────────
// 패딩 유틸
// ─────────────────────────────────────────────────────────────────────────────

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

AESStatus AES_stripPadding(const uint8_t* in, size_t in_len,
                           AESPadding padding, size_t* out_plain_len){
    if (!in || !out_plain_len) return AES_ERR_BAD_PARAM;
    if ((in_len==0) || (in_len % AES_BLOCK)) return AES_ERR_LENGTH;

    if (padding == AES_PADDING_NONE){ *out_plain_len=in_len; return AES_OK; }
    if (padding == AES_PADDING_ZERO_FORBIDDEN) return AES_ERR_BAD_PARAM;

    uint8_t last = in[in_len-1];
    size_t pad = (size_t)last;
    if (pad==0 || pad> AES_BLOCK) return AES_ERR_PADDING;

    if (padding == AES_PADDING_PKCS7){
        for (size_t i=0;i<pad;i++) if (in[in_len-1-i]!=last) return AES_ERR_PADDING;
    } else {
        for (size_t i=1;i<pad;i++) if (in[in_len-1-i]!=0x00) return AES_ERR_PADDING;
    }
    *out_plain_len = in_len - pad;
    return AES_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// 운용모드
// ─────────────────────────────────────────────────────────────────────────────

// ECB (패턴 누설, 전송용 비권장)
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

// CBC
AESStatus AES_encryptCBC(AES_ctx* ctx,
                         const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_cap, size_t* out_len,
                         uint8_t iv[16], AESPadding padding){
    if (!ctx || !in || !out || !out_len || !iv) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null param"); return AES_ERR_BAD_PARAM; }
    if (!no_forbidden_overlap(in,in_len,out,out_cap)) { aes_set_error(ctx, AES_ERR_OVERLAP, "in/out overlap"); return AES_ERR_OVERLAP; }

    size_t plen=0; AESStatus st = AES_applyPadding(in,in_len,out,out_cap,padding,&plen);
    if (st!=AES_OK){ aes_set_error(ctx, st, "padding fail"); return st; }

    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (size_t i=0;i<plen;i+=AES_BLOCK){
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

    uint8_t prev[16], cur[16]; memcpy(prev, iv, 16);
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

// CTR (in-place 가능)
AESStatus AES_cryptCTR(AES_ctx* ctx,
                       const uint8_t* in, size_t len,
                       uint8_t* out,
                       uint8_t nonce_counter[16]){
    if (!ctx || !in || !out || !nonce_counter) { aes_set_error(ctx, AES_ERR_BAD_PARAM, "null param"); return AES_ERR_BAD_PARAM; }

    uint8_t ctr[16]; memcpy(ctr, nonce_counter, 16);
    uint8_t ks[16];
    size_t i=0;
    while (i<len){
        AES_encryptBlock(ctx, ctr, ks);
        size_t chunk = (len-i>16)?16:(len-i);
        for (size_t b=0;b<chunk;b++) out[i+b] = in[i+b] ^ ks[b];

        // counter++ (big-endian)
        for (int p=15;p>=0;p--){ ctr[p]++; if (ctr[p]!=0) break; }
        i += chunk;
    }
    memcpy(nonce_counter, ctr, 16);
    return AES_OK;
}
