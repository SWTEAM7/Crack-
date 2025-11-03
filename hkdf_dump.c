#include <stdio.h>
#include <stdint.h>
#include "sha512.h"

int main(void){
    uint8_t ikm[22]; for (int i=0;i<22;i++) ikm[i]=0x0b;
    uint8_t salt[13]; for (int i=0;i<13;i++) salt[i]=(uint8_t)i;
    uint8_t info[10]; for (int i=0;i<10;i++) info[i]=(uint8_t)(0xf0+i);
    uint8_t okm[42];
    if (hkdf_sha512(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm, sizeof(okm))!=0) return 2;
    for (int i=0;i<42;i++){ printf("%02x", okm[i]); }
    printf("\n");
    return 0;
}
