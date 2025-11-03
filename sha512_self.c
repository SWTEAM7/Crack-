#include <stdio.h>
#include "sha512.h"

int main(void) {
    int r = sha512_selftest();
    printf("%d\n", r);
    return r != 0;
}
