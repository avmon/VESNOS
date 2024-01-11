#ifndef HEX_STR_H
#define HEX_STR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void bytesToHexString(const uint8_t *bytes, size_t length, char *hexString) {
    for (size_t i = 0; i < length; ++i) {
        sprintf(hexString + 2 * i, "%02X", bytes[i]);
    }
}

void hexStringToBytes(const char *hexString, uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        sscanf(hexString + 2 * i, "%2hhX", &bytes[i]);
    }
}

#endif // HEX_STR_H
