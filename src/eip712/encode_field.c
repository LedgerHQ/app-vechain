/*******************************************************************************
 *   Ledger VeChain App
 *   (c) 2025 VeChain Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/encode_field.c
 ********************************************************************************/

#include <string.h>

#include "os.h"
#include "app_mem_utils.h"

#include "encode_field.h"

typedef enum { PAD_MSB, PAD_LSB } e_padding_type;

static void *field_encode(const uint8_t *value,
                          uint8_t length,
                          e_padding_type ptype,
                          uint8_t pval) {
    if (length > EIP_712_ENCODED_FIELD_LENGTH) return NULL;

    uint8_t *padded = APP_MEM_ALLOC(EIP_712_ENCODED_FIELD_LENGTH);
    if (padded == NULL) return NULL;

    uint8_t start = 0;
    if (ptype == PAD_MSB) {
        memset(padded, pval, EIP_712_ENCODED_FIELD_LENGTH - length);
        start = EIP_712_ENCODED_FIELD_LENGTH - length;
    } else {
        explicit_bzero(padded + length, EIP_712_ENCODED_FIELD_LENGTH - length);
    }
    memcpy(padded + start, value, length);
    return padded;
}

void *encode_uint(const uint8_t *value, uint8_t length) {
    return field_encode(value, length, PAD_MSB, 0x00);
}

void *encode_int(const uint8_t *value, uint8_t length, uint8_t typesize) {
    if (length < 1) return NULL;
    uint8_t pad = 0x00;
    if (length == typesize && (value[0] & 0x80)) {
        pad = 0xFF;  // negative two's complement
    }
    return field_encode(value, length, PAD_MSB, pad);
}

void *encode_bytes(const uint8_t *value, uint8_t length) {
    return field_encode(value, length, PAD_LSB, 0x00);
}

void *encode_boolean(const bool *value, uint8_t length) {
    if (length != 1) return NULL;
    return encode_uint((const uint8_t *) value, length);
}

void *encode_address(const uint8_t *value, uint8_t length) {
    if (length != EVM_ADDRESS_LENGTH) return NULL;
    return encode_uint(value, length);
}
