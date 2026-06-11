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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/format_hash_field_type.c
 ********************************************************************************/

#include <string.h>

#include "os.h"

#include "format_hash_field_type.h"
#include "hash_bytes.h"
#include "sol_typenames.h"

static void hash_uint_to_str(uint32_t value, cx_hash_t *hash) {
    char tmp[12];
    if (value == 0) {
        hash_byte('0', hash);
        return;
    }
    size_t n = 0;
    while (value > 0 && n < sizeof(tmp)) {
        tmp[n++] = (char) ('0' + (value % 10));
        value /= 10;
    }
    for (size_t i = 0; i < n; i++) {
        hash_byte((uint8_t) tmp[n - 1 - i], hash);
    }
}

bool format_hash_field_type(const s_struct_712_field *field_ptr, cx_hash_t *hash) {
    if (field_ptr == NULL || hash == NULL) return false;

    if (field_ptr->type == TYPE_CUSTOM) {
        const char *name = field_ptr->type_name;
        if (name == NULL) return false;
        hash_nbytes((const uint8_t *) name, strlen(name), hash);
    } else {
        const char *sol = get_struct_field_sol_typename(field_ptr);
        if (sol == NULL) return false;
        hash_nbytes((const uint8_t *) sol, strlen(sol), hash);
        if (field_ptr->type_has_size) {
            uint32_t bits;
            if (field_ptr->type == TYPE_SOL_BYTES_FIX) {
                bits = field_ptr->type_size;  // already byte size for bytesN
            } else {
                bits = ((uint32_t) field_ptr->type_size) * 8;  // intN, uintN
            }
            hash_uint_to_str(bits, hash);
        }
    }

    if (field_ptr->type_is_array && field_ptr->array_levels != NULL) {
        for (uint8_t i = 0; i < field_ptr->array_level_count; i++) {
            hash_byte('[', hash);
            if (field_ptr->array_levels[i].type == ARRAY_FIXED_SIZE) {
                hash_uint_to_str(field_ptr->array_levels[i].size, hash);
            }
            hash_byte(']', hash);
        }
    }
    return true;
}
