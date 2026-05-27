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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/field_hash.c
 ********************************************************************************/

#include <string.h>

#include "os.h"
#include "app_mem_utils.h"

#include "context_712.h"
#include "encode_field.h"
#include "field_hash.h"
#include "hash_bytes.h"
#include "path.h"
#include "typed_data.h"
#include "ui_logic.h"

#define IS_DYN(type) (((type) == TYPE_SOL_STRING) || ((type) == TYPE_SOL_BYTES_DYN))

typedef enum { FHS_IDLE, FHS_WAITING_FOR_MORE } e_field_hashing_state;

typedef struct {
    uint16_t remaining_size;
    uint8_t state;
} s_field_hashing;

static s_field_hashing *fh = NULL;

bool field_hash_init(void) {
    if (fh != NULL) {
        field_hash_deinit();
    }
    if (!APP_MEM_CALLOC((void **) &fh, sizeof(*fh))) return false;
    fh->state = FHS_IDLE;
    return true;
}

void field_hash_deinit(void) {
    APP_MEM_FREE_AND_NULL((void **) &fh);
}

bool field_hash_in_progress(void) {
    return fh != NULL && fh->state != FHS_IDLE;
}

static const uint8_t *field_hash_prepare(const s_struct_712_field *field_ptr,
                                         const uint8_t *data,
                                         uint8_t *data_length) {
    if (*data_length < 2) return NULL;
    fh->remaining_size = (uint16_t) ((data[0] << 8) | data[1]);
    data += 2;
    *data_length -= 2;
    fh->state = FHS_WAITING_FOR_MORE;
    if (IS_DYN(field_ptr->type)) {
        if (cx_keccak_init_no_throw(&global_sha3, 256) != CX_OK) return NULL;
    }
    return data;
}

static const uint8_t *field_hash_finalize_static(const s_struct_712_field *field_ptr,
                                                 const uint8_t *data,
                                                 uint8_t data_length) {
    void *value = NULL;
    switch ((e_type) field_ptr->type) {
        case TYPE_SOL_INT:
            value = encode_int(data, data_length, field_ptr->type_size);
            break;
        case TYPE_SOL_UINT:
            value = encode_uint(data, data_length);
            break;
        case TYPE_SOL_BYTES_FIX:
            value = encode_bytes(data, data_length);
            break;
        case TYPE_SOL_ADDRESS:
            value = encode_address(data, data_length);
            break;
        case TYPE_SOL_BOOL:
            value = encode_boolean((const bool *) data, data_length);
            break;
        case TYPE_CUSTOM:
        default:
            return NULL;
    }
    return (const uint8_t *) value;
}

static const uint8_t *field_hash_finalize_dynamic(void) {
    uint8_t *value = APP_MEM_ALLOC(KECCAK256_HASH_BYTESIZE);
    if (value == NULL) return NULL;
    if (!finalize_hash((cx_hash_t *) &global_sha3, value, KECCAK256_HASH_BYTESIZE)) {
        APP_MEM_FREE(value);
        return NULL;
    }
    return value;
}

static void field_hash_feed_parent(uint8_t field_type, const uint8_t *encoded) {
    size_t len = IS_DYN(field_type) ? KECCAK256_HASH_BYTESIZE : EIP_712_ENCODED_FIELD_LENGTH;
    s_hash_ctx *parent = get_last_hash_ctx();
    if (parent != NULL) {
        hash_nbytes(encoded, len, (cx_hash_t *) &parent->hash);
    }
    APP_MEM_FREE((void *) encoded);
}

static bool field_hash_finalize(const s_struct_712_field *field_ptr,
                                const uint8_t *data,
                                uint8_t data_length) {
    const uint8_t *value = NULL;
    if (!IS_DYN(field_ptr->type)) {
        value = field_hash_finalize_static(field_ptr, data, data_length);
    } else {
        value = field_hash_finalize_dynamic();
    }
    if (value == NULL) return false;

    field_hash_feed_parent(field_ptr->type, value);

    // path_advance() legitimately returns false when we just consumed the
    // last field of a root struct (depth_count goes to 0 and path_update
    // has nothing left to point at). Match upstream and ignore the result.
    (void) path_advance(true);
    fh->state = FHS_IDLE;
    ui_712_finalize_field();
    return true;
}

bool field_hash(const uint8_t *data, uint8_t data_length, bool partial) {
    if (fh == NULL) return false;
    const s_struct_712_field *field_ptr = path_get_field();
    if (field_ptr == NULL) return false;

    bool first = (fh->state == FHS_IDLE);
    uint16_t total_length = 0;

    if (first) {
        if (!ui_712_show_raw_key(field_ptr)) return false;
        if (data_length < 2) return false;
        data = field_hash_prepare(field_ptr, data, &data_length);
        if (data == NULL) return false;
        total_length = fh->remaining_size;
    }
    if (data_length > fh->remaining_size) return false;
    fh->remaining_size -= data_length;
    if (IS_DYN(field_ptr->type)) {
        hash_nbytes(data, data_length, (cx_hash_t *) &global_sha3);
    }
    if (!ui_712_feed_to_display(field_ptr,
                                data,
                                data_length,
                                first ? &total_length : NULL,
                                fh->remaining_size == 0)) {
        return false;
    }
    if (fh->remaining_size == 0) {
        if (partial) return false;  // last chunk must be COMPLETE
        if (!field_hash_finalize(field_ptr, data, data_length)) return false;
    } else {
        if (!partial || !IS_DYN(field_ptr->type)) return false;
    }
    return true;
}
