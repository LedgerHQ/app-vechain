/*******************************************************************************
 *   Ledger VeChain App
 *   (c) 2025 VeChain Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 ********************************************************************************/

#include "os.h"
#include "hash_bytes.h"

void hash_byte(uint8_t b, cx_hash_t *hash) {
    if (hash == NULL) return;
    CX_ASSERT(cx_hash_no_throw(hash, 0, &b, 1, NULL, 0));
}

void hash_nbytes(const uint8_t *bytes, size_t length, cx_hash_t *hash) {
    if (hash == NULL || length == 0) return;
    CX_ASSERT(cx_hash_no_throw(hash, 0, bytes, length, NULL, 0));
}

bool finalize_hash(cx_hash_t *hash, uint8_t *out, size_t out_len) {
    if (hash == NULL || out == NULL) return false;
    return cx_hash_no_throw(hash, CX_LAST, NULL, 0, out, out_len) == CX_OK;
}
