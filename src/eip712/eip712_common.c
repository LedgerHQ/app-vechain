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

#include <string.h>
#include "eip712_common.h"

void eip712_compute_final_digest(const uint8_t domain_separator[32],
                                 const uint8_t hash_struct[32],
                                 uint8_t digest_out[32]) {
    uint8_t prefixed[2 + 32 + 32];
    prefixed[0] = 0x19;
    prefixed[1] = 0x01;
    memmove(prefixed + 2, domain_separator, 32);
    memmove(prefixed + 2 + 32, hash_struct, 32);
    CX_ASSERT(cx_keccak_256_hash(prefixed, sizeof(prefixed), digest_out));
}

void eip712_format_hash_preview(char *out, size_t out_size, const uint8_t hash[32]) {
    if (out_size < EIP712_HASH_PREVIEW_LEN) {
        if (out_size > 0) {
            out[0] = '\0';
        }
        return;
    }
    const size_t prefix_chars = (size_t) EIP712_HASH_PREVIEW_BYTES * 2;
    bytes_to_hex(out, prefix_chars + 1, hash, EIP712_HASH_PREVIEW_BYTES);
    out[prefix_chars] = '.';
    out[prefix_chars + 1] = '.';
    out[prefix_chars + 2] = '.';
    bytes_to_hex(out + prefix_chars + 3,
                 out_size - (prefix_chars + 3),
                 hash + 32 - EIP712_HASH_PREVIEW_BYTES,
                 EIP712_HASH_PREVIEW_BYTES);
}
