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

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "os.h"
#include "cx.h"

// EIP-712 APDU instructions (subset of LedgerHQ/app-ethereum layout).
// CAL filtering (INS 0x1E) is intentionally NOT implemented: typed-data
// review on this app shows raw field names from the type definition.
#define INS_SIGN_EIP_712                  0x0C
#define INS_EIP712_SEND_STRUCT_DEFINITION 0x1A
#define INS_EIP712_SEND_STRUCT_IMPL       0x1C

// INS_SIGN_EIP_712 P2 values
#define EIP712_P2_V0 0x00  // blind sign: host provides domainSeparator + hashStruct
#define EIP712_P2_V1 0x01  // clear sign: host streamed types and values, device hashed everything

// INS_EIP712_SEND_STRUCT_DEFINITION P2 values
#define EIP712_DEF_P2_NAME  0x00
#define EIP712_DEF_P2_FIELD 0xFF

// INS_EIP712_SEND_STRUCT_IMPL P1 / P2 values
#define EIP712_IMPL_P1_COMPLETE 0x00
#define EIP712_IMPL_P1_PARTIAL  0x01

#define EIP712_IMPL_P2_ROOT  0x00
#define EIP712_IMPL_P2_ARRAY 0x0F
#define EIP712_IMPL_P2_FIELD 0xFF

// EIP-712 runtime limits actually enforced by the firmware.
//
// Heap arena for the parser is `mem_buffer[APP_MEM_BUFFER_SIZE]` in
// src/eip712/mem_buffer.c, sized by Makefile (8 KB on Nano, 16 KB on
// touchscreens). It backs APP_MEM_ALLOC/APP_MEM_FREE from the Ledger SDK
// `lib_alloc`. Anything the EIP-712 parser stores (struct registry, hash
// contexts, interned strings, display pairs) lives there and is freed at
// eip712_context_deinit().
//
// Nesting bounds (MAX_PATH_DEPTH, MAX_ARRAY_DEPTH) live in
// src/eip712/path.h and ARE checked on every IMPL APDU.
//
// EIP712_MAX_DISPLAY_PAIRS is enforced at sign time:
// commands_712.c::handle_eip712_sign refuses to sign with
// SWO_CONDITIONS_NOT_SATISFIED (0x6985) if any pair could not be added
// to the review list. Larger on touchscreens because the bigger arena
// can hold both the extra `nbgl_layoutTagValue_t` slots and the
// interned key/value strings without exhausting memory.
//
// For empirical observations see tests/test_eip712_limits_cmd.py.
#if defined(TARGET_STAX) || defined(TARGET_FLEX) || defined(TARGET_APEX_P)
#define EIP712_MAX_DISPLAY_PAIRS 48
#else
#define EIP712_MAX_DISPLAY_PAIRS 24
#endif
#define EIP712_DISPLAY_VALUE_MAX 80
#define EIP712_DISPLAY_KEY_MAX   32

// Hex preview format used in v0 (truncated 0xABCD...EF01)
#define EIP712_HASH_PREVIEW_BYTES 2
#define EIP712_HASH_PREVIEW_LEN   (EIP712_HASH_PREVIEW_BYTES * 2 * 2 + 3 + 1)

/**
 * @brief Compute the final EIP-712 digest:
 *        keccak256(0x19 || 0x01 || domainSeparator || hashStruct)
 *
 * @param[in]  domain_separator 32 bytes domain separator
 * @param[in]  hash_struct      32 bytes hashStruct(message)
 * @param[out] digest_out       32 bytes digest output
 */
void eip712_compute_final_digest(const uint8_t domain_separator[32],
                                 const uint8_t hash_struct[32],
                                 uint8_t digest_out[32]);

/**
 * @brief Format a 32-byte hash as a truncated hex preview "abcd...ef01" into a
 *        null-terminated string. Caller must ensure out_size >= EIP712_HASH_PREVIEW_LEN.
 */
void eip712_format_hash_preview(char *out, size_t out_size, const uint8_t hash[32]);
