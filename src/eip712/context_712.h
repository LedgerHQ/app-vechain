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
#include <stdbool.h>

#include "cx.h"

#include "nbgl_use_case.h"

#include "eip712_common.h"

typedef struct {
    uint8_t domain_hash[32];
    uint8_t message_hash[32];
    bool domain_ready;
    bool message_ready;

    bool go_home_on_failure;

    // Display state for the review UI
    nbgl_layoutTagValue_t display_pairs[EIP712_MAX_DISPLAY_PAIRS];
    uint8_t display_pair_count;
    nbgl_layoutTagValueList_t display_list;
    uint16_t arena_used_strings;

    // Set when a field could not be added to display_pairs (cap reached
    // or string interning failed). The sign handler refuses the request
    // so the user is never asked to approve a partially-displayed message.
    bool display_overflow;
} s_eip712_context;

extern s_eip712_context *eip712_context;
extern cx_sha3_t global_sha3;

bool eip712_context_init(void);
void eip712_context_deinit(void);

bool eip712_display_push(const char *key, const char *value);
nbgl_layoutTagValueList_t *eip712_get_display_list(void);

const char *eip712_intern_string(const char *src);
const char *eip712_intern_buf(const uint8_t *src, size_t len);
