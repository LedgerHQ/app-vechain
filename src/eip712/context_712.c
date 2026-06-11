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

#include "os.h"
#include "app_mem_utils.h"

#include "context_712.h"
#include "sol_typenames.h"
#include "typed_data.h"

s_eip712_context *eip712_context = NULL;
cx_sha3_t global_sha3;

bool eip712_context_init(void) {
    if (eip712_context != NULL) {
        eip712_context_deinit();
    }
    if (!APP_MEM_CALLOC((void **) &eip712_context, sizeof(*eip712_context))) {
        return false;
    }
    eip712_context->go_home_on_failure = true;
    if (!typed_data_init()) {
        APP_MEM_FREE_AND_NULL((void **) &eip712_context);
        return false;
    }
    if (!sol_typenames_init()) {
        typed_data_deinit();
        APP_MEM_FREE_AND_NULL((void **) &eip712_context);
        return false;
    }
    return true;
}

void eip712_context_deinit(void) {
    sol_typenames_deinit();
    typed_data_deinit();
    if (eip712_context != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &eip712_context);
    }
}

bool eip712_display_push(const char *key, const char *value) {
    if (eip712_context == NULL) return false;
    if (eip712_context->display_pair_count >= EIP712_MAX_DISPLAY_PAIRS) return false;
    nbgl_layoutTagValue_t *pair =
        &eip712_context->display_pairs[eip712_context->display_pair_count++];
    pair->item = key;
    pair->value = value;
    return true;
}

nbgl_layoutTagValueList_t *eip712_get_display_list(void) {
    if (eip712_context == NULL) return NULL;
    eip712_context->display_list.nbMaxLinesForValue = 0;
    eip712_context->display_list.nbPairs = eip712_context->display_pair_count;
    eip712_context->display_list.pairs = eip712_context->display_pairs;
    return &eip712_context->display_list;
}

const char *eip712_intern_string(const char *src) {
    if (src == NULL) return NULL;
    return eip712_intern_buf((const uint8_t *) src, strlen(src));
}

const char *eip712_intern_buf(const uint8_t *src, size_t len) {
    if (src == NULL) return NULL;
    char *dst = APP_MEM_ALLOC(len + 1);
    if (dst == NULL) return NULL;
    memmove(dst, src, len);
    dst[len] = '\0';
    return dst;
}
