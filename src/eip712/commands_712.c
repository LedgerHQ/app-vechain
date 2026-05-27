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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/commands_712.c
 ********************************************************************************/

#include <string.h>

#include "os.h"
#include "status_words.h"

#include "crypto.h"
#include "handlers.h"
#include "main.h"

#include "commands_712.h"
#include "context_712.h"
#include "eip712_common.h"
#include "field_hash.h"
#include "path.h"
#include "typed_data.h"
#include "ui_logic.h"

static bool g_struct_defined = false;

static void teardown_context(void) {
    ui_712_deinit();
    path_deinit();
    field_hash_deinit();
    eip712_context_deinit();
    g_struct_defined = false;
}

static bool ensure_context(void) {
    if (eip712_context != NULL) return true;
    if (!eip712_context_init()) return false;
    if (!field_hash_init()) return false;
    if (!path_init()) return false;
    if (!ui_712_init()) return false;
    g_struct_defined = false;
    return true;
}

bool handle_eip712_struct_def(uint8_t p1, uint8_t p2, const uint8_t *cdata, uint8_t length) {
    UNUSED(p1);
    // A SEND_STRUCT_DEFINITION P2=NAME after a previous typed-data flow has
    // already been signed (g_struct_defined=true) means the host is starting
    // a brand-new typed-data session. Tear down the previous registry first.
    if (g_struct_defined && p2 == EIP712_DEF_P2_NAME) {
        teardown_context();
    }
    if (!ensure_context()) return false;
    if (g_struct_defined) return false;

    switch (p2) {
        case EIP712_DEF_P2_NAME:
            return set_struct_name(length, cdata);
        case EIP712_DEF_P2_FIELD:
            return set_struct_field(length, cdata);
        default:
            return false;
    }
}

bool handle_eip712_struct_impl(uint8_t p1, uint8_t p2, const uint8_t *cdata, uint8_t length) {
    if (eip712_context == NULL) return false;

    // The first SEND_STRUCT_IMPL APDU marks the end of the type-definition
    // phase. We just flip the flag so that subsequent SEND_STRUCT_DEFINITION
    // APDUs (a brand-new flow) trigger a context teardown.
    if (!g_struct_defined) {
        g_struct_defined = true;
    }

    switch (p2) {
        case EIP712_IMPL_P2_ROOT: {
            if (p1 != EIP712_IMPL_P1_COMPLETE) return false;
            return path_set_root((const char *) cdata, length);
        }

        case EIP712_IMPL_P2_ARRAY: {
            if (p1 != EIP712_IMPL_P1_COMPLETE) return false;
            return path_new_array_depth(cdata, length);
        }

        case EIP712_IMPL_P2_FIELD:
            return field_hash(cdata, length, p1 == EIP712_IMPL_P1_PARTIAL);

        default:
            return false;
    }
}

bool handle_eip712_sign(uint8_t *workBuffer, uint16_t dataLength, volatile uint32_t *flags) {
    if (eip712_context == NULL) return false;
    if (!eip712_context->domain_ready || !eip712_context->message_ready) return false;
    // Refuse to sign typed-data whose review screen would be incomplete
    // (more than EIP712_MAX_DISPLAY_PAIRS fields, or arena exhausted while
    // interning a key/value). Approving a partial view is a WYSIWYS hazard.
    if (eip712_context->display_overflow) {
        PRINTF("EIP-712 v1: refusing to sign, display pairs overflowed\n");
        return false;
    }

    parseBip32Path(&workBuffer,
                   &dataLength,
                   &tmpCtx.transactionContext.pathLength,
                   tmpCtx.transactionContext.bip32Path);
    if (dataLength != 0) return false;

    eip712_compute_final_digest(eip712_context->domain_hash,
                                eip712_context->message_hash,
                                tmpCtx.transactionContext.hash);

    PRINTF("EIP-712 v1 final digest:\n%.*H\n", 32, tmpCtx.transactionContext.hash);

    eip712_context->go_home_on_failure = false;
    ui_712_present_review();

    *flags |= IO_ASYNCH_REPLY;
    return true;
}
