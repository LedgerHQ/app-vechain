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
#include "cx.h"
#include "status_words.h"

#include "crypto.h"
#include "handlers.h"
#include "main.h"
#include "ui_nbgl.h"

#include "eip712_common.h"
#include "eip712_v0.h"

void eip712_handle_sign_v0(uint8_t *workBuffer, uint16_t dataLength, volatile uint32_t *flags) {
    if (!N_storage.eip712Allowed) {
        PRINTF("EIP-712 signing disabled in settings\n");
        THROW(SWO_CONDITIONS_NOT_SATISFIED);
    }
    if (!N_storage.blindSign712) {
        PRINTF("EIP-712 v0 (blind sign) disabled in settings\n");
        THROW(SWO_CONDITIONS_NOT_SATISFIED);
    }

    parseBip32Path(&workBuffer,
                   &dataLength,
                   &tmpCtx.transactionContext.pathLength,
                   tmpCtx.transactionContext.bip32Path);

    if (dataLength < 64) {
        PRINTF("EIP-712 v0: not enough data (need 64, got %u)\n", dataLength);
        THROW(SWO_INCORRECT_DATA);
    }

    const uint8_t *domain_separator = workBuffer;
    const uint8_t *hash_struct = workBuffer + 32;

    eip712_compute_final_digest(domain_separator, hash_struct, tmpCtx.transactionContext.hash);

    PRINTF("EIP-712 v0 digest:\n%.*H\n", 32, tmpCtx.transactionContext.hash);

    eip712_format_hash_preview((char *) fullAddress, sizeof(fullAddress), domain_separator);
    eip712_format_hash_preview((char *) fullAmount, sizeof(fullAmount), hash_struct);

    ui_display_action_sign_eip712_v0_flow();

    *flags |= IO_ASYNCH_REPLY;
}
