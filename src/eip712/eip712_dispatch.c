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
#include "status_words.h"

#include "main.h"

#include "commands_712.h"
#include "eip712_common.h"
#include "eip712_dispatch.h"
#include "eip712_v0.h"

void eip712_dispatch_apdu(uint8_t ins,
                          uint8_t p1,
                          uint8_t p2,
                          uint8_t *workBuffer,
                          uint16_t dataLength,
                          volatile uint32_t *flags,
                          volatile uint32_t *tx) {
    UNUSED(tx);

    if (!N_storage.eip712Allowed) {
        PRINTF("EIP-712 signing disabled in settings\n");
        THROW(SWO_CONDITIONS_NOT_SATISFIED);
    }

    bool ok = false;
    switch (ins) {
        case INS_SIGN_EIP_712:
            if (p1 != 0x00) {
                THROW(SWO_WRONG_P1_P2);
            }
            if (p2 == EIP712_P2_V0) {
                eip712_handle_sign_v0(workBuffer, dataLength, flags);
                return;  // v0 sets flags directly and never returns false
            } else if (p2 == EIP712_P2_V1) {
                ok = handle_eip712_sign(workBuffer, dataLength, flags);
                if (!ok) THROW(SWO_CONDITIONS_NOT_SATISFIED);
                return;
            } else {
                THROW(SWO_WRONG_P1_P2);
            }
            break;

        case INS_EIP712_SEND_STRUCT_DEFINITION:
            ok = handle_eip712_struct_def(p1, p2, workBuffer, (uint8_t) dataLength);
            break;

        case INS_EIP712_SEND_STRUCT_IMPL:
            ok = handle_eip712_struct_impl(p1, p2, workBuffer, (uint8_t) dataLength);
            break;

        default:
            THROW(SWO_INVALID_INS);
    }

    if (!ok) {
        THROW(SWO_INCORRECT_DATA);
    }
    // The synchronous EIP-712 sub-handlers (SEND_STRUCT_DEFINITION /
    // SEND_STRUCT_IMPL) finish here without an async UI step; the outer
    // dispatcher in handleApdu only writes the SW back to the host when
    // we explicitly throw a success status word.
    THROW(SWO_SUCCESS);
}
