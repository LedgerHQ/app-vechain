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

/**
 * @brief Top-level entry point for all EIP-712 related APDUs (0x0C, 0x1A,
 *        0x1C). Validates the setting and delegates to the proper
 *        sub-handler.
 */
void eip712_dispatch_apdu(uint8_t ins,
                          uint8_t p1,
                          uint8_t p2,
                          uint8_t *workBuffer,
                          uint16_t dataLength,
                          volatile uint32_t *flags,
                          volatile uint32_t *tx);
