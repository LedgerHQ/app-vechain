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
 * @brief Handle the v0 (blind-sign) variant of INS_SIGN_EIP_712 (P2=0x00).
 *
 * Input data layout: BIP32 path || domainSeparator (32) || hashStruct (32)
 *
 * Computes digest = keccak256(0x19 || 0x01 || domainSeparator || hashStruct),
 * stores it in tmpCtx.transactionContext.hash, formats Domain hash and Message
 * hash for display, and triggers the EIP-712 v0 review flow.
 */
void eip712_handle_sign_v0(uint8_t *workBuffer, uint16_t dataLength, volatile uint32_t *flags);
