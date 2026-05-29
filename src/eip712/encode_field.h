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

#define EIP_712_ENCODED_FIELD_LENGTH 32
// 20-byte EVM-style address layout (shared by VeChain and any EIP-712 dApp).
#define EVM_ADDRESS_LENGTH 20

void *encode_uint(const uint8_t *value, uint8_t length);
void *encode_int(const uint8_t *value, uint8_t length, uint8_t typesize);
void *encode_boolean(const bool *value, uint8_t length);
void *encode_address(const uint8_t *value, uint8_t length);
void *encode_bytes(const uint8_t *value, uint8_t length);
