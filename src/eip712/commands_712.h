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

bool handle_eip712_struct_def(uint8_t p1, uint8_t p2, const uint8_t *cdata, uint8_t length);
bool handle_eip712_struct_impl(uint8_t p1, uint8_t p2, const uint8_t *cdata, uint8_t length);
bool handle_eip712_sign(uint8_t *workBuffer, uint16_t dataLength, volatile uint32_t *flags);
