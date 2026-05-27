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
#include <stddef.h>

#include "cx.h"

#define KECCAK256_HASH_BYTESIZE 32

void hash_byte(uint8_t b, cx_hash_t *hash);
void hash_nbytes(const uint8_t *bytes, size_t length, cx_hash_t *hash);
bool finalize_hash(cx_hash_t *hash, uint8_t *out, size_t out_len);
