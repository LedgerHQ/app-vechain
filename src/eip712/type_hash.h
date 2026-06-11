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

bool type_hash(const char *struct_name, uint8_t struct_name_length, uint8_t *hash_buf);
