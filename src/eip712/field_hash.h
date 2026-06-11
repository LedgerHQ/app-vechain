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

bool field_hash_init(void);
void field_hash_deinit(void);
bool field_hash(const uint8_t *data, uint8_t data_length, bool partial);

bool field_hash_in_progress(void);
