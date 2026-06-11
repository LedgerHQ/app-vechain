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

#include <stdbool.h>

/**
 * Initialize the EIP-712 dynamic allocator. Must be called once at app start.
 * Returns true on success.
 */
bool app_mem_init(void);
