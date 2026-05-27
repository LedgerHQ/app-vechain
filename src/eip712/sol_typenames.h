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
#include "typed_data.h"

bool sol_typenames_init(void);
void sol_typenames_deinit(void);
const char *get_struct_field_sol_typename(const s_struct_712_field *field_ptr);
