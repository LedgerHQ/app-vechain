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

#include "typed_data.h"

bool ui_712_init(void);
void ui_712_deinit(void);
bool ui_712_show_raw_key(const s_struct_712_field *field_ptr);
bool ui_712_feed_to_display(const s_struct_712_field *field_ptr,
                            const uint8_t *data,
                            uint8_t data_length,
                            uint16_t *total_length,
                            bool last);
void ui_712_finalize_field(void);
void ui_712_present_review(void);
