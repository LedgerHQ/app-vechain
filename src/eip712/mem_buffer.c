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

/**
 * Static heap buffer used by the EIP-712 dynamic allocator.
 *
 * The actual allocator lives in the Ledger SDK (`lib_alloc/app_mem_utils.c`)
 * and exposes APP_MEM_ALLOC / APP_MEM_FREE / APP_MEM_CALLOC. We just provide
 * the underlying static buffer plus a thin `app_mem_init()` wrapper called
 * from main.c.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "os.h"
#include "app_mem_utils.h"

#ifndef APP_MEM_BUFFER_SIZE
#define APP_MEM_BUFFER_SIZE 8192
#endif

static uint8_t mem_buffer[APP_MEM_BUFFER_SIZE] __attribute__((aligned(sizeof(intmax_t))));

bool app_mem_init(void) {
    bool ok = mem_utils_init(mem_buffer, sizeof(mem_buffer));
    PRINTF("app_mem_init(buf=%p size=%u) -> %d\n",
           mem_buffer,
           (unsigned) sizeof(mem_buffer),
           ok ? 1 : 0);
    return ok;
}
