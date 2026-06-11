/*******************************************************************************
 *   Ledger VeChain App
 *   (c) 2025 VeChain Foundation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/path.h
 ********************************************************************************/

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "cx.h"

#include "lists.h"
#include "typed_data.h"

// Aligned with LedgerHQ/app-ethereum src/features/sign_message_eip712/path.h
// so the parser can sign deeply-nested typed-data such as OpenSea/Seaport
// orders. Each unit costs a few bytes per session in the heap arena.
#define MAX_PATH_DEPTH     16
#define MAX_ARRAY_DEPTH    8
#define DOMAIN_STRUCT_NAME "EIP712Domain"

typedef struct {
    uint8_t path_index;
    uint8_t size;
    uint8_t index;
} s_array_depth;

typedef enum {
    ROOT_NONE = 0,
    ROOT_DOMAIN,
    ROOT_MESSAGE,
} e_root_type;

typedef struct {
    uint8_t depth_count;
    uint8_t depths[MAX_PATH_DEPTH];
    uint8_t array_depth_count;
    s_array_depth array_depths[MAX_ARRAY_DEPTH];
    const s_struct_712 *root_struct;
    e_root_type root_type;
} s_path;

typedef struct {
    list_node_t _list;
    cx_sha3_t hash;
} s_hash_ctx;

bool path_init(void);
void path_deinit(void);

bool path_set_root(const char *struct_name, uint8_t length);
bool path_advance(bool do_typehash);
bool path_new_array_depth(const uint8_t *data, uint8_t length);

const void *path_get_field(void);
const void *path_get_nth_field(uint8_t n);
e_root_type path_get_root_type(void);
const s_struct_712 *path_get_root(void);
uint8_t path_get_depth_count(void);

s_hash_ctx *get_last_hash_ctx(void);
