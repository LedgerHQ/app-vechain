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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/typed_data.h
 ********************************************************************************/

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "lists.h"

// TypeDesc bit layout for the EIP-712 streaming encoding.
#define TYPE_MASK     (0xF)
#define ARRAY_MASK    (1 << 7)
#define TYPESIZE_MASK (1 << 6)

typedef enum { ARRAY_DYNAMIC = 0, ARRAY_FIXED_SIZE = 1, ARRAY_TYPES_COUNT } e_array_type;

typedef enum {
    TYPE_CUSTOM = 0,
    TYPE_SOL_INT = 1,
    TYPE_SOL_UINT = 2,
    TYPE_SOL_ADDRESS = 3,
    TYPE_SOL_BOOL = 4,
    TYPE_SOL_STRING = 5,
    TYPE_SOL_BYTES_FIX = 6,
    TYPE_SOL_BYTES_DYN = 7,
    TYPES_COUNT
} e_type;

typedef struct {
    uint8_t type;  // e_array_type
    uint8_t size;
} s_struct_712_field_array_level;

typedef struct struct_712_field {
    flist_node_t _list;
    bool type_is_array : 1;
    bool type_has_size : 1;
    uint8_t type : 4;  // e_type
    char *type_name;
    uint8_t type_size;
    uint8_t array_level_count;
    s_struct_712_field_array_level *array_levels;
    char *key_name;
} s_struct_712_field;

typedef struct struct_712 {
    flist_node_t _list;
    char *name;
    s_struct_712_field *fields;
} s_struct_712;

const s_struct_712 *get_struct_list(void);
const s_struct_712 *get_structn(const char *name_ptr, uint8_t name_length);
const char *get_struct_field_typename(const s_struct_712_field *field);

bool set_struct_name(uint8_t length, const uint8_t *name);
bool set_struct_field(uint8_t length, const uint8_t *data);

bool typed_data_init(void);
void typed_data_deinit(void);
