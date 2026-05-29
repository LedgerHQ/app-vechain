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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/typed_data.c
 ********************************************************************************/

#include <string.h>

#include "os.h"
#include "app_mem_utils.h"

#include "typed_data.h"

static s_struct_712 *g_struct_list = NULL;
static s_struct_712 *g_current_struct = NULL;

const s_struct_712 *get_struct_list(void) {
    return g_struct_list;
}

const s_struct_712 *get_structn(const char *name_ptr, uint8_t name_length) {
    const s_struct_712 *iter = g_struct_list;
    while (iter != NULL) {
        if (iter->name != NULL && strlen(iter->name) == name_length &&
            memcmp(iter->name, name_ptr, name_length) == 0) {
            return iter;
        }
        iter = (const s_struct_712 *) ((const flist_node_t *) iter)->next;
    }
    return NULL;
}

const char *get_struct_field_typename(const s_struct_712_field *field) {
    return field->type_name;
}

static char *intern_string(const uint8_t *src, size_t len) {
    char *dst = APP_MEM_ALLOC(len + 1);
    if (dst == NULL) return NULL;
    memmove(dst, src, len);
    dst[len] = '\0';
    return dst;
}

bool set_struct_name(uint8_t length, const uint8_t *name) {
    if (length == 0) return false;
    s_struct_712 *new_struct = NULL;
    if (!APP_MEM_CALLOC((void **) &new_struct, sizeof(*new_struct))) {
        return false;
    }
    new_struct->name = intern_string(name, length);
    if (new_struct->name == NULL) {
        APP_MEM_FREE(new_struct);
        return false;
    }
    new_struct->fields = NULL;
    flist_push_back((flist_node_t **) &g_struct_list, (flist_node_t *) new_struct);
    g_current_struct = new_struct;
    return true;
}

bool set_struct_field(uint8_t length, const uint8_t *data) {
    if (g_current_struct == NULL || length < 2) return false;

    s_struct_712_field *field = NULL;
    if (!APP_MEM_CALLOC((void **) &field, sizeof(*field))) {
        return false;
    }

    uint16_t cursor = 0;
    uint8_t type_desc = data[cursor++];
    field->type = type_desc & TYPE_MASK;
    field->type_has_size = (type_desc & TYPESIZE_MASK) != 0;
    field->type_is_array = (type_desc & ARRAY_MASK) != 0;

    if (field->type == TYPE_CUSTOM) {
        uint8_t name_len = data[cursor++];
        if (cursor + name_len > length) goto fail;
        field->type_name = intern_string(data + cursor, name_len);
        if (field->type_name == NULL) goto fail;
        cursor += name_len;
    }

    if (field->type_has_size) {
        if (cursor >= length) goto fail;
        field->type_size = data[cursor++];
    }

    if (field->type_is_array) {
        if (cursor >= length) goto fail;
        uint8_t levels = data[cursor++];
        if (levels == 0) goto fail;
        field->array_level_count = levels;
        if (!APP_MEM_CALLOC((void **) &field->array_levels,
                            sizeof(*field->array_levels) * levels)) {
            goto fail;
        }
        for (uint8_t i = 0; i < levels; i++) {
            if (cursor >= length) goto fail;
            uint8_t kind = data[cursor++];
            field->array_levels[i].type = kind;
            if (kind == ARRAY_FIXED_SIZE) {
                if (cursor >= length) goto fail;
                field->array_levels[i].size = data[cursor++];
            }
        }
    }

    if (cursor >= length) goto fail;
    uint8_t key_len = data[cursor++];
    if (cursor + key_len > length) goto fail;
    field->key_name = intern_string(data + cursor, key_len);
    if (field->key_name == NULL) goto fail;

    flist_push_back((flist_node_t **) &g_current_struct->fields, (flist_node_t *) field);
    return true;

fail:
    if (field->array_levels != NULL) APP_MEM_FREE(field->array_levels);
    if (field->key_name != NULL) APP_MEM_FREE(field->key_name);
    if (field->type_name != NULL) APP_MEM_FREE(field->type_name);
    APP_MEM_FREE(field);
    return false;
}

static void free_field(void *node) {
    s_struct_712_field *f = (s_struct_712_field *) node;
    if (f == NULL) return;
    if (f->type_name != NULL) APP_MEM_FREE(f->type_name);
    if (f->key_name != NULL) APP_MEM_FREE(f->key_name);
    if (f->array_levels != NULL) APP_MEM_FREE(f->array_levels);
    APP_MEM_FREE(f);
}

static void free_struct(void *node) {
    s_struct_712 *s = (s_struct_712 *) node;
    if (s == NULL) return;
    flist_clear((flist_node_t **) &s->fields, &free_field);
    if (s->name != NULL) APP_MEM_FREE(s->name);
    APP_MEM_FREE(s);
}

bool typed_data_init(void) {
    g_struct_list = NULL;
    g_current_struct = NULL;
    return true;
}

void typed_data_deinit(void) {
    flist_clear((flist_node_t **) &g_struct_list, &free_struct);
    g_current_struct = NULL;
}
