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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/type_hash.c
 ********************************************************************************/

#include <string.h>

#include "os.h"
#include "app_mem_utils.h"

#include "context_712.h"
#include "format_hash_field_type.h"
#include "hash_bytes.h"
#include "lists.h"
#include "type_hash.h"
#include "typed_data.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef struct struct_dep {
    flist_node_t _list;
    const s_struct_712 *s;
} s_struct_dep;

static bool encode_and_hash_field(const s_struct_712_field *field_ptr) {
    if (!format_hash_field_type(field_ptr, (cx_hash_t *) &global_sha3)) {
        return false;
    }
    hash_byte(' ', (cx_hash_t *) &global_sha3);
    hash_nbytes((const uint8_t *) field_ptr->key_name,
                strlen(field_ptr->key_name),
                (cx_hash_t *) &global_sha3);
    return true;
}

static bool encode_and_hash_type(const s_struct_712 *struct_ptr) {
    hash_nbytes((const uint8_t *) struct_ptr->name,
                strlen(struct_ptr->name),
                (cx_hash_t *) &global_sha3);
    hash_byte('(', (cx_hash_t *) &global_sha3);

    const s_struct_712_field *field_ptr = struct_ptr->fields;
    bool first = true;
    while (field_ptr != NULL) {
        if (!first) {
            hash_byte(',', (cx_hash_t *) &global_sha3);
        }
        if (!encode_and_hash_field(field_ptr)) {
            return false;
        }
        first = false;
        field_ptr = (const s_struct_712_field *) ((const flist_node_t *) field_ptr)->next;
    }
    hash_byte(')', (cx_hash_t *) &global_sha3);
    return true;
}

static bool add_dep_if_new(s_struct_dep **first_dep, const s_struct_712 *struct_ptr) {
    s_struct_dep *iter = *first_dep;
    while (iter != NULL) {
        if (iter->s == struct_ptr) return true;
        iter = (s_struct_dep *) ((flist_node_t *) iter)->next;
    }
    s_struct_dep *new_dep = APP_MEM_ALLOC(sizeof(*new_dep));
    if (new_dep == NULL) return false;
    new_dep->_list.next = NULL;
    new_dep->s = struct_ptr;
    flist_push_back((flist_node_t **) first_dep, (flist_node_t *) new_dep);
    return true;
}

static bool collect_direct_deps(s_struct_dep **first_dep, const s_struct_712 *struct_ptr) {
    const s_struct_712_field *field = struct_ptr->fields;
    while (field != NULL) {
        if (field->type == TYPE_CUSTOM) {
            const char *dep_name = get_struct_field_typename(field);
            const s_struct_712 *dep = get_structn(dep_name, strlen(dep_name));
            if (dep == NULL) return false;
            if (!add_dep_if_new(first_dep, dep)) return false;
        }
        field = (const s_struct_712_field *) ((const flist_node_t *) field)->next;
    }
    return true;
}

static bool get_struct_dependencies(s_struct_dep **first_dep, const s_struct_712 *struct_ptr) {
    if (!collect_direct_deps(first_dep, struct_ptr)) return false;
    s_struct_dep *cursor = *first_dep;
    while (cursor != NULL) {
        if (!collect_direct_deps(first_dep, cursor->s)) return false;
        cursor = (s_struct_dep *) ((flist_node_t *) cursor)->next;
    }
    return true;
}

static bool compare_struct_deps(const void *va, const void *vb) {
    const s_struct_dep *a = (const s_struct_dep *) va;
    const s_struct_dep *b = (const s_struct_dep *) vb;
    const char *n1 = a->s->name;
    const char *n2 = b->s->name;
    size_t l1 = strlen(n1);
    size_t l2 = strlen(n2);
    int cmp = strncmp(n1, n2, MIN(l1, l2));
    if (cmp < 0) return true;
    if (cmp > 0) return false;
    return l1 <= l2;
}

static void delete_struct_dep(void *node) {
    APP_MEM_FREE(node);
}

bool type_hash(const char *struct_name, uint8_t struct_name_length, uint8_t *hash_buf) {
    const s_struct_712 *struct_ptr = get_structn(struct_name, struct_name_length);
    if (struct_ptr == NULL) return false;

    if (cx_keccak_init_no_throw(&global_sha3, 256) != CX_OK) return false;

    s_struct_dep *deps = NULL;
    if (!get_struct_dependencies(&deps, struct_ptr)) {
        flist_clear((flist_node_t **) &deps, &delete_struct_dep);
        return false;
    }
    flist_sort((flist_node_t **) &deps, &compare_struct_deps);

    if (!encode_and_hash_type(struct_ptr)) {
        flist_clear((flist_node_t **) &deps, &delete_struct_dep);
        return false;
    }
    const s_struct_dep *iter = deps;
    while (iter != NULL) {
        if (!encode_and_hash_type(iter->s)) {
            flist_clear((flist_node_t **) &deps, &delete_struct_dep);
            return false;
        }
        iter = (const s_struct_dep *) ((const flist_node_t *) iter)->next;
    }
    flist_clear((flist_node_t **) &deps, &delete_struct_dep);

    return finalize_hash((cx_hash_t *) &global_sha3, hash_buf, KECCAK256_HASH_BYTESIZE);
}
