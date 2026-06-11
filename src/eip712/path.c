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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/path.c
 ********************************************************************************/

#include <string.h>

#include "os.h"
#include "app_mem_utils.h"

#include "context_712.h"
#include "hash_bytes.h"
#include "path.h"
#include "type_hash.h"
#include "typed_data.h"

static s_path *path_struct = NULL;
static s_hash_ctx *g_hash_ctxs = NULL;

// ============================================================================
// Forward / helper
// ============================================================================

static const void *get_nth_field_from(const s_path *path, uint8_t *fields_count_ptr, uint8_t n) {
    if (path == NULL || path->root_struct == NULL) return NULL;
    if (n > path->depth_count) return NULL;

    const s_struct_712 *struct_ptr = path->root_struct;
    const s_struct_712_field *field_ptr = NULL;
    for (uint8_t depth = 0; depth < n; depth++) {
        field_ptr = struct_ptr->fields;
        if (field_ptr == NULL) return NULL;
        if (fields_count_ptr != NULL) {
            *fields_count_ptr = 0;
            for (const s_struct_712_field *t = field_ptr; t != NULL;
                 t = (const s_struct_712_field *) ((const flist_node_t *) t)->next) {
                *fields_count_ptr += 1;
            }
        }
        for (uint8_t i = 0; i < path->depths[depth]; i++) {
            field_ptr = (const s_struct_712_field *) ((const flist_node_t *) field_ptr)->next;
            if (field_ptr == NULL) return NULL;
        }
        if (field_ptr->type == TYPE_CUSTOM) {
            const char *typename = get_struct_field_typename(field_ptr);
            struct_ptr = get_structn(typename, strlen(typename));
            if (struct_ptr == NULL) return NULL;
        }
    }
    return field_ptr;
}

static const void *get_nth_field(uint8_t *fields_count_ptr, uint8_t n) {
    return get_nth_field_from(path_struct, fields_count_ptr, n);
}

const void *path_get_nth_field(uint8_t n) {
    return get_nth_field(NULL, n);
}

const void *path_get_field(void) {
    if (path_struct == NULL) return NULL;
    return get_nth_field(NULL, path_struct->depth_count);
}

uint8_t path_get_depth_count(void) {
    return path_struct == NULL ? 0 : path_struct->depth_count;
}

e_root_type path_get_root_type(void) {
    return path_struct == NULL ? ROOT_NONE : path_struct->root_type;
}

const s_struct_712 *path_get_root(void) {
    return path_struct == NULL ? NULL : path_struct->root_struct;
}

// ============================================================================
// Hash context stack (linked list)
// ============================================================================

s_hash_ctx *get_last_hash_ctx(void) {
    list_node_t *iter = (list_node_t *) g_hash_ctxs;
    while (iter != NULL && iter->next != NULL) {
        iter = iter->next;
    }
    return (s_hash_ctx *) iter;
}

static s_hash_ctx *get_previous_hash_ctx(s_hash_ctx *ctx) {
    if (ctx == NULL) return NULL;
    return (s_hash_ctx *) ((list_node_t *) ctx)->prev;
}

static void delete_hash_ctx(void *node) {
    APP_MEM_FREE(node);
}

static void remove_last_hash_ctx(void) {
    list_pop_back((list_node_t **) &g_hash_ctxs, &delete_hash_ctx);
}

static bool push_new_hash_depth(bool init) {
    s_hash_ctx *ctx = NULL;
    if (!APP_MEM_CALLOC((void **) &ctx, sizeof(*ctx))) return false;
    if (init) {
        if (cx_keccak_init_no_throw(&ctx->hash, 256) != CX_OK) {
            APP_MEM_FREE(ctx);
            return false;
        }
    }
    list_push_back((list_node_t **) &g_hash_ctxs, (list_node_t *) ctx);
    return true;
}

static bool finalize_hash_depth(uint8_t *out) {
    s_hash_ctx *ctx = get_last_hash_ctx();
    if (ctx == NULL) return false;
    size_t hashed = ctx->hash.blen;
    if (!finalize_hash((cx_hash_t *) &ctx->hash, out, KECCAK256_HASH_BYTESIZE)) {
        return false;
    }
    remove_last_hash_ctx();
    return hashed > 0;
}

static bool feed_last_hash_depth(const uint8_t *hash) {
    s_hash_ctx *ctx = get_last_hash_ctx();
    if (ctx == NULL) return false;
    return cx_hash_no_throw((cx_hash_t *) &ctx->hash, 0, hash, KECCAK256_HASH_BYTESIZE, NULL, 0) ==
           CX_OK;
}

// ============================================================================
// Depth stack
// ============================================================================

static bool path_depth_list_push(void) {
    if (path_struct == NULL) return false;
    if (path_struct->depth_count >= MAX_PATH_DEPTH) return false;
    path_struct->depths[path_struct->depth_count] = 0;
    path_struct->depth_count += 1;
    return true;
}

static bool path_depth_list_pop(void) {
    if (path_struct == NULL || path_struct->depth_count == 0) return false;
    uint8_t hash[KECCAK256_HASH_BYTESIZE];
    bool to_feed;

    path_struct->depth_count -= 1;
    to_feed = finalize_hash_depth(hash);
    if (path_struct->depth_count > 0) {
        if (to_feed) {
            if (!feed_last_hash_depth(hash)) return false;
        }
    } else {
        if (eip712_context != NULL) {
            if (path_struct->root_type == ROOT_DOMAIN) {
                memcpy(eip712_context->domain_hash, hash, KECCAK256_HASH_BYTESIZE);
                eip712_context->domain_ready = true;
            } else if (path_struct->root_type == ROOT_MESSAGE) {
                memcpy(eip712_context->message_hash, hash, KECCAK256_HASH_BYTESIZE);
                eip712_context->message_ready = true;
            }
        }
    }
    return true;
}

static bool array_depth_list_push(uint8_t pidx, uint8_t size) {
    if (path_struct == NULL) return false;
    if (path_struct->array_depth_count >= MAX_ARRAY_DEPTH) return false;
    s_array_depth *a = &path_struct->array_depths[path_struct->array_depth_count++];
    a->path_index = pidx;
    a->size = size;
    a->index = 0;
    return true;
}

static bool array_depth_list_pop(void) {
    if (path_struct == NULL || path_struct->array_depth_count == 0) return false;
    uint8_t hash[KECCAK256_HASH_BYTESIZE];
    finalize_hash_depth(hash);
    if (!feed_last_hash_depth(hash)) return false;
    path_struct->array_depth_count -= 1;
    return true;
}

// ============================================================================
// Path advance / update
// ============================================================================

static bool path_update(bool skip_if_array, bool stop_at_array, bool do_typehash) {
    if (path_struct == NULL) return false;
    const s_struct_712_field *starting_field = path_get_field();
    if (starting_field == NULL) return false;

    const s_struct_712_field *field = starting_field;
    uint8_t hash[KECCAK256_HASH_BYTESIZE];

    while (field->type == TYPE_CUSTOM) {
        if (((field == starting_field) && skip_if_array) ||
            ((field != starting_field) && stop_at_array)) {
            if (field->type_is_array) {
                bool is_outer_array = false;
                if (path_struct->array_depth_count > 0) {
                    const s_struct_712_field *outer = get_nth_field(
                        NULL,
                        path_struct->array_depths[path_struct->array_depth_count - 1].path_index +
                            1);
                    is_outer_array = (outer != NULL) && (outer == field);
                }
                if (!is_outer_array) {
                    break;
                }
            }
        }
        const char *typename = get_struct_field_typename(field);
        const s_struct_712 *child = get_structn(typename, strlen(typename));
        if (child == NULL || child->fields == NULL) return false;
        field = child->fields;

        if (!push_new_hash_depth(true)) return false;
        if (do_typehash) {
            if (!type_hash(typename, strlen(typename), hash)) return false;
            if (!feed_last_hash_depth(hash)) return false;
        }
        if (!path_depth_list_push()) return false;
    }
    return true;
}

bool path_set_root(const char *struct_name, uint8_t name_length) {
    if (path_struct == NULL) return false;

    const s_struct_712 *new_root = get_structn(struct_name, name_length);
    if (new_root == NULL || new_root == path_struct->root_struct) return false;
    path_struct->root_struct = new_root;

    if (!push_new_hash_depth(true)) return false;
    uint8_t hash[KECCAK256_HASH_BYTESIZE];
    if (!type_hash(struct_name, name_length, hash)) return false;
    if (!feed_last_hash_depth(hash)) return false;

    path_struct->depth_count = 0;
    path_depth_list_push();
    path_struct->array_depth_count = 0;

    if (name_length == strlen(DOMAIN_STRUCT_NAME) &&
        memcmp(struct_name, DOMAIN_STRUCT_NAME, name_length) == 0) {
        if (path_struct->root_type != ROOT_NONE) return false;
        path_struct->root_type = ROOT_DOMAIN;
    } else {
        if (path_struct->root_type != ROOT_DOMAIN) return false;
        path_struct->root_type = ROOT_MESSAGE;
    }

    path_update(true, true, true);
    return true;
}

static bool check_and_add_array_depth(s_struct_712_field_array_level *array_lvl,
                                      uint8_t total_count,
                                      uint8_t pidx,
                                      uint8_t size) {
    uint8_t arr_idx = (total_count - path_struct->array_depth_count) - 1;
    array_lvl += arr_idx;
    if (array_lvl->type == ARRAY_FIXED_SIZE && array_lvl->size != size) {
        return false;
    }
    return array_depth_list_push(pidx, size);
}

bool path_new_array_depth(const uint8_t *data, uint8_t length) {
    if (path_struct == NULL || length != 1) return false;

    s_hash_ctx *start_hash_ctx = get_last_hash_ctx();
    uint8_t array_size = data[0];

    if (!path_update(false, array_size > 0, array_size > 0)) return false;

    uint8_t array_depth_count_bak = path_struct->array_depth_count;
    const s_struct_712_field *field = NULL;
    uint8_t total = 0;
    uint8_t pidx;

    for (pidx = 0; pidx < path_struct->depth_count; pidx++) {
        field = get_nth_field(NULL, pidx + 1);
        if (field == NULL) return false;
        if (field->type_is_array) {
            if (field->array_levels == NULL) return false;
            total += field->array_level_count;
            if (total > path_struct->array_depth_count) {
                if (!check_and_add_array_depth(field->array_levels, total, pidx, array_size)) {
                    return false;
                }
                break;
            }
        }
    }
    if (pidx == path_struct->depth_count) return false;

    bool is_custom = field->type == TYPE_CUSTOM;
    if (!push_new_hash_depth(!is_custom)) return false;

    if (is_custom) {
        // PR #905 fix: re-anchor hash contexts so the array-level hasher sits
        // before the entered struct hasher, not after it.
        if (start_hash_ctx == NULL) return false;
        s_hash_ctx *cur = get_last_hash_ctx();
        s_hash_ctx *prev = get_previous_hash_ctx(cur);
        while (prev != start_hash_ctx) {
            if (cur == NULL || prev == NULL) return false;
            if (array_size > 0) {
                memcpy(&cur->hash, &prev->hash, sizeof(prev->hash));
            } else {
                if (cx_keccak_init_no_throw((cx_sha3_t *) &cur->hash, 256) != CX_OK) return false;
            }
            if (cx_keccak_init_no_throw((cx_sha3_t *) &prev->hash, 256) != CX_OK) return false;
            cur = prev;
            prev = get_previous_hash_ctx(cur);
        }
        if (cx_keccak_init_no_throw((cx_sha3_t *) &cur->hash, 256) != CX_OK) return false;
    }

    if (array_size == 0) {
        do {
            path_advance(false);
        } while (path_struct->array_depth_count > array_depth_count_bak);
    }
    return true;
}

static bool path_advance_in_struct(void) {
    if (path_struct == NULL || path_struct->depth_count == 0) return false;
    uint8_t fields_count = 0;
    if (path_get_field() == NULL) return false;
    (void) get_nth_field(&fields_count, path_struct->depth_count);
    uint8_t *depth = &path_struct->depths[path_struct->depth_count - 1];
    *depth += 1;
    bool end = (*depth == fields_count);
    if (end) {
        path_depth_list_pop();
    }
    return end;
}

static bool path_advance_in_array(void) {
    if (path_struct == NULL) return true;
    bool end_reached;
    do {
        end_reached = false;
        if (path_struct->array_depth_count == 0) break;
        s_array_depth *arr = &path_struct->array_depths[path_struct->array_depth_count - 1];
        if (arr->path_index == (path_struct->depth_count - 1)) {
            arr->index += 1;
            if (arr->index == arr->size) {
                array_depth_list_pop();
                end_reached = true;
            } else {
                return false;
            }
        }
    } while (end_reached);
    return true;
}

bool path_advance(bool do_typehash) {
    bool end_reached;
    do {
        if (path_advance_in_array()) {
            end_reached = path_advance_in_struct();
        } else {
            end_reached = false;
        }
    } while (end_reached);
    return path_update(true, true, do_typehash);
}

// ============================================================================
// Init / deinit
// ============================================================================

bool path_init(void) {
    if (path_struct != NULL) {
        path_deinit();
    }
    if (!APP_MEM_CALLOC((void **) &path_struct, sizeof(*path_struct))) return false;
    g_hash_ctxs = NULL;
    return true;
}

void path_deinit(void) {
    if (path_struct != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &path_struct);
    }
    list_clear((list_node_t **) &g_hash_ctxs, &delete_hash_ctx);
}
