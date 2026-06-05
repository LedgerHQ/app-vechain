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

#include <string.h>

#include "os.h"
#include "app_mem_utils.h"

#include "vetUtils.h"
#include "uint256.h"

#include "context_712.h"
#include "ui_logic.h"

static const char HEX_DIGITS[] = "0123456789abcdef";

extern void ui_display_action_sign_eip712_v1_flow(void);

typedef struct {
    char *current_key;
    uint8_t *current_value;
    uint16_t current_value_len;
    uint16_t current_value_cap;
    uint8_t current_field_type;
    uint8_t current_field_type_size;
    bool field_active;
} s_ui_712_state;

static s_ui_712_state ui_712_state;

static void reset_state(void) {
    if (ui_712_state.current_value != NULL) {
        APP_MEM_FREE(ui_712_state.current_value);
    }
    if (ui_712_state.current_key != NULL) {
        APP_MEM_FREE(ui_712_state.current_key);
    }
    memset(&ui_712_state, 0, sizeof(ui_712_state));
}

bool ui_712_init(void) {
    reset_state();
    return true;
}

void ui_712_deinit(void) {
    reset_state();
}

bool ui_712_show_raw_key(const s_struct_712_field *field_ptr) {
    if (field_ptr == NULL || field_ptr->key_name == NULL) return false;
    reset_state();

    // Raw clear-sign mode: display the field key as declared in the typed-data
    // type definition, no CAL filter overrides.
    const char *raw_key = field_ptr->key_name;
    size_t klen = strlen(raw_key);
    ui_712_state.current_key = APP_MEM_ALLOC(klen + 1);
    if (ui_712_state.current_key == NULL) return false;
    memmove(ui_712_state.current_key, raw_key, klen + 1);
    ui_712_state.current_field_type = field_ptr->type;
    ui_712_state.current_field_type_size = field_ptr->type_size;
    ui_712_state.field_active = true;
    return true;
}

bool ui_712_feed_to_display(const s_struct_712_field *field_ptr,
                            const uint8_t *data,
                            uint8_t data_length,
                            uint16_t *total_length,
                            bool last) {
    UNUSED(field_ptr);
    UNUSED(last);
    if (!ui_712_state.field_active) return true;

    if (total_length != NULL) {
        ui_712_state.current_value_cap = *total_length;
        if (ui_712_state.current_value_cap == 0) {
            ui_712_state.current_value_cap = data_length;
        }
        ui_712_state.current_value =
            APP_MEM_ALLOC(ui_712_state.current_value_cap > 0 ? ui_712_state.current_value_cap : 1);
        if (ui_712_state.current_value == NULL) return false;
        ui_712_state.current_value_len = 0;
    }
    if (data_length > 0) {
        if (ui_712_state.current_value_len + data_length > ui_712_state.current_value_cap) {
            return false;
        }
        memmove(ui_712_state.current_value + ui_712_state.current_value_len, data, data_length);
        ui_712_state.current_value_len += data_length;
    }
    return true;
}

static void truncate_with_ellipsis(char *out, size_t out_size) {
    if (out_size < 4) return;
    size_t len = strlen(out);
    if (len + 1 < out_size) return;
    out[out_size - 4] = '.';
    out[out_size - 3] = '.';
    out[out_size - 2] = '.';
    out[out_size - 1] = '\0';
}

static void format_hex_bytes(const uint8_t *value, size_t v_len, char *out, size_t out_size) {
    if (out_size < 3) {
        if (out_size > 0) out[0] = '\0';
        return;
    }
    out[0] = '0';
    out[1] = 'x';
    size_t cursor = 2;
    for (size_t i = 0; i < v_len && cursor + 2 < out_size; i++) {
        out[cursor++] = HEX_DIGITS[(value[i] >> 4) & 0x0f];
        out[cursor++] = HEX_DIGITS[value[i] & 0x0f];
    }
    out[cursor] = '\0';
    truncate_with_ellipsis(out, out_size);
}

static void format_address(const uint8_t *value, size_t v_len, char *out, size_t out_size) {
    if (v_len != 20 || out_size < 43) {
        format_hex_bytes(value, v_len, out, out_size);
        return;
    }
    out[0] = '0';
    out[1] = 'x';
    getVetAddressStringFromBinary((uint8_t *) value, (uint8_t *) out + 2);
}

static void format_uint(const uint8_t *value, size_t v_len, char *out, size_t out_size) {
    if (v_len > 32 || out_size < 2) {
        format_hex_bytes(value, v_len, out, out_size);
        return;
    }
    uint8_t padded[32] = {0};
    memmove(padded + 32 - v_len, value, v_len);
    uint256_t big;
    readu256BE(padded, &big);
    if (!tostring256(&big, 10, out, (uint32_t) out_size)) {
        format_hex_bytes(value, v_len, out, out_size);
    }
}

// Signed-integer formatter. The host minimises positive values (it strips
// leading 0x00 bytes) but streams negative values at the full type width
// (`type_size` bytes). encode_field.c::encode_int() relies on the same
// convention: it only sign-extends when `length == type_size`. So a value is
// negative ONLY when it spans the full type width AND its top bit is set.
// Inferring the sign from the top bit alone is wrong: a minimised positive
// such as int256(128) arrives as a single 0x80 byte, which encode_int() hashes
// as +128 but the old logic rendered as -128 -> display/signature mismatch.
static void format_int(const uint8_t *value,
                       size_t v_len,
                       uint8_t type_size,
                       char *out,
                       size_t out_size) {
    if (v_len == 0 || v_len > 32 || out_size < 3) {
        format_hex_bytes(value, v_len, out, out_size);
        return;
    }
    if ((value[0] & 0x80) == 0 || v_len != type_size) {
        format_uint(value, v_len, out, out_size);
        return;
    }
    uint8_t magnitude[32] = {0};
    size_t start = 32 - v_len;
    for (size_t i = 0; i < v_len; i++) {
        magnitude[start + i] = (uint8_t) ~value[i];
    }
    for (size_t i = 32; i > 0; i--) {
        magnitude[i - 1] = (uint8_t) (magnitude[i - 1] + 1);
        if (magnitude[i - 1] != 0) break;
    }
    out[0] = '-';
    uint256_t big;
    readu256BE(magnitude, &big);
    if (!tostring256(&big, 10, out + 1, (uint32_t) (out_size - 1))) {
        format_hex_bytes(value, v_len, out, out_size);
    }
}

static void format_bool(const uint8_t *value, size_t v_len, char *out, size_t out_size) {
    bool t = false;
    for (size_t i = 0; i < v_len; i++) {
        if (value[i] != 0) {
            t = true;
            break;
        }
    }
    if (out_size >= 6) {
        strlcpy(out, t ? "true" : "false", out_size);
    } else if (out_size > 0) {
        out[0] = t ? '1' : '0';
        out[1] = '\0';
    }
}

static void format_string(const uint8_t *value, size_t v_len, char *out, size_t out_size) {
    if (out_size == 0) return;
    size_t copy = v_len < out_size - 1 ? v_len : out_size - 1;
    memmove(out, value, copy);
    out[copy] = '\0';
    if (copy < v_len) truncate_with_ellipsis(out, out_size);
}

static void format_value(uint8_t type,
                         const uint8_t *value,
                         size_t v_len,
                         uint8_t type_size,
                         char *out,
                         size_t out_size) {
    if (out_size == 0) return;
    out[0] = '\0';
    switch ((e_type) type) {
        case TYPE_SOL_UINT:
            format_uint(value, v_len, out, out_size);
            break;
        case TYPE_SOL_INT:
            format_int(value, v_len, type_size, out, out_size);
            break;
        case TYPE_SOL_ADDRESS:
            format_address(value, v_len, out, out_size);
            break;
        case TYPE_SOL_BOOL:
            format_bool(value, v_len, out, out_size);
            break;
        case TYPE_SOL_STRING:
            format_string(value, v_len, out, out_size);
            break;
        case TYPE_SOL_BYTES_FIX:
        case TYPE_SOL_BYTES_DYN:
            format_hex_bytes(value, v_len, out, out_size);
            break;
        case TYPE_CUSTOM:
        default:
            strlcpy(out, "(struct)", out_size);
            break;
    }
}

void ui_712_finalize_field(void) {
    if (!ui_712_state.field_active) return;

    char value_buf[EIP712_DISPLAY_VALUE_MAX];
    const uint8_t *val = ui_712_state.current_value;
    size_t val_len = (val != NULL) ? ui_712_state.current_value_len : 0;
    if (val == NULL) {
        val = (const uint8_t *) "";
    }
    format_value(ui_712_state.current_field_type,
                 val,
                 val_len,
                 ui_712_state.current_field_type_size,
                 value_buf,
                 sizeof(value_buf));

    const char *key_interned = eip712_intern_string(ui_712_state.current_key);
    const char *value_interned = eip712_intern_string(value_buf);

    if (key_interned == NULL || value_interned == NULL ||
        !eip712_display_push(key_interned, value_interned)) {
        // Either interning failed (arena exhausted) or the display cap was
        // reached. Mark the context so the sign handler can refuse: never
        // ask the user to approve a partially-displayed typed-data message.
        if (eip712_context != NULL) {
            eip712_context->display_overflow = true;
        }
    }

    if (ui_712_state.current_value != NULL) {
        APP_MEM_FREE(ui_712_state.current_value);
        ui_712_state.current_value = NULL;
    }
    if (ui_712_state.current_key != NULL) {
        APP_MEM_FREE(ui_712_state.current_key);
        ui_712_state.current_key = NULL;
    }
    ui_712_state.field_active = false;
    ui_712_state.current_value_len = 0;
    ui_712_state.current_value_cap = 0;
}

void ui_712_present_review(void) {
    ui_display_action_sign_eip712_v1_flow();
}
