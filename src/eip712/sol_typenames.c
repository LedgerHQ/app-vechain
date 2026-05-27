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
 *  Adapted from LedgerHQ/app-ethereum src/features/sign_message_eip712/sol_typenames.c
 ********************************************************************************/

#include "os.h"
#include "sol_typenames.h"

bool sol_typenames_init(void) {
    return true;
}

void sol_typenames_deinit(void) {
}

const char *get_struct_field_sol_typename(const s_struct_712_field *field_ptr) {
    if (field_ptr == NULL) return NULL;
    switch ((e_type) field_ptr->type) {
        case TYPE_SOL_INT:
            return "int";
        case TYPE_SOL_UINT:
            return "uint";
        case TYPE_SOL_ADDRESS:
            return "address";
        case TYPE_SOL_BOOL:
            return "bool";
        case TYPE_SOL_STRING:
            return "string";
        case TYPE_SOL_BYTES_FIX:
        case TYPE_SOL_BYTES_DYN:
            return "bytes";
        case TYPE_CUSTOM:
        default:
            return NULL;
    }
}
