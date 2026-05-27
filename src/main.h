#pragma once

#include "crypto.h"
#include "vetClauseUstream.h"
#include "vetUstream.h"
#include "vetDisplay.h"

typedef struct internalStorage_t {
    uint8_t dataAllowed;
    uint8_t multiClauseAllowed;
    uint8_t eip712Allowed;
    uint8_t blindSign712;
    uint8_t initialized;
} internalStorage_t;

extern const internalStorage_t N_storage_real;
#define N_storage (*(volatile internalStorage_t *) PIC(&N_storage_real))

extern void ui_idle(void);
