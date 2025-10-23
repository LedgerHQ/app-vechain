#pragma once

#include <stdint.h>
#include "crypto.h"

typedef struct publicKeyContext_t {
    cx_ecfp_public_key_t publicKey;
    uint8_t address[41];
    uint8_t chainCode[32];
    bool getChaincode;
} publicKeyContext_t;

typedef struct transactionContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t hash[32];
} transactionContext_t;

typedef struct messageSigningContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t hash[32];
    uint32_t remainingLength;
} messageSigningContext_t;

typedef union tmpCtx_t {
    publicKeyContext_t publicKeyContext;
    transactionContext_t transactionContext;
    messageSigningContext_t messageSigningContext;
} tmpCtx_t;

extern tmpCtx_t tmpCtx;

extern volatile char fullAddress[43];
extern volatile char fullAmount[50];
extern volatile char maxFee[60];
extern volatile bool dataPresent;
extern volatile bool multipleClauses;

extern void display_reset(void);
extern void handleApdu(volatile uint32_t flags[static 1], volatile uint32_t tx[static 1]);
