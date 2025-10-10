#pragma once
#include <stdint.h>
#include "cx.h"
#include "os.h"

#define MAX_BIP32_PATH 10

extern int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                                     uint8_t *chain_code,  // Can be NULL.
                                     const uint32_t bip32_path[static MAX_BIP32_PATH],
                                     uint8_t bip32_path_len);

extern cx_err_t crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                                       cx_ecfp_public_key_t *public_key,
                                       uint8_t raw_public_key[static 64]);

extern int crypto_sign_message(uint8_t sig_r[static 32],
                               uint8_t sig_s[static 32],
                               uint8_t v[static 1]);

extern void parseBip32Path(uint8_t **dataBuffer,
                           uint16_t *dataLength,
                           uint8_t *bip32PathLength,
                           uint32_t bip32Path[static MAX_BIP32_PATH]);

extern uint32_t set_result_get_publicKey(void);
