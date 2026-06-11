#pragma once
#include <stdint.h>
#include "cx.h"
#include "os.h"

#define MAX_BIP32_PATH 10

// Length in bytes of the r and s components of a secp256k1 ECDSA signature
// (256-bit group order). Used as the rs_len parameter of cx_ecdsa_sign_rs_no_throw
// and as the size of the sig_r / sig_s output buffers.
#define SECP256K1_RS_LEN 32

// Length in bytes of the message digest fed to ECDSA on secp256k1.
// Numerically equal to SECP256K1_RS_LEN on this curve, but kept as a separate
// symbol to make the intent (hash length vs signature-component length) explicit.
#define SECP256K1_HASH_LEN 32

extern int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                                     uint8_t *chain_code,  // Can be NULL.
                                     const uint32_t bip32_path[static MAX_BIP32_PATH],
                                     uint8_t bip32_path_len);

extern cx_err_t crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                                       cx_ecfp_public_key_t *public_key,
                                       uint8_t raw_public_key[static 64]);

extern int crypto_sign_message(uint8_t sig_r[static SECP256K1_RS_LEN],
                               uint8_t sig_s[static SECP256K1_RS_LEN],
                               uint8_t v[static 1]);

extern int crypto_sign_hash(const uint8_t hash[static SECP256K1_HASH_LEN],
                            uint8_t sig_r[static SECP256K1_RS_LEN],
                            uint8_t sig_s[static SECP256K1_RS_LEN],
                            uint8_t v[static 1]);

extern void parseBip32Path(uint8_t **dataBuffer,
                           uint16_t *dataLength,
                           uint8_t *bip32PathLength,
                           uint32_t bip32Path[static MAX_BIP32_PATH]);

extern uint32_t set_result_get_publicKey(void);
