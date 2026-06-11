/*******************************************************************************
 *   Ledger Blue
 *   (c) 2016 Ledger
 *   (c) 2018 Totient Labs
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "status_words.h"
#include "os.h"
#include "cx.h"
#include "handlers.h"

/**
 * @brief Sets the result for the GET_PUBLIC_KEY command.
 *
 * @details This function prepares the APDU buffer with the result data for the GET_PUBLIC_KEY
 * command. It copies the public key, address, and chain code (if available) into the APDU buffer.
 *
 * @return The total size of the data written to the APDU buffer.
 */
uint32_t set_result_get_publicKey() {
    // Initialize the buffer size counter
    uint32_t tx = 0;
    // Set size of the public key, copy the public key into the APDU buffer, and update the buffer
    // size counter
    G_io_apdu_buffer[tx++] = 65;
    memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.publicKey.W, 65);
    tx += 65;
    // Set size of the address, copy the address into the APDU buffer, and update the buffer size
    // counter
    G_io_apdu_buffer[tx++] = 40;
    memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.address, 40);
    tx += 40;
    // if chaincode is available, copy the chaincode into the APDU buffer and update the buffer size
    // counter
    if (tmpCtx.publicKeyContext.getChaincode) {
        memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.chainCode, 32);
        tx += 32;
    }
    return tx;
}

/**
 * @brief Derives a private key according to a given BIP32 path.
 *
 * @details This function derives a private key based on the provided BIP32 path and initializes the
 * private key structure. It follows these steps:
 * - Derives the raw private key and chain code using the BIP32 path.
 * - Initializes the private key structure with the derived raw private key.
 * - Clears the raw private key from memory after use for security.
 *
 * @param[out] private_key Pointer to store the derived private key.
 * @param[out] chain_code Pointer to store the derived chain code.
 * @param[in] bip32_path Pointer to the BIP32 path.
 * @param[in] bip32_path_len Length of the BIP32 path.
 *
 * @return Error code indicating the success or failure of the operation.
 */
int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t *chain_code,  // Can be NULL.
                              const uint32_t bip32_path[static MAX_BIP32_PATH],
                              uint8_t bip32_path_len) {
    // must be 64, even if we only use 32
    uint8_t raw_private_key[64] = {0};
    int error = 0;

    // Derive the raw private key and chain code using the BIP32 path
    error = os_derive_bip32_no_throw(CX_CURVE_256K1,
                                     bip32_path,
                                     bip32_path_len,
                                     raw_private_key,
                                     chain_code);
    if (error != 0) {
        // Clear the raw private key from memory if an error occurs
        explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        return error;
    }

    // Initialize the private key structure with the derived raw private key
    error = cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, raw_private_key, 32, private_key);

    // Clear the raw private key from memory after use for security
    explicit_bzero(&raw_private_key, sizeof(raw_private_key));
    return error;
}

/**
 * @brief Initializes a public key from a given private key.
 *
 * @details This function generates the corresponding public key from the provided private key.
 * It follows these steps:
 * - Generates the corresponding public key using the provided private key and the specified
 * elliptic curve.
 * - Copies the raw public key to the output buffer.
 *
 * @param[in] private_key Pointer to the private key.
 * @param[out] public_key Pointer to store the generated public key.
 * @param[out] raw_public_key Pointer to the buffer to store the raw public key.
 *
 * @return Error code indicating the success or failure of the operation.
 */
cx_err_t crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                                cx_ecfp_public_key_t *public_key,
                                uint8_t raw_public_key[static 64]) {
    // generate corresponding public key
    cx_err_t error = cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, public_key, private_key, 1);
    if (error) return error;

    // Copy the raw public key to the output buffer
    memmove(raw_public_key, public_key->W + 1, 64);
    return 0;
}

/**
 * @brief Signs a message using a private key.
 *
 * @details This function signs a message using the provided private key and computes the signature
 * components (R, S, V). It follows these steps:
 * - Derives the private key according to the BIP32 path.
 * - Signs the message using the private key, producing the R and S components of the signature.
 * - Determines the V component based on the signature information.
 * - Clears the private key from memory after use for security.
 *
 * @param[out] sig_r Pointer to store the R component of the signature.
 * @param[out] sig_s Pointer to store the S component of the signature.
 * @param[out] v Pointer to store the V component of the signature.
 *
 * @return Error code indicating the success or failure of the operation.
 */
int crypto_sign_hash(const uint8_t hash[static SECP256K1_HASH_LEN],
                     uint8_t sig_r[static SECP256K1_RS_LEN],
                     uint8_t sig_s[static SECP256K1_RS_LEN],
                     uint8_t v[static 1]) {
    cx_ecfp_private_key_t private_key = {0};
    uint32_t info = 0;
    memset(sig_r, 0, SECP256K1_RS_LEN);
    memset(sig_s, 0, SECP256K1_RS_LEN);
    memset(v, 0, 1);

    // derive private key according to BIP32 path
    int error = crypto_derive_private_key(&private_key,
                                          NULL,
                                          tmpCtx.transactionContext.bip32Path,
                                          tmpCtx.transactionContext.pathLength);

    if (error != 0) {
        return error;
    }

    // Sign the provided hash using the private key
    error = cx_ecdsa_sign_rs_no_throw(&private_key,
                                      CX_RND_RFC6979 | CX_LAST,
                                      CX_SHA256,
                                      hash,
                                      SECP256K1_HASH_LEN,
                                      SECP256K1_RS_LEN,
                                      sig_r,
                                      sig_s,
                                      &info);

    // Clear the private key from memory after use for security
    explicit_bzero(&private_key, sizeof(private_key));
    PRINTF("Signature: %.*H\n", SECP256K1_RS_LEN, sig_r);
    PRINTF("%.*H\n", SECP256K1_RS_LEN, sig_s);
    PRINTF("%.*H\n", 1, &info);

    // Determine the V component based on the signature information
    if (error == 0) {
        if (info & CX_ECCINFO_PARITY_ODD) {
            v[0] |= 0x01;
        }
    }
    PRINTF("%.*H\n", 1, v);

    return error;
}

int crypto_sign_message(uint8_t sig_r[static SECP256K1_RS_LEN],
                        uint8_t sig_s[static SECP256K1_RS_LEN],
                        uint8_t v[static 1]) {
    return crypto_sign_hash(tmpCtx.messageSigningContext.hash, sig_r, sig_s, v);
}

/**
 * @brief Parses a BIP32 path from a buffer and save it with its path length,
 * updating the buffer pointer and data length.
 *
 * @details
 * The function proceeds as follows:
 * - Reads the path length from the first byte of the work buffer.
 * - Checks if the path length is within the valid range.
 * - Parses each 4-byte component of the BIP32 path from the buffer and stores it in the bip32Path
 * array.
 * - Updates the work buffer pointer and data length to reflect the bytes consumed during parsing.
 *
 * @param[in,out] pWorkBuffer Pointer to the pointer of the work buffer containing the BIP32 path +
 * data The pointer of the work buffer is incremented as the buffer is parsed.
 * @param[in,out] dataLength Pointer to the remaining length of the data in the work buffer.
 *                           This length is decremented as bytes are consumed from the buffer.
 * @param[out] pathLength Pointer to uint8_t BIP32 pathLength of a transactionContext_t or
 * messageSigningContext_t.
 * @param[out] bip32Path uint32_t *bip32Path of a transactionContext_t or messageSigningContext_t.
 *                       The array should have a size of at least MAX_BIP32_PATH.
 */
void parseBip32Path(uint8_t **pWorkBuffer,
                    uint16_t dataLength[static 1],
                    uint8_t pathLength[static 1],
                    uint32_t bip32Path[static MAX_BIP32_PATH]) {
    uint32_t i;
    // check all initialized pointers
    if (pWorkBuffer == NULL || *pWorkBuffer == NULL || dataLength == NULL || pathLength == NULL ||
        bip32Path == NULL) {
        THROW(SWO_UNKNOWN);
    }
    // retrieve the path length
    *pathLength = (*pWorkBuffer)[0];
    if ((*pathLength < 0x01) || (*pathLength > MAX_BIP32_PATH) ||
        *dataLength < 1 + *pathLength * 4) {
        PRINTF("Invalid path\n");
        THROW(SWO_INCORRECT_DATA);
    }
    (*pWorkBuffer)++;
    (*dataLength)--;

    if (*dataLength < *pathLength) {
        THROW(SWO_INCORRECT_DATA);
    }
    // parse each 4-byte component of the BIP32 path
    for (i = 0; i < *pathLength; i++) {
        bip32Path[i] = ((*pWorkBuffer)[0] << 24) | ((*pWorkBuffer)[1] << 16) |
                       ((*pWorkBuffer)[2] << 8) | ((*pWorkBuffer)[3]);
        (*pWorkBuffer) += 4;
        (*dataLength) -= 4;
    }
}
