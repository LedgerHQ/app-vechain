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

#include "offsets.h"
#include "vetUtils.h"
#include "vetDisplay.h"
#include "main.h"
#include "handlers.h"
#include "tokens.h"
#include "ui_callback.h"
#include "ui_nbgl.h"
#include "eip712_common.h"
#include "eip712_dispatch.h"

#define HASH_LENGTH 2
#define HASH_OFFSET (HASH_LENGTH * 2 + 3)

#define CLA                       0xE0
#define INS_GET_PUBLIC_KEY        0x02
#define INS_SIGN                  0x04
#define INS_GET_APP_CONFIGURATION 0x06
#define INS_SIGN_PERSONAL_MESSAGE 0x08
#define INS_SIGN_CERTIFICATE      0x09
// EIP-712 INS values are declared in eip712/eip712_common.h
// (INS_SIGN_EIP_712 0x0C, INS_EIP712_SEND_STRUCT_DEFINITION 0x1A,
//  INS_EIP712_SEND_STRUCT_IMPL 0x1C)
#define P1_CONFIRM      0x01
#define P1_NON_CONFIRM  0x00
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE    0x01
#define P1_FIRST        0x00
#define P1_MORE         0x80

#define CONFIG_DATA_ENABLED        0x01
#define CONFIG_MULTICLAUSE_ENABLED 0x01
#define CONFIG_EIP712_ENABLED      0x01

/* Constants related to this dependencies to send apdu codes to app-vechain
    https://github.com/dinn2018/hw-app-vet/blob/master/src/index.ts#L137-L168
*/
#define ERROR_TYPE_MASK 0xF000
#define ERROR_TYPE_HW   0x6000

const internalStorage_t N_storage_real;

static const uint8_t TOKEN_TRANSFER_ID[] = {0xa9, 0x05, 0x9c, 0xbb};
static const uint8_t TICKER_VET[] = "VET ";

cx_blake2b_t blake2b;
volatile char fullAddress[43];
volatile char fullAmount[50];
volatile char maxFee[60];
volatile bool dataPresent;
volatile bool multipleClauses;

static const char SIGN_MAGIC[] =
    "\x19"
    "VeChain Signed Message:\n";

typedef struct txFullContext_t {
    txContext_t txContext;
    clausesContext_t clausesContext;
    clauseContext_t clauseContext;
} txFullContext_t;

typedef struct displayContext_t {
    txFullContext_t txFullContext;
    feeComputationContext_t feeComputationContext;
} displayContext_t;

union {
    txContent_t txContent;
} tmpContent;

tmpCtx_t tmpCtx;
displayContext_t displayContext;
clausesContent_t clausesContent;
clauseContent_t clauseContent;

/////////////////////////////////////////////////////////////////////
void display_reset(void) {
    memset((void *) &displayContext, 0, sizeof(displayContext));
}

/////////////////////////////////////////////////////////////////////

void ui_idle(void) {
    ui_menu_main();
}

/////////////////////////////////////////////////////////////////////

/**
 * @brief Handles the retrieval of a public key based on a given BIP32 path and instruction
 * parameters.
 *
 * @details This function retrieves a public key based on the provided BIP32 path and instruction
 * parameters. It follows these steps:
 * - Verifies the validity of the BIP32 path and instruction parameters.
 * - Derives a private key using the provided BIP32 path.
 * - Initializes a public key based on the derived private key.
 * - Clears the private key from memory after deriving the public key.
 * - Constructs an Ethereum address from the derived public key.
 * - Handles different modes of operation (confirm/non-confirm).
 * - Initiates UI-based interaction for confirmation (if necessary).
 *
 * @param[in] p1 Instruction parameter 1 (P1), indicating confirmation mode.
 * @param[in] p2 Instruction parameter 2 (P2), indicating chaincode inclusion.
 * @param[in] dataBuffer Pointer to the data buffer containing BIP32 path and optional data.
 * @param[in] dataLength Length of the data buffer.
 * @param[in,out] flags Pointer to flags for APDU processing.
 * @param[in,out] tx Pointer to the outgoing APDU buffer size.
 */
void handleGetPublicKey(uint8_t p1,
                        uint8_t p2,
                        uint8_t dataBuffer[static 255],
                        uint16_t dataLength,
                        volatile uint32_t flags[static 1],
                        volatile uint32_t tx[static 1]) {
    uint8_t rawPublicKey[64] = {0};
    uint32_t bip32Path[MAX_BIP32_PATH] = {0};
    uint8_t bip32PathLength = 0;
    cx_ecfp_private_key_t privateKey = {0};
    // Verify the correctness of instruction parameters (P1, P2)
    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        THROW(SWO_WRONG_P1_P2);
    }
    if ((p2 != P2_CHAINCODE) && (p2 != P2_NO_CHAINCODE)) {
        THROW(SWO_WRONG_P1_P2);
    }

    // Extract the BIP32 path from the data buffer
    parseBip32Path(&dataBuffer, &dataLength, &bip32PathLength, bip32Path);

    // Determine whether to include chaincode in the derived private key
    tmpCtx.publicKeyContext.getChaincode = (p2 == P2_CHAINCODE);

    // Derive private key using the provided BIP32 path
    crypto_derive_private_key(
        &privateKey,
        (tmpCtx.publicKeyContext.getChaincode ? tmpCtx.publicKeyContext.chainCode : NULL),
        bip32Path,
        bip32PathLength);

    // Initialize public key based on the derived private key
    crypto_init_public_key(&privateKey, &tmpCtx.publicKeyContext.publicKey, rawPublicKey);

    // reset private key
    explicit_bzero(&privateKey, sizeof(privateKey));

    // Construct VeChain address from the derived public key
    getVetAddressStringFromKey(&tmpCtx.publicKeyContext.publicKey, tmpCtx.publicKeyContext.address);

    // Handle different modes of operation (confirm/non-confirm)
    if (p1 == P1_NON_CONFIRM) {
        *tx = set_result_get_publicKey();
        THROW(SWO_SUCCESS);
    } else {
        // Format the address for display
        snprintf((char *) fullAddress,
                 sizeof(fullAddress),
                 "0x%.*s",
                 40,
                 tmpCtx.publicKeyContext.address);

        // Display the public key using the UI
        ui_display_public_key_flow();

        // Set flags for asynchronous reply
        *flags |= IO_ASYNCH_REPLY;
    }
}

/**
 * @brief Handles the signing of a transaction.
 *
 * @details This function handles the signing of a transaction. It supports both the first
 * part of the transaction and subsequent parts. It follows these steps:
 * - Parses the input parameters to determine the action to be taken.
 * - Initializes the transaction context and prepares for transaction processing.
 * - Processes the transaction data, including path extraction, clause content, and data presence.
 * - Stores the transaction hash and performs necessary checks.
 * - Prepares the display or UI for confirming the transaction signing action.
 *
 * @param[in] p1 Instruction parameter 1 (P1), indicating the type of transaction signing action.
 *        If set to P1_FIRST, it indicates the beginning of a new signing operation.
 *        If set to P1_MORE, it indicates further parts of the signing operation.
 * @param[in] p2 Instruction parameter 2 (P2), currently unused.
 * @param[in] workBuffer Pointer to the data buffer containing the transaction data.
 * @param[in] dataLength Length of the transaction data.
 * @param[in,out] flags Pointer to flags for APDU processing.
 * @param[in,out] tx Pointer to the outgoing APDU buffer size.
 */
void handleSign(uint8_t p1,
                uint8_t p2,
                uint8_t workBuffer[static 255],
                uint16_t dataLength,
                volatile uint32_t flags[static 1],
                volatile uint32_t tx[static 1]) {
    UNUSED(tx);
    uint8_t tx_type;
    parserStatus_e txResult;
    uint32_t i;
    uint8_t decimals = DECIMALS_VET;
    uint8_t *ticker = (uint8_t *) TICKER_VET;

    if (p1 == P1_FIRST) {
        memset(&clausesContent, 0, sizeof(clausesContent));
        memset(&clauseContent, 0, sizeof(clauseContent));

        // Extract and parse the BIP32 path
        parseBip32Path(&workBuffer,
                       &dataLength,
                       &tmpCtx.transactionContext.pathLength,
                       tmpCtx.transactionContext.bip32Path);
        dataPresent = false;
        initTx(&displayContext.txFullContext.txContext,
               &tmpContent.txContent,
               &displayContext.txFullContext.clausesContext,
               &clausesContent,
               &displayContext.txFullContext.clauseContext,
               &clauseContent,
               &blake2b,
               NULL);

        // The first chunk must carry at least one transaction byte after the
        // BIP32 path. Without this check, reading workBuffer[0] runs past the
        // host data and the VIP251 branch's `dataLength--` underflows the
        // uint16_t to ~65535, which is then fed as commandLength to processTx
        // and triggers an out-of-bounds read in the RLP parser.
        if (dataLength < 1) {
            PRINTF("Missing transaction payload\n");
            THROW(SWO_INCORRECT_DATA);
        }

        // VIP252: TransactionType might be present before the TransactionPayload.
        tx_type = workBuffer[0];
        if (tx_type == VIP251) {
            PRINTF("VIP251 transaction type %d\n", sizeof(tx_type));
            CX_ASSERT(
                cx_hash_no_throw((cx_hash_t *) &blake2b, 0, &tx_type, sizeof(tx_type), NULL, 0));
            displayContext.txFullContext.txContext.txType = tx_type;
            workBuffer++;
            dataLength--;
        } else {
            displayContext.txFullContext.txContext.txType = LEGACY;
        }
    } else if (p1 != P1_MORE) {
        THROW(SWO_WRONG_P1_P2);
    }
    if (p2 != 0) {
        THROW(SWO_WRONG_P1_P2);
    }
    if (displayContext.txFullContext.txContext.currentField == TX_RLP_NONE) {
        PRINTF("Parser not initialized\n");
        THROW(SWO_CONDITIONS_NOT_SATISFIED);
    }
    if (displayContext.txFullContext.clausesContext.currentField == CLAUSES_RLP_NONE) {
        PRINTF("Parser not initialized\n");
        THROW(SWO_CONDITIONS_NOT_SATISFIED);
    }
    txResult = processTx(&displayContext.txFullContext.txContext,
                         &displayContext.txFullContext.clausesContext,
                         &displayContext.txFullContext.clauseContext,
                         workBuffer,
                         dataLength);
    PRINTF("txResult:%d\n", txResult);
    switch (txResult) {
        case USTREAM_FINISHED:
            break;
        case USTREAM_PROCESSING:
            THROW(SWO_SUCCESS);
        case USTREAM_FAULT:
            THROW(SWO_INCORRECT_DATA);
        default:
            PRINTF("Unexpected parser status\n");
            THROW(SWO_INCORRECT_DATA);
    }

    // Store the hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &blake2b,
                               CX_LAST,
                               NULL,
                               0,
                               tmpCtx.transactionContext.hash,
                               32));

    PRINTF("messageHash:\n%.*H\n", 32, tmpCtx.transactionContext.hash);
    // Check for data presence
    dataPresent = clausesContent.dataPresent;
    if (dataPresent && !N_storage.dataAllowed) {
        PRINTF("Data field forbidden\n");
        THROW(SWO_INCORRECT_DATA);
    }

    // Check for multiple clauses
    multipleClauses = (clausesContent.clausesLength > 1);
    if (multipleClauses && !N_storage.multiClauseAllowed) {
        PRINTF("Multiple clauses forbidden\n");
        THROW(SWO_INCORRECT_DATA);
    }

    // If there is a token to process, check if it is well known
    if (dataPresent && memcmp(clauseContent.data, TOKEN_TRANSFER_ID, 4) == 0) {
        for (i = 0; i < NUM_TOKENS; i++) {
            tokenDefinition_t *currentToken = PIC(&TOKENS[i]);
            if (memcmp(currentToken->address, clauseContent.to, 20) == 0) {
                dataPresent = false;
                decimals = currentToken->decimals;
                ticker = currentToken->ticker;
                clauseContent.toLength = 20;
                memmove(clauseContent.to, clauseContent.data + 4 + 12, 20);
                memmove(clauseContent.value.value, clauseContent.data + 4 + 32, 32);
                clauseContent.value.length = 32;
                break;
            }
        }
    }

    // Add address
    addressToDisplayString(clauseContent.to, (uint8_t *) fullAddress);

    // Add amount in ethers or tokens. Refuse the TX if the formatted amount
    // would not fit in the display buffer: an HSM that silently truncates
    // here would let the host trick the user into approving a number that is
    // shorter than what gets actually signed.
    bool amount_ok = sendAmountToDisplayString(&clauseContent.value,
                                               ticker,
                                               decimals,
                                               (uint8_t *) fullAmount,
                                               sizeof(fullAmount));
    bool fee_ok;
    if (displayContext.txFullContext.txContext.txType == VIP251) {
        fee_ok = maxFeeVIP251ToDisplayString(&tmpContent.txContent.maxFeePerGas,
                                             &tmpContent.txContent.gas,
                                             &displayContext.feeComputationContext,
                                             (uint8_t *) maxFee,
                                             sizeof(maxFee));
    } else {
        fee_ok = maxFeeToDisplayString(&tmpContent.txContent.gaspricecoef,
                                       &tmpContent.txContent.gas,
                                       &displayContext.feeComputationContext,
                                       (uint8_t *) maxFee,
                                       sizeof(maxFee));
    }
    if (!amount_ok || !fee_ok) {
        PRINTF("Display formatting overflow (amount_ok=%d fee_ok=%d)\n",
               (int) amount_ok,
               (int) fee_ok);
        THROW(SWO_INCORRECT_DATA);
    }

    ui_display_action_sign_tx_flow();

    *flags |= IO_ASYNCH_REPLY;
}

/**
 * @brief Retrieves the application configuration settings and version information.
 *
 * @details This function retrieves the application configuration settings and version information
 * for the current application. It follows these steps:
 * - Retrieves the application configuration settings from non-volatile storage.
 * - Retrieves the major, minor, and patch version numbers of the application.
 * - Sets the outgoing APDU buffer with the configuration settings and version information.
 * - Sets the outgoing APDU buffer size to indicate the number of bytes transmitted.
 *
 * @note Settings flag bits:
 * - bit 0 (0x01): contract data signature allowed.
 * - bit 1 (0x02): multiple clauses transactions allowed.
 * - bit 2 (0x04): EIP-712 typed-data signing allowed (master switch).
 * - bit 3 (0x08): EIP-712 v0 (blind signing) allowed.
 *
 * @param[in] p1 Instruction parameter 1 (P1), currently unused.
 * @param[in] p2 Instruction parameter 2 (P2), currently unused.
 * @param[in] workBuffer Pointer to the data buffer (currently unused).
 * @param[in] dataLength Length of the data buffer (currently unused).
 * @param[in,out] flags Pointer to flags for APDU processing (currently unused).
 * @param[in,out] tx Pointer to the outgoing APDU buffer size.
 */
void handleGetAppConfiguration(uint8_t p1,
                               uint8_t p2,
                               uint8_t workBuffer[static 255],
                               uint16_t dataLength,
                               volatile uint32_t flags[static 1],
                               volatile uint32_t tx[static 1]) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);
    UNUSED(flags);

    // Retrieve configuration settings (see doc/vetapp.asc for the bit layout)
    G_io_apdu_buffer[0] =
        (uint8_t) ((N_storage.dataAllowed ? CONFIG_DATA_ENABLED : 0x00) |
                   (N_storage.multiClauseAllowed ? CONFIG_MULTICLAUSE_ENABLED << 1 : 0x00) |
                   (N_storage.eip712Allowed ? CONFIG_EIP712_ENABLED << 2 : 0x00) |
                   (N_storage.blindSign712 ? 0x08 : 0x00));

    // Retrieve version information
    G_io_apdu_buffer[1] = MAJOR_VERSION;
    G_io_apdu_buffer[2] = MINOR_VERSION;
    G_io_apdu_buffer[3] = PATCH_VERSION;

    // Set transaction buffer size
    *tx = 4;
    THROW(SWO_SUCCESS);
}

/**
 * @brief Handles the signing of a certificate.
 *
 * @details This function handles the signing of a certificate, supporting both
 * the first part of the certificate and subsequent parts. It follows these steps:
 * - Parses the input parameters to determine the action to be taken.
 * - Initializes the certificate signing context and computes the certificate header.
 * - Updates the certificate hash with the certificate data for subsequent parts.
 * - Finalizes the certificate hash and generates the certificate signature when the entire
 * certificate is processed.
 * - Prepares the display or UI for confirming the certificate signing action.
 *
 * @note This function assumes the following:
 *       - The certificate data is in JSON format.
 *       - The BIP32 path for the key derivation is provided before the certificate data.
 *       - The certificate signing operation may involve multiple parts.
 *
 * @param[in] p1 Instruction parameter 1 (P1), indicating the type of certificate signing action.
 *        If set to P1_FIRST, it indicates the beginning of a new signing operation.
 *        If set to P1_MORE, it indicates further parts of the signing operation.
 * @param[in] p2 Instruction parameter 2 (P2), currently unused.
 * @param[in] workBuffer Pointer to the data buffer containing the certificate data.
 * @param[in] dataLength Length of the certificate data.
 * @param[in,out] flags Pointer to flags for APDU processing.
 * @param[in,out] tx Pointer to the outgoing APDU buffer size.
 *
 */
void handleSignCertificate(uint8_t p1,
                           uint8_t p2,
                           uint8_t workBuffer[static 255],
                           uint16_t dataLength,
                           volatile uint32_t flags[static 1],
                           volatile uint32_t tx[static 1]) {
    UNUSED(tx);

    // Process the first part of the certificate signing operation
    if (p1 == P1_FIRST) {
        // Extract and parse the BIP32 path
        parseBip32Path(&workBuffer,
                       &dataLength,
                       &tmpCtx.transactionContext.pathLength,
                       tmpCtx.transactionContext.bip32Path);

        // The first chunk must carry the 4-byte length AND at least the
        // opening '{' of the JSON certificate. Without these checks the
        // length read OOB-reads past the host data and `dataLength -= 4`
        // underflows the uint16_t.
        if (dataLength < 5) {
            PRINTF("Missing certificate length / opening byte\n");
            THROW(SWO_INCORRECT_DATA);
        }

        // Extract and parse the remaining length (cast to uint32_t to avoid
        // `int` promotion UB when bit 7 of the high byte is set).
        tmpCtx.messageSigningContext.remainingLength =
            ((uint32_t) workBuffer[0] << 24) | ((uint32_t) workBuffer[1] << 16) |
            ((uint32_t) workBuffer[2] << 8) | (uint32_t) workBuffer[3];
        workBuffer += 4;
        dataLength -= 4;

        // Check if the certificate starts with '{' (indicating JSON format)
        if (workBuffer[0] != '{') {
            PRINTF("Invalid json\n");
            THROW(SWO_INCORRECT_DATA);
        }

        // Initialize Blake2b hash function with a 256-bit output size
        CX_ASSERT(cx_blake2b_init_no_throw(&blake2b, 256));
    } else if (p1 != P1_MORE) {
        THROW(SWO_WRONG_P1_P2);
    }
    if (p2 != 0) {
        THROW(SWO_WRONG_P1_P2);
    }
    if (dataLength > tmpCtx.messageSigningContext.remainingLength) {
        THROW(SWO_INSUFFICIENT_MEMORY);
    }

    // Update message hash with certificate data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &blake2b, 0, workBuffer, dataLength, NULL, 0));
    tmpCtx.messageSigningContext.remainingLength -= dataLength;

    // Check if all certificate data has been processed
    if (tmpCtx.messageSigningContext.remainingLength == 0) {
        // Check if the certificate ends with '}' (indicating JSON format)
        if (workBuffer[dataLength - 1] != '}') {
            PRINTF("Invalid json\n");
            THROW(SWO_INCORRECT_DATA);
        }

        // Finalize message hash
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &blake2b,
                                   CX_LAST,
                                   NULL,
                                   0,
                                   tmpCtx.messageSigningContext.hash,
                                   32));

        // Convert the message hash to hexadecimal string
        bytes_to_hex((char *) fullAddress,
                     HASH_OFFSET,
                     tmpCtx.messageSigningContext.hash,
                     HASH_LENGTH);
        // Add separator characters
        fullAddress[HASH_LENGTH * 2] = '.';
        fullAddress[HASH_LENGTH * 2 + 1] = '.';
        fullAddress[HASH_LENGTH * 2 + 2] = '.';
        // Convert the second half of the message hash to hexadecimal string
        bytes_to_hex((char *) fullAddress + HASH_OFFSET,
                     sizeof(fullAddress) - HASH_OFFSET,
                     tmpCtx.messageSigningContext.hash + 32 - HASH_LENGTH,
                     HASH_LENGTH);

        // Display the action for signing a certificate
        ui_display_action_sign_msg_cert(CERTIFICATE_TRANSACTION);

        // Set flag for asynchronous reply
        *flags |= IO_ASYNCH_REPLY;
    } else {
        THROW(SWO_SUCCESS);
    }
}

/**
 * @brief Handles the signing of a personal message.
 *
 * @details This function handles the signing of a personal message. It supports both
 * the first part of the message and subsequent parts. It follows these steps:
 * - Parses the input parameters to determine the action to be taken.
 * - Initializes the message context and computes the message header.
 * - Updates the message hash with the message data for subsequent parts of the message.
 * - Finalizes the message hash and generates the message signature when the entire message is
 * processed.
 * - Prepares the display or UI for confirming the message signing action.
 *
 * @param[in] p1 Instruction parameter 1 (P1), indicating the type of message signing action.
 * @param[in] p2 Instruction parameter 2 (P2), currently unused.
 * @param[in] workBuffer Pointer to the data buffer containing the message data.
 * @param[in] dataLength Length of the message data.
 * @param[in,out] flags Pointer to flags for APDU processing.
 * @param[in,out] tx Pointer to the outgoing APDU buffer size (currently unused).
 */
void handleSignPersonalMessage(uint8_t p1,
                               uint8_t p2,
                               uint8_t workBuffer[static 255],
                               uint16_t dataLength,
                               volatile uint32_t flags[static 1],
                               volatile uint32_t tx[static 1]) {
    UNUSED(tx);

    if (p1 == P1_FIRST) {
        // First part of the message
        char tmp[11];
        uint32_t index;
        uint32_t base = 10;
        uint8_t pos = 0;

        // Extract and parse the BIP32 path
        parseBip32Path(&workBuffer,
                       &dataLength,
                       &tmpCtx.transactionContext.pathLength,
                       tmpCtx.transactionContext.bip32Path);

        // Reject APDUs that don't carry the full 4-byte big-endian message
        // length. Skipping this check used to underflow `dataLength` (uint16_t)
        // to ~65532 and caused a downstream OOB read inside cx_hash_no_throw.
        if (dataLength < 4) {
            PRINTF("Missing message length\n");
            THROW(SWO_INCORRECT_DATA);
        }

        // Parse remaining message length (cast each byte to uint32_t to avoid
        // implementation-defined `int` promotion when bit 7 is set).
        tmpCtx.messageSigningContext.remainingLength =
            ((uint32_t) workBuffer[0] << 24) | ((uint32_t) workBuffer[1] << 16) |
            ((uint32_t) workBuffer[2] << 8) | (uint32_t) workBuffer[3];
        workBuffer += 4;
        dataLength -= 4;
        // Initialize message header + length
        CX_ASSERT(cx_blake2b_init_no_throw(&blake2b, 256));
        // Hash the signature magic constant
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &blake2b,
                                   0,
                                   (uint8_t *) SIGN_MAGIC,
                                   sizeof(SIGN_MAGIC) - 1,
                                   NULL,
                                   0));

        // Calculate the index for message header + length
        for (index = 1; (((index * base) <= tmpCtx.messageSigningContext.remainingLength) &&
                         (((index * base) / base) == index));
             index *= base)
            ;

        // Generate the message header + length as a string
        for (; index; index /= base) {
            tmp[pos++] = '0' + ((tmpCtx.messageSigningContext.remainingLength / index) % base);
        }
        tmp[pos] = '\0';

        // Hash the message header + length
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &blake2b, 0, (uint8_t *) tmp, pos, NULL, 0));
    } else if (p1 != P1_MORE) {
        THROW(SWO_WRONG_P1_P2);
    }
    if (p2 != 0) {
        THROW(SWO_WRONG_P1_P2);
    }
    if (dataLength > tmpCtx.messageSigningContext.remainingLength) {
        THROW(SWO_INSUFFICIENT_MEMORY);
    }

    // Update message hash with message data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &blake2b, 0, workBuffer, dataLength, NULL, 0));
    // Decrease the remaining length by the processed data length
    tmpCtx.messageSigningContext.remainingLength -= dataLength;

    // Check if all message data has been processed
    if (tmpCtx.messageSigningContext.remainingLength == 0) {
        // Finalize message hash
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &blake2b,
                                   CX_LAST,
                                   NULL,
                                   0,
                                   tmpCtx.messageSigningContext.hash,
                                   32));

        // Convert the message hash to hexadecimal string
        bytes_to_hex((char *) fullAddress,
                     HASH_OFFSET,
                     tmpCtx.messageSigningContext.hash,
                     HASH_LENGTH);
        // Add separator characters
        fullAddress[HASH_LENGTH * 2] = '.';
        fullAddress[HASH_LENGTH * 2 + 1] = '.';
        fullAddress[HASH_LENGTH * 2 + 2] = '.';

        // Convert the second half of the message hash to hexadecimal string
        bytes_to_hex((char *) fullAddress + HASH_OFFSET,
                     sizeof(fullAddress) - HASH_OFFSET,
                     tmpCtx.messageSigningContext.hash + 32 - HASH_LENGTH,
                     HASH_LENGTH);

        // Display the action for signing a message
        ui_display_action_sign_msg_cert(MSG_TRANSACTION);

        // Set flag for asynchronous reply
        *flags |= IO_ASYNCH_REPLY;

    } else {
        // More data remains to be processed, return OK status
        THROW(SWO_SUCCESS);
    }
}

/**
 * @brief Handles incoming APDU commands and delegates them to instruction handler based on (INS).
 *
 * @details This function processes incoming APDU commands and delegates them to specific handlers
 * based on the instruction (INS) field of the APDU. It follows these steps:
 * - Verifies if the class (CLA) of the APDU command is supported 0xE0.
 * - Routes the APDU to the appropriate handler based on its instruction (INS).
 * - Handles exceptions such as IO reset or hardware errors.
 *
 * @note APDU commands are structured as follows:
 * - CLA: Instruction class 0xE0
 * - INS: Instruction code
 * - P1-P2: Instruction parameters
 * - LC: Length of the data in the data field of the command [0x00, 0xFF]
 * - Data field of the command. (MAX 255 bytes)
 *
 * @param[in,out] flags Pointer to flags for APDU processing.
 * @param[in,out] tx Pointer to the outgoing APDU buffer size.
 *
 * @return void
 */
void handleApdu(volatile uint32_t flags[static 1], volatile uint32_t tx[static 1]) {
    unsigned short sw = 0;

    BEGIN_TRY {
        TRY {
            // Check if the class of the APDU command is supported.
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(SWO_INVALID_CLA);
            }

            PRINTF("New APDU received:\n%.*H\n",
                   G_io_apdu_buffer[OFFSET_LC] + OFFSET_LC,
                   G_io_apdu_buffer);

            // Handle different APDU instructions based on their INS (Instruction) field.
            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_PUBLIC_KEY:
                    handleGetPublicKey(G_io_apdu_buffer[OFFSET_P1],
                                       G_io_apdu_buffer[OFFSET_P2],
                                       G_io_apdu_buffer + OFFSET_CDATA,
                                       G_io_apdu_buffer[OFFSET_LC],
                                       flags,
                                       tx);
                    break;

                case INS_SIGN:
                    handleSign(G_io_apdu_buffer[OFFSET_P1],
                               G_io_apdu_buffer[OFFSET_P2],
                               G_io_apdu_buffer + OFFSET_CDATA,
                               G_io_apdu_buffer[OFFSET_LC],
                               flags,
                               tx);
                    break;

                case INS_GET_APP_CONFIGURATION:
                    handleGetAppConfiguration(G_io_apdu_buffer[OFFSET_P1],
                                              G_io_apdu_buffer[OFFSET_P2],
                                              G_io_apdu_buffer + OFFSET_CDATA,
                                              G_io_apdu_buffer[OFFSET_LC],
                                              flags,
                                              tx);
                    break;

                case INS_SIGN_PERSONAL_MESSAGE:
                    handleSignPersonalMessage(G_io_apdu_buffer[OFFSET_P1],
                                              G_io_apdu_buffer[OFFSET_P2],
                                              G_io_apdu_buffer + OFFSET_CDATA,
                                              G_io_apdu_buffer[OFFSET_LC],
                                              flags,
                                              tx);
                    break;

                case INS_SIGN_CERTIFICATE:
                    handleSignCertificate(G_io_apdu_buffer[OFFSET_P1],
                                          G_io_apdu_buffer[OFFSET_P2],
                                          G_io_apdu_buffer + OFFSET_CDATA,
                                          G_io_apdu_buffer[OFFSET_LC],
                                          flags,
                                          tx);
                    break;

                case INS_SIGN_EIP_712:
                case INS_EIP712_SEND_STRUCT_DEFINITION:
                case INS_EIP712_SEND_STRUCT_IMPL:
                    eip712_dispatch_apdu(G_io_apdu_buffer[OFFSET_INS],
                                         G_io_apdu_buffer[OFFSET_P1],
                                         G_io_apdu_buffer[OFFSET_P2],
                                         G_io_apdu_buffer + OFFSET_CDATA,
                                         G_io_apdu_buffer[OFFSET_LC],
                                         flags,
                                         tx);
                    break;

                default:
                    THROW(SWO_INVALID_INS);
                    break;
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
            switch (e & ERROR_TYPE_MASK) {
                case ERROR_TYPE_HW:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    memset(&displayContext, 0, sizeof(displayContext));
                    break;
                case SWO_SUCCESS:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            // Unexpected exception => report
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY {
        }
    }
    END_TRY;
}
