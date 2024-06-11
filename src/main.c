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

#include "os.h"
#include "cx.h"
#include "stdbool.h"
#include "vetUstream.h"
#include "vetUtils.h"
#include "vetDisplay.h"
#include "uint256.h"
#include "tokens.h"

#include "os_io_seproxyhal.h"
#include <string.h>

#include "ux.h"

#include "main.h"
#include "ui_nbgl.h"

const internalStorage_t N_storage_real;
unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

uint32_t set_result_get_publicKey(void);

#define MAX_BIP32_PATH 10

#define CLA 0xE0
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN 0x04
#define INS_GET_APP_CONFIGURATION 0x06
#define INS_SIGN_PERSONAL_MESSAGE 0x08
#define INS_SIGN_CERTIFICATE 0x09
#define P1_CONFIRM 0x01
#define P1_NON_CONFIRM 0x00
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE 0x01
#define P1_FIRST 0x00
#define P1_MORE 0x80

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

#define CONFIG_DATA_ENABLED 0x01
#define CONFIG_MULTICLAUSE_ENABLED 0x01

#define DECIMALS_VET 18

/* Constants related to this dependencies to send apdu codes to app-vechain
    https://github.com/dinn2018/hw-app-vet/blob/master/src/index.ts#L137-L168
*/
#define HW_SW_TRANSACTION_CANCELLED 0x6985
#define HW_TECHNICAL_PROBLEM 0x6F00
#define HW_INCORRECT_DATA 0x6A80
#define HW_INCORRECT_P1_P2 0x6B00
#define HW_OK 0x9000
#define HW_INVALID_MESSAGE_SIZE 0x6a83
#define HW_NOT_ENOUGH_MEMORY_SPACE 0x6A84
#define HW_CLA_NOT_SUPPORTED 0x6E00
#define HW_INS_NOT_SUPPORTED 0x6D00
#define HW_SECURITY_STATUS_NOT_SATISFIED 0x6982
#define ERROR_TYPE_MASK 0xF000
#define ERROR_TYPE_HW 0x6000

static const uint8_t TOKEN_TRANSFER_ID[] = {0xa9, 0x05, 0x9c, 0xbb};
static const uint8_t TICKER_VET[] = "VET ";

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

union {
    publicKeyContext_t publicKeyContext;
    transactionContext_t transactionContext;
    messageSigningContext_t messageSigningContext;
} tmpCtx;

typedef struct txFullContext_t {
    txContext_t txContext;
    clausesContext_t clausesContext;
    clauseContext_t clauseContext;
} txFullContext_t;

union {
    txFullContext_t txFullContext;
    feeComputationContext_t feeComputationContext;
} displayContext;

union {
    txContent_t txContent;
} tmpContent;
clausesContent_t clausesContent;
clauseContent_t clauseContent;

cx_blake2b_t blake2b;
volatile char addressSummary[32];
volatile char fullAddress[43];
volatile char fullAmount[50];
volatile char maxFee[60];
volatile bool dataPresent;
volatile bool multipleClauses;
volatile bool skipDataWarning;
volatile bool skipClausesWarning;

#ifdef HAVE_BAGL
bagl_element_t tmp_element;
#endif

#include "ux.h"
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

static const char SIGN_MAGIC[] = "\x19"
                                       "VeChain Signed Message:\n";

const unsigned char hex_digits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
/**
 * @brief Appends the given status word (SW) to the APDU buffer.
 *
 * @param[in,out] tx Pointer to the apdu buffer size.
 * @param[in] sw The status word (SW) to be appended.
 */
void apdu_buffer_append_state(uint32_t tx[static 1], unsigned short sw)
{
    G_io_apdu_buffer[(*tx)++] = sw >> 8;
    G_io_apdu_buffer[(*tx)++] = sw;
}

void array_hexstr(char *strbuf, const void *bin, unsigned int len) {
    while (len--) {
        *strbuf++ = hex_digits[((*((char *)bin)) >> 4) & 0xF];
        *strbuf++ = hex_digits[(*((char *)bin)) & 0xF];
        bin = (const void *)((unsigned int)bin + 1);
    }
    *strbuf = 0; // EOS
}

#ifdef HAVE_BAGL
const bagl_element_t *ui_menu_item_out_over(const bagl_element_t *e) {
    // the selection rectangle is after the none|touchable
    e = (const bagl_element_t *)(((unsigned int)e) + sizeof(bagl_element_t));
    return e;
}

const char* settings_submenu_getter(unsigned int idx);
void settings_submenu_selector(unsigned int idx);

//////////////////////////////////////////////////////////////////////////////////////
// Contract data submenu:

void settings_contract_data_change(uint8_t enabled) {
    nvm_write((void *)&N_storage.dataAllowed, &enabled, 1);
    ui_idle();
}

const char* const settings_contract_data_getter_values[] = {
  "No",
  "Yes",
  "Back"
};

const char* settings_contract_data_getter(unsigned int idx) {
  if (idx < ARRAYLEN(settings_contract_data_getter_values)) {
    return settings_contract_data_getter_values[idx];
  }
  return NULL;
}

void settings_contract_data_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      settings_contract_data_change(0);
      break;
    case 1:
      settings_contract_data_change(1);
      break;
    default:
      ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector);
  }
}

//////////////////////////////////////////////////////////////////////////////////////
// Clause change submenu:

void settings_clause_change(uint8_t enabled) {
    nvm_write((void *)&N_storage.multiClauseAllowed, &enabled, 1);
    ui_idle();
}

const char* const settings_clause_getter_values[] = {
  "No",
  "Yes",
  "Back"
};

const char* settings_clause_getter(unsigned int idx) {
  if (idx < ARRAYLEN(settings_clause_getter_values)) {
    return settings_clause_getter_values[idx];
  }
  return NULL;
}

void settings_clause_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      settings_clause_change(0);
      break;
    case 1:
      settings_clause_change(1);
      break;
    default:
      ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector);
  }
}

//////////////////////////////////////////////////////////////////////////////////////
// Settings menu:

const char* const settings_submenu_getter_values[] = {
  "Contract data",
  "Multi-clause",
  "Back",
};

const char* settings_submenu_getter(unsigned int idx) {
  if (idx < ARRAYLEN(settings_submenu_getter_values)) {
    return settings_submenu_getter_values[idx];
  }
  return NULL;
}

void settings_submenu_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      ux_menulist_init_select(0, settings_contract_data_getter, settings_contract_data_selector, N_storage.dataAllowed);
      break;
    case 1:
        ux_menulist_init_select(0, settings_clause_getter, settings_clause_selector, N_storage.multiClauseAllowed);
        break;
    default:
      ui_idle();
  }
}

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_idle_flow_1_step,
    pnn,
    {
      &C_nanox_badge,
      "Application",
      "is ready",
    });
UX_STEP_VALID(
    ux_idle_flow_2_step,
    pb,
    ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector),
    {
      &C_icon_coggle,
      "Settings",
    });
UX_STEP_NOCB(
    ux_idle_flow_3_step,
    bn,
    {
      "Version",
      APPVERSION,
    });
UX_STEP_VALID(
    ux_idle_flow_4_step,
    pb,
    os_sched_exit(-1),
    {
      &C_icon_dashboard_x,
      "Quit",
    });
UX_FLOW(ux_idle_flow,
  &ux_idle_flow_1_step,
  &ux_idle_flow_2_step,
  &ux_idle_flow_3_step,
  &ux_idle_flow_4_step
);


//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_display_public_flow_5_step,
    bnnn_paging,
    {
      .title = "Address",
      .text = (char *)fullAddress,
    });
UX_STEP_VALID(
    ux_display_public_flow_6_step,
    pb,
    io_seproxyhal_touch_address_ok(),
    {
      &C_icon_validate_14,
      "Approve",
    });
UX_STEP_VALID(
    ux_display_public_flow_7_step, 
    pb, 
    io_seproxyhal_touch_cancel(),
    {
      &C_icon_crossmark,
      "Reject",
    });
UX_FLOW(ux_display_public_flow,
  &ux_display_public_flow_5_step,
  &ux_display_public_flow_6_step,
  &ux_display_public_flow_7_step
);


//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(ux_confirm_full_flow_1_step,
    pnn,
    {
      &C_icon_eye,
      "Review",
      "transaction",
    });

// OPTIONNAL
UX_STEP_NOCB(
    ux_confirm_full_warning_data_step,
    pnn,
    {
      &C_icon_warning_x,
      "WARNING",
      "Data present",
    });
UX_STEP_NOCB(
    ux_confirm_full_warning_clauses_step,
    pnn,
    {
      &C_icon_warning_x,
      "WARNING",
      "Multiple Clauses",
    });

// OPTIONNAL

UX_STEP_NOCB(
    ux_confirm_full_flow_2_step,
    bnnn_paging,
    {
      .title = "Amount",
      .text = (char *)fullAmount
    });
UX_STEP_NOCB(
    ux_confirm_full_flow_3_step,
    bnnn_paging,
    {
      .title = "Address",
      .text = (char *)fullAddress,
    });
UX_STEP_NOCB(
    ux_confirm_full_flow_4_step,
    bnnn_paging,
    {
      .title = "Max Fees",
      .text = (char *)maxFee,
    });
UX_STEP_VALID(
    ux_confirm_full_flow_5_step,
    pbb,
    io_seproxyhal_touch_tx_ok(),
    {
      &C_icon_validate_14,
      "Accept",
      "and send",
    });
UX_STEP_VALID(
    ux_confirm_full_flow_6_step, 
    pb, 
    io_seproxyhal_touch_cancel(),
    {
      &C_icon_crossmark,
      "Reject",
    });
// confirm_full: confirm transaction / Amount: fullAmount / Address: fullAddress / MaxFees: maxFee
UX_FLOW(ux_confirm_full_flow,
  &ux_confirm_full_flow_1_step,
  &ux_confirm_full_flow_2_step,
  &ux_confirm_full_flow_3_step,
  &ux_confirm_full_flow_4_step,
  &ux_confirm_full_flow_5_step,
  &ux_confirm_full_flow_6_step
);

UX_FLOW(ux_confirm_full_data_flow,
  &ux_confirm_full_flow_1_step,
  &ux_confirm_full_warning_data_step,
  FLOW_BARRIER,
  &ux_confirm_full_flow_2_step,
  &ux_confirm_full_flow_3_step,
  &ux_confirm_full_flow_4_step,
  &ux_confirm_full_flow_5_step,
  &ux_confirm_full_flow_6_step
);

UX_FLOW(ux_confirm_full_clauses_flow,
  &ux_confirm_full_flow_1_step,
  &ux_confirm_full_warning_clauses_step,
  FLOW_BARRIER,
  &ux_confirm_full_flow_2_step,
  &ux_confirm_full_flow_3_step,
  &ux_confirm_full_flow_4_step,
  &ux_confirm_full_flow_5_step,
  &ux_confirm_full_flow_6_step
);

UX_FLOW(ux_confirm_full_data_clauses_flow,
  &ux_confirm_full_flow_1_step,
  &ux_confirm_full_warning_data_step,
  FLOW_BARRIER,
  &ux_confirm_full_warning_clauses_step,
  FLOW_BARRIER,
  &ux_confirm_full_flow_2_step,
  &ux_confirm_full_flow_3_step,
  &ux_confirm_full_flow_4_step,
  &ux_confirm_full_flow_5_step,
  &ux_confirm_full_flow_6_step
);


//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_sign_msg_flow_1_step,
    pnn,
    {
      &C_icon_certificate,
      "Sign",
      "message",
    });
UX_STEP_NOCB(
    ux_sign_msg_flow_2_step,
    bnnn_paging,
    {
      .title = "Message hash",
      .text = (char *)fullAddress,
    });
UX_STEP_VALID(
    ux_sign_msg_flow_3_step,
    pbb,
    io_seproxyhal_touch_tx_ok(),
    {
      &C_icon_validate_14,
      "Sign",
      "message",
    });
UX_STEP_VALID(
    ux_sign_msg_flow_4_step,
    pbb,
    io_seproxyhal_touch_cancel(),
    {
      &C_icon_crossmark,
      "Cancel",
      "signature",
    });

UX_FLOW(ux_sign_msg_flow,
  &ux_sign_msg_flow_1_step,
  &ux_sign_msg_flow_2_step,
  &ux_sign_msg_flow_3_step,
  &ux_sign_msg_flow_4_step
);

UX_STEP_NOCB(
    ux_sign_cert_flow_1_step,
    pnn,
    {
      &C_icon_certificate,
      "Sign",
      "certificate",
    });
UX_STEP_NOCB(
    ux_sign_cert_flow_2_step,
    bnnn_paging,
    {
      .title = "Certificate hash",
      .text = (char *)fullAddress,
    });
UX_STEP_VALID(
    ux_sign_cert_flow_3_step,
    pbb,
    io_seproxyhal_touch_tx_ok(),
    {
      &C_icon_validate_14,
      "Sign",
      "certificate",
    });

UX_FLOW(ux_sign_cert_flow,
  &ux_sign_cert_flow_1_step,
  &ux_sign_cert_flow_2_step,
  &ux_sign_cert_flow_3_step,
  &ux_sign_msg_flow_4_step
);

//////////////////////////////////////////////////////////////////////

void ui_idle(void) {
    skipDataWarning = false;
    skipClausesWarning = false;

    // reserve a display stack slot if none yet
    if(G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
}

#else // HAVE_BAGL

void ui_idle(void) 
{
    skipDataWarning = false;
    skipClausesWarning = false;
    ui_menu_main();
}
#endif


//////////////////////////////// Crypto functions //////////////////////////////////////

/**
 * @brief Derives a private key according to a given BIP32 path.
 *
 * @details This function derives a private key based on the provided BIP32 path and initializes the private key structure.
 * It follows these steps:
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
                              uint8_t *chain_code, // Can be NULL.
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
    if (error != 0){
        // Clear the raw private key from memory if an error occurs
        explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        return error;
    }

    // Initialize the private key structure with the derived raw private key
    error = cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                              raw_private_key,
                                              32,
                                              private_key);

    // Clear the raw private key from memory after use for security
    explicit_bzero(&raw_private_key, sizeof(raw_private_key));
    return error;
}

/**
 * @brief Initializes a public key from a given private key.
 *
 * @details This function generates the corresponding public key from the provided private key.
 * It follows these steps:
 * - Generates the corresponding public key using the provided private key and the specified elliptic curve.
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
                                uint8_t raw_public_key[static 64])
{
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
 * @details This function signs a message using the provided private key and computes the signature components (R, S, V).
 * It follows these steps:
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
int crypto_sign_message(uint8_t sig_r[static 32], uint8_t sig_s[static 32], uint8_t v[static 1])
{
    cx_ecfp_private_key_t private_key = {0};
    uint32_t info = 0;
    memset(sig_r, 0, 32);
    memset(sig_s, 0, 32);
    memset(v, 0, 1);

    // derive private key according to BIP32 path
    int error = crypto_derive_private_key(&private_key,
                                          NULL,
                                          tmpCtx.transactionContext.bip32Path,
                                          tmpCtx.transactionContext.pathLength);
                                          
    if (error != 0) {
        return error;
    }

    // Sign the message using the private key
    error = cx_ecdsa_sign_rs_no_throw(
        &private_key,
        CX_RND_RFC6979 | CX_LAST,
        CX_SHA256,
        tmpCtx.messageSigningContext.hash,
        sizeof(tmpCtx.messageSigningContext.hash),
        32,
        sig_r,
        sig_s,
        &info);

    // Clear the private key from memory after use for security
    explicit_bzero(&private_key, sizeof(private_key));
    PRINTF("Signature: %.*H\n", 32, sig_r);
    PRINTF("%.*H\n", 32, sig_s);
    PRINTF("%.*H\n", 1, &info);

    // Determine the V component based on the signature information
    if (error == 0) 
    {
        if (info & CX_ECCINFO_PARITY_ODD) {
            v[0] |= 0x01;
        }
    }
    PRINTF("%.*H\n", 1, v);

    return error;
}

/**
 * @brief Parses a BIP32 path from a buffer and save it with its path length,
 * updating the buffer pointer and data length.
 *
 * @details
 * The function proceeds as follows:
 * - Reads the path length from the first byte of the work buffer.
 * - Checks if the path length is within the valid range.
 * - Parses each 4-byte component of the BIP32 path from the buffer and stores it in the bip32Path array.
 * - Updates the work buffer pointer and data length to reflect the bytes consumed during parsing.
 *
 * @param[in,out] pWorkBuffer Pointer to the pointer of the work buffer containing the BIP32 path + data
 *                            The pointer of the work buffer is incremented as the buffer is parsed.
 * @param[in,out] dataLength Pointer to the remaining length of the data in the work buffer.
 *                           This length is decremented as bytes are consumed from the buffer.
 * @param[out] pathLength Pointer to uint8_t BIP32 pathLength of a transactionContext_t or messageSigningContext_t.
 * @param[out] bip32Path uint32_t *bip32Path of a transactionContext_t or messageSigningContext_t.
 *                       The array should have a size of at least MAX_BIP32_PATH.
 */
void parseBip32Path(uint8_t **pWorkBuffer, uint16_t dataLength[static 1], uint8_t pathLength[static 1], uint32_t bip32Path[static MAX_BIP32_PATH])
{
    uint32_t i;
    // check all initialized pointers
    if (pWorkBuffer == NULL || *pWorkBuffer == NULL || dataLength == NULL || pathLength == NULL || bip32Path == NULL){
        THROW(HW_TECHNICAL_PROBLEM);
    }
    // retrieve the path length
    *pathLength = (*pWorkBuffer)[0];
    if ((*pathLength < 0x01) || (*pathLength > MAX_BIP32_PATH) || *dataLength < 1 + *pathLength * 4){
        PRINTF("Invalid path\n");
        THROW(HW_INCORRECT_DATA);
    }
    (*pWorkBuffer)++;
    (*dataLength)--;

    if (*dataLength < *pathLength){
        THROW(HW_INCORRECT_DATA);
    }
    // parse each 4-byte component of the BIP32 path
    for (i = 0; i < *pathLength; i++){
        bip32Path[i] = ((*pWorkBuffer)[0] << 24) | ((*pWorkBuffer)[1] << 16) | ((*pWorkBuffer)[2] << 8) | ((*pWorkBuffer)[3]);
        (*pWorkBuffer) += 4;
        (*dataLength) -= 4;
    }
}
/////////////////////////////////////////////////////////////////////


/**
 * @brief Exits the touch operation and returns to the dashboard.
 *
 * @details This function exits the touch operation and returns to the dashboard by invoking the operating system scheduler exit function.
 * It follows these steps:
 * - Calls the operating system scheduler exit function to return to the dashboard.
 * - Returns 0 indicating that the widget should not be redrawn.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_exit() {
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

/**
 * @brief Handles the cancellation of a touch operation.
 *
 * @details This function cancels a touch operation by sending back a response with a cancellation status code.
 * It follows these steps:
 * - Sets the APDU buffer with a cancellation status code.
 * - Sends back the response and does not restart the event loop.
 * - Optionally displays back the original UX if BAGL is supported.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_cancel() {
    uint32_t tx = 0;
    apdu_buffer_append_state(&tx, HW_SW_TRANSACTION_CANCELLED);
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
#ifdef HAVE_BAGL
    // Display back the original UX
    ui_idle();
#endif
    return 0; // do not redraw the widget
}

/**
 * @brief Handles the confirmation of an address.
 *
 * @details This function confirms an address by retrieving the public key and associated data,
 * and sends back the response containing the public key, address, and success status code.
 * It follows these steps:
 * - Calls the set_result_get_publicKey function to set the result containing the public key, address, and chain code.
 * - Adds success status codes to the APDU buffer.
 * - Sends back the response and does not restart the event loop.
 * - Optionally displays back the original UX if BAGL is supported.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_address_ok() {
    uint32_t tx = set_result_get_publicKey();

    // Add success status code
    apdu_buffer_append_state(&tx, HW_OK);

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

#ifdef HAVE_BAGL
    // Display back the original UX
    ui_idle();
#endif
    return 0; // do not redraw the widget
}

/**
 * @brief Handles the confirmation of a transaction.
 *
 * @details This function confirms a transaction by signing the message with the provided parameters,
 * and sends back the response containing the signature and transaction status. It follows these steps:
 * - Initializes variables for signature components and transaction status.
 * - Performs a heartbeat to ensure proper device operation.
 * - Calls the crypto_sign_message function to sign the message.
 * - Moves the signature components and transaction status to the APDU buffer.
 * - Sends back the response and does not restart the event loop.
 * - Optionally displays back the original UX if BAGL is supported.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_tx_ok() {
    uint32_t tx = 0;
    uint8_t sig_r[32];
    uint8_t sig_s[32];
    uint8_t v = 0;
    int error;

    io_seproxyhal_io_heartbeat();
    // Sign the message
    error = crypto_sign_message(sig_r, sig_s, &v);
    io_seproxyhal_io_heartbeat();

    if (error != 0) {
        THROW(error);
    }

    // Move signature components to the APDU buffer
    memmove(G_io_apdu_buffer, sig_r, 32);
    memmove(G_io_apdu_buffer + 32, sig_s, 32);
    tx = 64;
    G_io_apdu_buffer[tx++] = v & 0x01;

    // Clear the signature components from memory after use.
    memset(sig_r, 0, 32);
    memset(sig_s, 0, 32);
    v = 0;

    // Add success status code
    apdu_buffer_append_state(&tx, HW_OK);
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

#ifdef HAVE_BAGL
    // Display back the original UX
    ui_idle();
#endif
    return 0; // do not redraw the widget
}

/**
 * @brief Handles I/O exchange over different communication channels.
 *
 * @details This function facilitates communication with the host device over various channels.
 * It supports keyboard input and multiplexed I/O exchange over a SPI channel using TLV encapsulated protocol.
 *
 * @param[in] channel The communication channel.
 * @param[in] tx_len The length of the data to be transmitted.
 *
 * @return The length of the received data or 0 if nothing received from the master.
 */
unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    // Mask out the IO_FLAGS from the channel
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        // If there is data to transmit
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            // Check if reset is required after replying
            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            // Receive data over SPI
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

/**
 * @brief Sets the result for the GET_PUBLIC_KEY command.
 *
 * @details This function prepares the APDU buffer with the result data for the GET_PUBLIC_KEY command.
 * It copies the public key, address, and chain code (if available) into the APDU buffer.
 *
 * @return The total size of the data written to the APDU buffer.
 */
uint32_t set_result_get_publicKey() {
    // Initialize the buffer size counter
    uint32_t tx = 0;
    // Set size of the public key, copy the public key into the APDU buffer, and update the buffer size counter
    G_io_apdu_buffer[tx++] = 65;
    memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.publicKey.W, 65);
    tx += 65;
    // Set size of the address, copy the address into the APDU buffer, and update the buffer size counter
    G_io_apdu_buffer[tx++] = 40;
    memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.address, 40);
    tx += 40;
    // if chaincode is available, copy the chaincode into the APDU buffer and update the buffer size counter
    if (tmpCtx.publicKeyContext.getChaincode) {
        memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.chainCode,
                   32);
        tx += 32;
    }
    return tx;
}



/**
 * @brief Handles the retrieval of a public key based on a given BIP32 path and instruction parameters.
 *
 * @details This function retrieves a public key based on the provided BIP32 path and instruction parameters.
 * It follows these steps:
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
void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t dataBuffer[static 255],
                        uint16_t dataLength, volatile unsigned int flags[static 1],
                        volatile unsigned int tx[static 1])
{
    uint8_t rawPublicKey[64] = {0};
    uint32_t bip32Path[MAX_BIP32_PATH] = {0};
    uint8_t bip32PathLength = 0;
    cx_ecfp_private_key_t privateKey = {0};
    // Verify the correctness of instruction parameters (P1, P2)
    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        THROW(HW_INCORRECT_P1_P2);
    }
    if ((p2 != P2_CHAINCODE) && (p2 != P2_NO_CHAINCODE)) {
        THROW(HW_INCORRECT_P1_P2);
    }

    // Extract the BIP32 path from the data buffer
    parseBip32Path(&dataBuffer, &dataLength, &bip32PathLength, bip32Path);

    // Determine whether to include chaincode in the derived private key
    tmpCtx.publicKeyContext.getChaincode = (p2 == P2_CHAINCODE);

    // Derive private key using the provided BIP32 path
    crypto_derive_private_key(&privateKey,
                              (tmpCtx.publicKeyContext.getChaincode ? tmpCtx.publicKeyContext.chainCode : NULL),
                               bip32Path,
                               bip32PathLength);

    // Initialize public key based on the derived private key
    crypto_init_public_key(&privateKey,
                           &tmpCtx.publicKeyContext.publicKey,
                           rawPublicKey);

    // reset private key
    explicit_bzero(&privateKey, sizeof(privateKey));

    // Construct VeChain address from the derived public key
    getVetAddressStringFromKey(&tmpCtx.publicKeyContext.publicKey,
                               tmpCtx.publicKeyContext.address);

    // Handle different modes of operation (confirm/non-confirm)
    if (p1 == P1_NON_CONFIRM) {
        *tx = set_result_get_publicKey();
        THROW(HW_OK);
    } 
    else 
    {
        // prepare for a UI based reply
        skipDataWarning = false;
        skipClausesWarning = false;

        // Format the address for display
        snprintf((char *)fullAddress, sizeof(fullAddress), "0x%.*s", 40,
            tmpCtx.publicKeyContext.address);

#ifdef HAVE_BAGL

        // Push a new UX stack if none exists
        if(G_ux.stack_count == 0) {
        ux_stack_push();
        }

        // Initialize the UX flow for displaying the public key
        ux_flow_init(0, ux_display_public_flow, NULL);
#else

        // Display the public key using the UI
        ui_display_public_key_flow();
#endif

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
void handleSign(uint8_t p1, uint8_t p2, uint8_t workBuffer[static 255],
                uint16_t dataLength, volatile unsigned int flags[static 1],
                volatile unsigned int tx[static 1])
{
    UNUSED(tx);
    parserStatus_e txResult;
    //uint256_t gasPriceCoef, gas, baseGasPrice, maxGasCoef, uint256a, uint256b;
    uint32_t i;
    //uint8_t address[41];
    uint8_t decimals = DECIMALS_VET;
    uint8_t *ticker = (uint8_t *)TICKER_VET;

    if (p1 == P1_FIRST) {
        memset(&clausesContent, 0, sizeof(clausesContent));
        memset(&clauseContent, 0, sizeof(clauseContent));
        
        // Extract and parse the BIP32 path
        parseBip32Path(&workBuffer, &dataLength, &tmpCtx.transactionContext.pathLength, tmpCtx.transactionContext.bip32Path);
        dataPresent = false;
        initTx(&displayContext.txFullContext.txContext, &tmpContent.txContent,
               &displayContext.txFullContext.clausesContext, &clausesContent,
               &displayContext.txFullContext.clauseContext, &clauseContent,
               &blake2b, NULL);
    } else if (p1 != P1_MORE) {
        THROW(HW_INCORRECT_P1_P2);
    }
    if (p2 != 0) {
        THROW(HW_INCORRECT_P1_P2);
    }
    if (displayContext.txFullContext.txContext.currentField == TX_RLP_NONE) {
        PRINTF("Parser not initialized\n");
        THROW(HW_SW_TRANSACTION_CANCELLED);
    }
    if (displayContext.txFullContext.clausesContext.currentField == CLAUSES_RLP_NONE) {
        PRINTF("Parser not initialized\n");
        THROW(HW_SW_TRANSACTION_CANCELLED);
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
        THROW(HW_OK);
    case USTREAM_FAULT:
        THROW(HW_INCORRECT_DATA);
    default:
        PRINTF("Unexpected parser status\n");
        THROW(HW_INCORRECT_DATA);
    }

    // Store the hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *)&blake2b, CX_LAST, NULL, 0, tmpCtx.transactionContext.hash, 32));

    PRINTF("messageHash:\n%.*H\n", 32, tmpCtx.transactionContext.hash);
    // Check for data presence
    dataPresent = clausesContent.dataPresent;
    if (dataPresent && !N_storage.dataAllowed) {
        PRINTF("Data field forbidden\n");
        THROW(HW_INCORRECT_DATA);
    }

    // Check for multiple clauses
    multipleClauses = (clausesContent.clausesLength > 1);
    if (multipleClauses && !N_storage.multiClauseAllowed) {
        PRINTF("Multiple clauses forbidden\n");
        THROW(HW_INCORRECT_DATA);
    }

    // If there is a token to process, check if it is well known
    if (dataPresent && memcmp(clauseContent.data, TOKEN_TRANSFER_ID, 4) == 0) {
        for (i = 0; i < NUM_TOKENS; i++) {
            tokenDefinition_t *currentToken = PIC(&TOKENS[i]);
            if (memcmp(currentToken->address,
                          clauseContent.to, 20) == 0) {
                dataPresent = false;
                decimals = currentToken->decimals;
                ticker = currentToken->ticker;
                clauseContent.toLength = 20;
                memmove(clauseContent.to,
                           clauseContent.data + 4 + 12, 20);
                memmove(clauseContent.value.value,
                           clauseContent.data + 4 + 32, 32);
                clauseContent.value.length = 32;
                break;
            }
        }
    }

    // Add address
    addressToDisplayString(clauseContent.to, (uint8_t *)fullAddress);

    // Add amount in ethers or tokens
    sendAmountToDisplayString(
        &clauseContent.value,
        ticker,
        decimals,
        (uint8_t *)fullAmount);

    // Compute maximum fee
    maxFeeToDisplayString(
        &tmpContent.txContent.gaspricecoef,
        &tmpContent.txContent.gas,
        &displayContext.feeComputationContext,
        (uint8_t *)maxFee);

#ifdef HAVE_BAGL
    if(G_ux.stack_count == 0) {
    ux_stack_push();
    }
    if(dataPresent && multipleClauses){
        ux_flow_init(0, ux_confirm_full_data_clauses_flow, NULL);
    }
    else if(dataPresent && !multipleClauses){
        ux_flow_init(0, ux_confirm_full_data_flow, NULL);
    }
    else if(!dataPresent && multipleClauses){
        ux_flow_init(0, ux_confirm_full_clauses_flow, NULL);
    }
    else{
        ux_flow_init(0, ux_confirm_full_flow, NULL);
    }
#else
    ui_display_action_sign_tx_flow();
#endif

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
 * @note Settings values:
 * - 0: Both data and multiple clauses disabled.
 * - 1: Data enabled, multiple clauses disabled.
 * - 2: Data disabled, multiple clauses enabled.
 * - 3: Both data and multiple clauses enabled.
 *
 * @param[in] p1 Instruction parameter 1 (P1), currently unused.
 * @param[in] p2 Instruction parameter 2 (P2), currently unused.
 * @param[in] workBuffer Pointer to the data buffer (currently unused).
 * @param[in] dataLength Length of the data buffer (currently unused).
 * @param[in,out] flags Pointer to flags for APDU processing (currently unused).
 * @param[in,out] tx Pointer to the outgoing APDU buffer size.
 */
void handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t workBuffer[static 255],
                               uint16_t dataLength,
                               volatile unsigned int flags[static 1],
                               volatile unsigned int tx[static 1]) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);
    UNUSED(flags);

    // Retrieve configuration settings
    G_io_apdu_buffer[0] = (
        (N_storage.dataAllowed ? CONFIG_DATA_ENABLED : 0x00) |
        (N_storage.multiClauseAllowed ? CONFIG_MULTICLAUSE_ENABLED<<1 : 0x00)
    );

    // Retrieve version information
    G_io_apdu_buffer[1] = MAJOR_VERSION;
    G_io_apdu_buffer[2] = MINOR_VERSION;
    G_io_apdu_buffer[3] = PATCH_VERSION;

    // Set transaction buffer size
    *tx = 4;
    THROW(HW_OK);
}

/**
 * @brief Handles the signing of a certificate.
 *
 * @details This function handles the signing of a certificate, supporting both
 * the first part of the certificate and subsequent parts. It follows these steps:
 * - Parses the input parameters to determine the action to be taken.
 * - Initializes the certificate signing context and computes the certificate header.
 * - Updates the certificate hash with the certificate data for subsequent parts.
 * - Finalizes the certificate hash and generates the certificate signature when the entire certificate is processed.
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
void handleSignCertificate(uint8_t p1, uint8_t p2, uint8_t workBuffer[static 255],
                           uint16_t dataLength,
                           volatile unsigned int flags[static 1],
                           volatile unsigned int tx[static 1])
{
    UNUSED(tx);

    // Process the first part of the certificate signing operation
    if (p1 == P1_FIRST) {

        // Extract and parse the BIP32 path
        parseBip32Path(&workBuffer, &dataLength, &tmpCtx.transactionContext.pathLength, tmpCtx.transactionContext.bip32Path);

        // Extract and parse the remaining length
        tmpCtx.messageSigningContext.remainingLength =
            (workBuffer[0] << 24) | (workBuffer[1] << 16) |
            (workBuffer[2] << 8) | (workBuffer[3]);
        workBuffer += 4;
        dataLength -= 4;

        // Check if the certificate starts with '{' (indicating JSON format)
        if (workBuffer[0] != '{') {
            PRINTF("Invalid json\n");
            THROW(HW_INCORRECT_DATA);
        }

        // Initialize Blake2b hash function with a 256-bit output size
        CX_ASSERT(cx_blake2b_init_no_throw(&blake2b, 256));
    } else if (p1 != P1_MORE) {
        THROW(HW_INCORRECT_P1_P2);
    }
    if (p2 != 0) {
        THROW(HW_INCORRECT_P1_P2);
    }
    if (dataLength > tmpCtx.messageSigningContext.remainingLength) {
        THROW(HW_NOT_ENOUGH_MEMORY_SPACE);
    }

    // Update message hash with certificate data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *)&blake2b, 0, workBuffer, dataLength, NULL, 0));
    tmpCtx.messageSigningContext.remainingLength -= dataLength;

    // Check if all certificate data has been processed
    if (tmpCtx.messageSigningContext.remainingLength == 0) {
        // Check if the certificate ends with '}' (indicating JSON format)
        if (workBuffer[dataLength-1] != '}') {
            PRINTF("Invalid json\n");
            THROW(HW_INCORRECT_DATA);
        }

        // Finalize message hash
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *)&blake2b, CX_LAST, NULL, 0, tmpCtx.messageSigningContext.hash, 32));

        // Convert the message hash to hexadecimal string
#define HASH_LENGTH 4
        array_hexstr((char *)fullAddress, tmpCtx.messageSigningContext.hash, HASH_LENGTH / 2);
        // Add separator characters
        fullAddress[HASH_LENGTH / 2 * 2] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 1] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 2] = '.';
        // Convert the second half of the message hash to hexadecimal string
        array_hexstr((char *)fullAddress + HASH_LENGTH / 2 * 2 + 3,
                     tmpCtx.messageSigningContext.hash + 32 - HASH_LENGTH / 2, HASH_LENGTH / 2);

#ifdef HAVE_BAGL
        // If BAGL is supported, push a new screen stack and initialize UI flow
        if(G_ux.stack_count == 0) {
            ux_stack_push();
        }
        ux_flow_init(0, ux_sign_cert_flow, NULL);
#else
        // Display the action for signing a certificate
        ui_display_action_sign_msg_cert(CERTIFICATE_TRANSACTION);
#endif

        // Set flag for asynchronous reply
        *flags |= IO_ASYNCH_REPLY;
    } else {
        THROW(HW_OK);
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
 * - Finalizes the message hash and generates the message signature when the entire message is processed.
 * - Prepares the display or UI for confirming the message signing action.
 *
 * @param[in] p1 Instruction parameter 1 (P1), indicating the type of message signing action.
 * @param[in] p2 Instruction parameter 2 (P2), currently unused.
 * @param[in] workBuffer Pointer to the data buffer containing the message data.
 * @param[in] dataLength Length of the message data.
 * @param[in,out] flags Pointer to flags for APDU processing.
 * @param[in,out] tx Pointer to the outgoing APDU buffer size (currently unused).
 */
void handleSignPersonalMessage(uint8_t p1, uint8_t p2, uint8_t workBuffer[static 255],
                               uint16_t dataLength,
                               volatile unsigned int flags[static 1],
                               volatile unsigned int tx[static 1])
{
    UNUSED(tx);

    if (p1 == P1_FIRST) {
        // First part of the message
        char tmp[11];
        uint32_t index;
        uint32_t base = 10;
        uint8_t pos = 0;

        // Extract and parse the BIP32 path
        parseBip32Path(&workBuffer, &dataLength, &tmpCtx.transactionContext.pathLength, tmpCtx.transactionContext.bip32Path);

        // Parse remaining message length
        tmpCtx.messageSigningContext.remainingLength =
            (workBuffer[0] << 24) | (workBuffer[1] << 16) |
            (workBuffer[2] << 8) | (workBuffer[3]);
        workBuffer += 4;
        dataLength -= 4;
        // Initialize message header + length
        CX_ASSERT(cx_blake2b_init_no_throw(&blake2b, 256));
        // Hash the signature magic constant
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *)&blake2b, 0, (uint8_t *)SIGN_MAGIC, sizeof(SIGN_MAGIC) - 1, NULL, 0));

        // Calculate the index for message header + length
        for (index = 1; (((index * base) <=
                          tmpCtx.messageSigningContext.remainingLength) &&
                         (((index * base) / base) == index));
             index *= base)
            ;

        // Generate the message header + length as a string
        for (; index; index /= base) {
            tmp[pos++] =
                '0' +
                ((tmpCtx.messageSigningContext.remainingLength / index) % base);
        }
        tmp[pos] = '\0';

        // Hash the message header + length
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *)&blake2b, 0, (uint8_t *)tmp, pos, NULL, 0));
    } else if (p1 != P1_MORE) {
        THROW(HW_INCORRECT_P1_P2);
    }
    if (p2 != 0) {
        THROW(HW_INCORRECT_P1_P2);
    }
    if (dataLength > tmpCtx.messageSigningContext.remainingLength) {
        THROW(HW_NOT_ENOUGH_MEMORY_SPACE);
    }

    // Update message hash with message data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *)&blake2b, 0, workBuffer, dataLength, NULL, 0));
    // Decrease the remaining length by the processed data length
    tmpCtx.messageSigningContext.remainingLength -= dataLength;

    // Check if all message data has been processed
    if (tmpCtx.messageSigningContext.remainingLength == 0) {
        // Finalize message hash
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *)&blake2b, CX_LAST, NULL, 0, tmpCtx.messageSigningContext.hash, 32));

        // Convert the message hash to hexadecimal string
#define HASH_LENGTH 4
        array_hexstr((char *)fullAddress, tmpCtx.messageSigningContext.hash, HASH_LENGTH / 2);
        // Add separator characters
        fullAddress[HASH_LENGTH / 2 * 2] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 1] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 2] = '.';

        // Convert the second half of the message hash to hexadecimal string
        array_hexstr((char *)fullAddress + HASH_LENGTH / 2 * 2 + 3,
                     tmpCtx.messageSigningContext.hash + 32 - HASH_LENGTH / 2, HASH_LENGTH / 2);

#ifdef HAVE_BAGL
    // If BAGL is supported, push a new screen stack and initialize UI flow
    if(G_ux.stack_count == 0) {
    ux_stack_push();
    }
    ux_flow_init(0, ux_sign_msg_flow, NULL);
#else
        // Display the action for signing a message
        ui_display_action_sign_msg_cert(MSG_TRANSACTION);
#endif

        // Set flag for asynchronous reply
        *flags |= IO_ASYNCH_REPLY;

    } else {
        // More data remains to be processed, return OK status
        THROW(HW_OK);
    }
}

/**
 * @brief Handles incoming APDU commands and delegates them to instruction handler based on (INS).
 *
 * @details This function processes incoming APDU commands and delegates them to specific handlers based on the
 * instruction (INS) field of the APDU. It follows these steps:
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
void handleApdu(volatile unsigned int flags[static 1], volatile unsigned int tx[static 1])
{
    unsigned short sw = 0;

    BEGIN_TRY {
        TRY {
            // Check if the class of the APDU command is supported.
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(HW_CLA_NOT_SUPPORTED);
            }

            PRINTF("New APDU received:\n%.*H\n", G_io_apdu_buffer[OFFSET_LC] + OFFSET_LC, G_io_apdu_buffer);

            // Handle different APDU instructions based on their INS (Instruction) field.
            switch (G_io_apdu_buffer[OFFSET_INS]) {
            case INS_GET_PUBLIC_KEY:
                handleGetPublicKey(G_io_apdu_buffer[OFFSET_P1],
                                   G_io_apdu_buffer[OFFSET_P2],
                                   G_io_apdu_buffer + OFFSET_CDATA,
                                   G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            case INS_SIGN:
                handleSign(G_io_apdu_buffer[OFFSET_P1],
                           G_io_apdu_buffer[OFFSET_P2],
                           G_io_apdu_buffer + OFFSET_CDATA,
                           G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            case INS_GET_APP_CONFIGURATION:
                handleGetAppConfiguration(
                    G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
                    G_io_apdu_buffer + OFFSET_CDATA,
                    G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            case INS_SIGN_PERSONAL_MESSAGE:
                handleSignPersonalMessage(
                    G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
                    G_io_apdu_buffer + OFFSET_CDATA,
                    G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            case INS_SIGN_CERTIFICATE:
                handleSignCertificate(
                    G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
                    G_io_apdu_buffer + OFFSET_CDATA,
                    G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            default:
                THROW(HW_INS_NOT_SUPPORTED);
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
            case HW_OK:
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

/**
 * @brief Main function for processing incoming APDU commands and dispatching them to handlers.
 *
 * @note the bootloader ignores the way APDU are fetched. Its only goal is to retrieve APDU.
 * When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make sure the io_event
 * is called with a switch event, before the apdu is replied to the bootloader.
 * This avoid APDU injection faults.
 *
 * @details
 * The function operates in the following steps:
 * - Waits for an APDU command.
 * - Processes the received APDU command.
 * - Handles exceptions such as IO reset, hardware errors, or other errors.
 *
 * @return void
 */
void sample_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(HW_SECURITY_STATUS_NOT_SATISFIED);
                }

                handleApdu(&flags, &tx);
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
                case HW_OK:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = e;
                    //sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    // return_to_dashboard:
    return;
}

#ifdef HAVE_BAGL
// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default(element);
}
#endif  // HAVE_BAGL

/**
 * @brief Handles incoming events from the SEPROXYHAL (Secure Proxy Hardware Abstraction Layer).
 *
 * @details This function is responsible for handling incoming events from the SEPROXYHAL. It processes various types of events, including button push events, status events, ticker events, and display events. It follows these steps:
 * - Ignores the event channel as nothing is done with it.
 * - Processes the event based on its type:
 *   - If the event is a finger event (if supported), triggers UX_FINGER_EVENT.
 *   - If the event is a button push event, triggers UX_BUTTON_PUSH_EVENT.
 *   - If the event is a status event:
 *     - Checks if the USB power status is not set and throws an IO reset exception if USB is not powered.
 *     - Triggers UX_DEFAULT_EVENT for other status events.
 *   - If the event is a display processed event, triggers UX_DISPLAYED_EVENT (if supported).
 *   - If the event is a ticker event, triggers UX_TICKER_EVENT.
 * - Closes the event if not done previously by sending the general status.
 *
 * @param[in] channel The event channel.
 *
 * @return Returns 1 to indicate that the command has been processed and the current APDU transport should not be reset.
 */
unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed
    UNUSED(channel);

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
#ifdef HAVE_NBGL
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;
#endif

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
#ifdef HAVE_BAGL
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif
        break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
        if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
            !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
              SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
            THROW(EXCEPTION_IO_RESET);
        }
        // no break is intentional
        __attribute__((fallthrough));
    default:
        UX_DEFAULT_EVENT();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
        UX_DISPLAYED_EVENT({});
#endif  // HAVE_BAGL
#ifdef HAVE_NBGL
        UX_DEFAULT_EVENT();
#endif  // HAVE_NBGL
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            if (UX_ALLOWED) {
                if (skipDataWarning && (ux_step == 0)) {
                    ux_step++;
                }
                if (skipClausesWarning && (ux_step == 1)) {
                    ux_step++;
                }

                if (ux_step_count) {
                    // prepare next screen
                    ux_step = (ux_step + 1) % ux_step_count;
                    // redisplay screen
                    UX_REDISPLAY();
                }
            }
        });
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

/**
 * @brief Exits the application, terminating its execution.
 *
 * @details This function exits the application, terminating its execution. It follows these steps:
 * - Calls os_sched_exit to terminate the application with a specified exit code (-1).
 */
void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

/**
 * @brief Entry point of the application, responsible for initializing the context, handling exceptions, and starting the event loop.
 *
 * @details This function follows these steps:
 * - Initializes the display context.
 * - Ensures proper exception handling by calling os_boot().
 * - Initializes the SEPROXYHAL IO layer.
 * - Initializes the storage if uninitialized with default settings.
 * - Resets USB state by powering it off and on.
 * - Displays the idle user interface.
 * - Resets BLE state (if supported) by powering it off and on.
 * - Executes the main functionality of the application in a continuous loop.
 * - Handles exceptions such as IO reset.
 * - Cleans up resources and exits the application.
 *
 * @return Returns 0 upon successful execution.
 */
__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    // Initialize the display context.
    memset(&displayContext, 0, sizeof(displayContext));

    // ensure exception will work as planned
    os_boot();

    // Main program loop, runs indefinitely.
    for (;;) {
        UX_INIT();

        BEGIN_TRY {
            TRY {
                // Initialize the SEPROXYHAL IO layer.
                io_seproxyhal_init();

                // If the storage is uninitialized, initialize it with default settings.
                if (N_storage.initialized != 0x01) {
                    internalStorage_t storage;
                    storage.dataAllowed = CONFIG_DATA_ENABLED;
                    storage.multiClauseAllowed = CONFIG_MULTICLAUSE_ENABLED;
                    storage.initialized = 0x01;
                    nvm_write((void *)&N_storage, &storage, sizeof(internalStorage_t));
                }


#ifdef HAVE_BLE
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // HAVE_BLE

                // Power OFF and ON USB to reset its state.
                USB_power(0);
                USB_power(1);

                // Display the idle user interface.
                ui_idle();


#ifdef HAVE_BLE
                // If BLE is supported, power OFF and ON BLE to reset its state.
                BLE_power(0, NULL);
                BLE_power(1, NULL);
#endif // HAVE_BLE

                // Execute the main functionality of the application.
                sample_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX before continuing
                continue;
            }
            CATCH_ALL {
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    // Clean up resources and exit the application.
    app_exit();

    return 0;
}
