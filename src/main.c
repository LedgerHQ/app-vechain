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
#define CONFIG_MULTICLAUSE_ENABLED 0x02

#define DECIMALS_VET 18

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

uint8_t signature[100];

cx_blake2b_t blake2b;
cx_sha3_t sha3;
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

int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t *chain_code,
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    // must be 64, even if we only use 32
    uint8_t raw_private_key[64] = {0};
    int error = 0;

    error = os_derive_bip32_no_throw(CX_CURVE_256K1,
                                     bip32_path,
                                     bip32_path_len,
                                     raw_private_key,
                                     chain_code);
    if (error != 0)
    {
        explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        return error;
    }
    error = cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                              raw_private_key,
                                              32,
                                              private_key);
    if (error != 0)
    {
        explicit_bzero(&raw_private_key, sizeof(raw_private_key));
        return error;
        }

    return error;
}

cx_err_t crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                                cx_ecfp_public_key_t *public_key,
                                uint8_t raw_public_key[static 64])
{
    // generate corresponding public key
    cx_err_t error = cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, public_key, private_key, 1);
    if (error != 0)
    {
        THROW(0x6f00);
    }
    memmove(raw_public_key, public_key->W + 1, 64);
    return error;
}

int crypto_sign_message(uint8_t *sig_r, uint8_t *sig_s, uint8_t *v)
{
    cx_ecfp_private_key_t private_key = {0};
    uint32_t info = 0;
   
    // derive private key according to BIP32 path
    int error = crypto_derive_private_key(&private_key,
                                          NULL,
                                          tmpCtx.transactionContext.bip32Path,
                                          tmpCtx.transactionContext.pathLength);
                                          
    if (error != 0) {
        return error;
    }

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
    explicit_bzero(&private_key, sizeof(private_key));
    PRINTF("Signature: %.*H\n", 32, sig_r);
    PRINTF("%.*H\n", 32, sig_s);
    PRINTF("%.*H\n", 1, &info);

    if (error == 0) 
    {
        if (info & CX_ECCINFO_PARITY_ODD) {
            v[0] |= 0x01;
        }
    }
    PRINTF("%.*H\n", 1, v);

    return error;
}

/////////////////////////////////////////////////////////////////////


unsigned int io_seproxyhal_touch_exit() {
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_cancel() {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
#ifdef HAVE_BAGL
    // Display back the original UX
    ui_idle();
#endif
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_ok() {
    uint32_t tx = set_result_get_publicKey();
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

#ifdef HAVE_BAGL
    // Display back the original UX
    ui_idle();
#endif
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_tx_ok() {
    uint32_t tx = 0;
    uint8_t sig_r[32];
    uint8_t sig_s[32];
    uint8_t v = 0;
    int error;

    memset(signature, 0, sizeof(signature));
    io_seproxyhal_io_heartbeat();
    error = crypto_sign_message(sig_r, sig_s, &v);
    io_seproxyhal_io_heartbeat();

    if (error != 0)
    {
        THROW(0x6f00);
    }

    memmove(G_io_apdu_buffer, sig_r, 32);
    memmove(G_io_apdu_buffer + 32, sig_s, 32);
    tx = 64;
    G_io_apdu_buffer[tx++] = v & 0x01;
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

#ifdef HAVE_BAGL
    // Display back the original UX
    ui_idle();
#endif
    return 0; // do not redraw the widget
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

uint32_t set_result_get_publicKey() {
    uint32_t tx = 0;
    G_io_apdu_buffer[tx++] = 65;
    memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.publicKey.W, 65);
    tx += 65;
    G_io_apdu_buffer[tx++] = 40;
    memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.address, 40);
    tx += 40;
    if (tmpCtx.publicKeyContext.getChaincode) {
        memmove(G_io_apdu_buffer + tx, tmpCtx.publicKeyContext.chainCode,
                   32);
        tx += 32;
    }
    return tx;
}



void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                        uint16_t dataLength, volatile unsigned int *flags,
                        volatile unsigned int *tx) {
    UNUSED(dataLength);
    uint8_t rawPublicKey[64]; 
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint32_t i;
    uint8_t bip32PathLength = *(dataBuffer++);
    cx_ecfp_private_key_t privateKey;

    if ((bip32PathLength < 0x01) || (bip32PathLength > MAX_BIP32_PATH)) {
        PRINTF("Invalid path\n");
        THROW(0x6a80);
    }
    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        THROW(0x6B00);
    }
    if ((p2 != P2_CHAINCODE) && (p2 != P2_NO_CHAINCODE)) {
        THROW(0x6B00);
    }
    for (i = 0; i < bip32PathLength; i++) {
        bip32Path[i] = (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
                       (dataBuffer[2] << 8) | (dataBuffer[3]);
        dataBuffer += 4;
    }
    tmpCtx.publicKeyContext.getChaincode = (p2 == P2_CHAINCODE);

    crypto_derive_private_key(&privateKey,
                              (tmpCtx.publicKeyContext.getChaincode ? tmpCtx.publicKeyContext.chainCode : NULL),
                               bip32Path,
                               bip32PathLength);

    crypto_init_public_key(&privateKey,
                           &tmpCtx.publicKeyContext.publicKey,
                           rawPublicKey);

    // reset private key
    explicit_bzero(&privateKey, sizeof(privateKey));

    getVetAddressStringFromKey(&tmpCtx.publicKeyContext.publicKey,
                               tmpCtx.publicKeyContext.address, &sha3);
    if (p1 == P1_NON_CONFIRM) {
        *tx = set_result_get_publicKey();
        THROW(0x9000);
    } 
    else 
    {
        // prepare for a UI based reply
        skipDataWarning = false;
        skipClausesWarning = false;

        snprintf((char *)fullAddress, sizeof(fullAddress), "0x%.*s", 40,
            tmpCtx.publicKeyContext.address);

#ifdef HAVE_BAGL
        if(G_ux.stack_count == 0) {
        ux_stack_push();
        }
        ux_flow_init(0, ux_display_public_flow, NULL);
#else
        ui_display_public_key_flow();
#endif

        *flags |= IO_ASYNCH_REPLY;
    }
}

void handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                uint16_t dataLength, volatile unsigned int *flags,
                volatile unsigned int *tx) {
    UNUSED(tx);
    parserStatus_e txResult;
    //uint256_t gasPriceCoef, gas, baseGasPrice, maxGasCoef, uint256a, uint256b;
    uint32_t i;
    //uint8_t address[41];
    uint8_t decimals = DECIMALS_VET;
    uint8_t *ticker = (uint8_t *)TICKER_VET;
    int error = 0;

    if (p1 == P1_FIRST) {
        memset(&clausesContent, 0, sizeof(clausesContent));
        memset(&clauseContent, 0, sizeof(clauseContent));
        tmpCtx.transactionContext.pathLength = workBuffer[0];
        if ((tmpCtx.transactionContext.pathLength < 0x01) ||
            (tmpCtx.transactionContext.pathLength > MAX_BIP32_PATH)) {
            PRINTF("Invalid path\n");
            THROW(0x6a80);
        }
        workBuffer++;
        dataLength--;
        for (i = 0; i < tmpCtx.transactionContext.pathLength; i++) {
            tmpCtx.transactionContext.bip32Path[i] =
                (workBuffer[0] << 24) | (workBuffer[1] << 16) |
                (workBuffer[2] << 8) | (workBuffer[3]);
            workBuffer += 4;
            dataLength -= 4;
        }
        dataPresent = false;
        initTx(&displayContext.txFullContext.txContext, &tmpContent.txContent,
               &displayContext.txFullContext.clausesContext, &clausesContent,
               &displayContext.txFullContext.clauseContext, &clauseContent,
               &blake2b, NULL);
    } else if (p1 != P1_MORE) {
        THROW(0x6B00);
    }
    if (p2 != 0) {
        THROW(0x6B00);
    }
    if (displayContext.txFullContext.txContext.currentField == TX_RLP_NONE) {
        PRINTF("Parser not initialized\n");
        THROW(0x6985);
    }
    if (displayContext.txFullContext.clausesContext.currentField == CLAUSES_RLP_NONE) {
        PRINTF("Parser not initialized\n");
        THROW(0x6985);
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
        THROW(0x9000);
    case USTREAM_FAULT:
        THROW(0x6A80);
    default:
        PRINTF("Unexpected parser status\n");
        THROW(0x6A80);
    }

    // Store the hash
    error = cx_hash_no_throw((cx_hash_t *)&blake2b, CX_LAST, NULL, 0, tmpCtx.transactionContext.hash, 32);
    if (error != 0)
    {
        THROW(0x6f00);
    }

    PRINTF("messageHash:\n%.*H\n", 32, tmpCtx.transactionContext.hash);
    // Check for data presence
    dataPresent = clausesContent.dataPresent;
    if (dataPresent && !N_storage.dataAllowed) {
        PRINTF("Data field forbidden\n");
        THROW(0x6A80);
    }

    // Check for multiple clauses
    multipleClauses = (clausesContent.clausesLength > 1);
    if (multipleClauses && !N_storage.multiClauseAllowed) {
        PRINTF("Multiple clauses forbidden\n");
        THROW(0x6A80);
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
    addressToDisplayString(clauseContent.to, &sha3, (uint8_t *)fullAddress);

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

void handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);
    UNUSED(flags);
    G_io_apdu_buffer[0] = (
        (N_storage.dataAllowed ? CONFIG_DATA_ENABLED : 0x00) |
        (N_storage.multiClauseAllowed ? CONFIG_MULTICLAUSE_ENABLED : 0x00)
    );
    G_io_apdu_buffer[1] = MAJOR_VERSION;
    G_io_apdu_buffer[2] = MINOR_VERSION;
    G_io_apdu_buffer[3] = PATCH_VERSION;
    *tx = 4;
    THROW(0x9000);
}

void handleSignCertificate(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx) {
    UNUSED(tx);
    int error = 0;

    if (p1 == P1_FIRST) {
        uint32_t i;

        tmpCtx.messageSigningContext.pathLength = workBuffer[0];
        if ((tmpCtx.messageSigningContext.pathLength < 0x01) ||
            (tmpCtx.messageSigningContext.pathLength > MAX_BIP32_PATH)) {
            PRINTF("Invalid path\n");
            THROW(0x6a83);
        }
        workBuffer++;
        dataLength--;

        for (i = 0; i < tmpCtx.messageSigningContext.pathLength; i++) {
            tmpCtx.messageSigningContext.bip32Path[i] =
                (workBuffer[0] << 24) | (workBuffer[1] << 16) |
                (workBuffer[2] << 8) | (workBuffer[3]);
            workBuffer += 4;
            dataLength -= 4;
        }

        tmpCtx.messageSigningContext.remainingLength =
            (workBuffer[0] << 24) | (workBuffer[1] << 16) |
            (workBuffer[2] << 8) | (workBuffer[3]);
        workBuffer += 4;
        dataLength -= 4;

        if (workBuffer[0] != '{') {
            PRINTF("Invalid json\n");
            THROW(0x6A80);
        }

        error = cx_blake2b_init_no_throw(&blake2b, 256);
        if (error != 0) {
            THROW(0x6f00);
        }
    } else if (p1 != P1_MORE) {
        THROW(0x6B00);
    }
    if (p2 != 0) {
        THROW(0x6B00);
    }
    if (dataLength > tmpCtx.messageSigningContext.remainingLength) {
        THROW(0x6A84);
    }

    error = cx_hash_no_throw((cx_hash_t *)&blake2b, 0, workBuffer, dataLength, NULL, 0);
    if (error != 0)
    {
        THROW(0x6f00);
    }
    tmpCtx.messageSigningContext.remainingLength -= dataLength;

    if (tmpCtx.messageSigningContext.remainingLength == 0) {
        if (workBuffer[dataLength-1] != '}') {
            PRINTF("Invalid json\n");
            THROW(0x6A80);
        }

        error = cx_hash_no_throw((cx_hash_t *)&blake2b, CX_LAST, NULL, 0, tmpCtx.messageSigningContext.hash, 32);
        if (error != 0)
        {
            THROW(0x6f00);
        }

#define HASH_LENGTH 4
        array_hexstr((char *)fullAddress, tmpCtx.messageSigningContext.hash, HASH_LENGTH / 2);
        fullAddress[HASH_LENGTH / 2 * 2] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 1] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 2] = '.';
        array_hexstr((char *)fullAddress + HASH_LENGTH / 2 * 2 + 3,
                     tmpCtx.messageSigningContext.hash + 32 - HASH_LENGTH / 2, HASH_LENGTH / 2);

#ifdef HAVE_BAGL
        if(G_ux.stack_count == 0) {
            ux_stack_push();
        }
        ux_flow_init(0, ux_sign_cert_flow, NULL);
#else
        ui_display_action_sign_msg_cert(CERTIFICATE_TRANSACTION);
#endif

        *flags |= IO_ASYNCH_REPLY;
    } else {
        THROW(0x9000);
    }
}

void handleSignPersonalMessage(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx) {
    UNUSED(tx);
    int error = 0;

    if (p1 == P1_FIRST) {
        char tmp[11];
        uint32_t index;
        uint32_t base = 10;
        uint8_t pos = 0;
        uint32_t i;
        tmpCtx.messageSigningContext.pathLength = workBuffer[0];
        if ((tmpCtx.messageSigningContext.pathLength < 0x01) ||
            (tmpCtx.messageSigningContext.pathLength > MAX_BIP32_PATH)) {
            PRINTF("Invalid path\n");
            THROW(0x6a83);
        }
        workBuffer++;
        dataLength--;
        for (i = 0; i < tmpCtx.messageSigningContext.pathLength; i++) {
            tmpCtx.messageSigningContext.bip32Path[i] =
                (workBuffer[0] << 24) | (workBuffer[1] << 16) |
                (workBuffer[2] << 8) | (workBuffer[3]);
            workBuffer += 4;
            dataLength -= 4;
        }
        tmpCtx.messageSigningContext.remainingLength =
            (workBuffer[0] << 24) | (workBuffer[1] << 16) |
            (workBuffer[2] << 8) | (workBuffer[3]);
        workBuffer += 4;
        dataLength -= 4;
        // Initialize message header + length
        error = cx_blake2b_init_no_throw(&blake2b, 256);
        if (error != 0) {
            THROW(0x6f00);
        }
        error = cx_hash_no_throw((cx_hash_t *)&blake2b, 0, (uint8_t *)SIGN_MAGIC, sizeof(SIGN_MAGIC) - 1, NULL, 0);
        if (error != 0)
        {
            THROW(0x6f00);
        }
        for (index = 1; (((index * base) <=
                          tmpCtx.messageSigningContext.remainingLength) &&
                         (((index * base) / base) == index));
             index *= base)
            ;
        for (; index; index /= base) {
            tmp[pos++] =
                '0' +
                ((tmpCtx.messageSigningContext.remainingLength / index) % base);
        }
        tmp[pos] = '\0';
        error = cx_hash_no_throw((cx_hash_t *)&blake2b, 0, (uint8_t *)tmp, pos, NULL, 0);
        if (error != 0)
        {
            THROW(0x6f00);
        }
    } else if (p1 != P1_MORE) {
        THROW(0x6B00);
    }
    if (p2 != 0) {
        THROW(0x6B00);
    }
    if (dataLength > tmpCtx.messageSigningContext.remainingLength) {
        THROW(0x6A84);
    }
    error = cx_hash_no_throw((cx_hash_t *)&blake2b, 0, workBuffer, dataLength, NULL, 0);
    if (error != 0) {
        THROW(0x6f00);
    }
    tmpCtx.messageSigningContext.remainingLength -= dataLength;
    if (tmpCtx.messageSigningContext.remainingLength == 0) {
        error = cx_hash_no_throw((cx_hash_t *)&blake2b, CX_LAST, NULL, 0, tmpCtx.messageSigningContext.hash, 32);
        if (error != 0) {
            THROW(0x6f00);
        }
#define HASH_LENGTH 4
        array_hexstr((char *)fullAddress, tmpCtx.messageSigningContext.hash, HASH_LENGTH / 2);
        fullAddress[HASH_LENGTH / 2 * 2] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 1] = '.';
        fullAddress[HASH_LENGTH / 2 * 2 + 2] = '.';
        array_hexstr((char *)fullAddress + HASH_LENGTH / 2 * 2 + 3,
                     tmpCtx.messageSigningContext.hash + 32 - HASH_LENGTH / 2, HASH_LENGTH / 2);

#ifdef HAVE_BAGL
    if(G_ux.stack_count == 0) {
    ux_stack_push();
    }
    ux_flow_init(0, ux_sign_msg_flow, NULL);
#else
        ui_display_action_sign_msg_cert(MSG_TRANSACTION);
#endif

        *flags |= IO_ASYNCH_REPLY;

    } else {
        THROW(0x9000);
    }
}

void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx) {
    unsigned short sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(0x6E00);
            }

            PRINTF("New APDU received:\n%.*H\n", G_io_apdu_buffer[OFFSET_LC] + OFFSET_LC, G_io_apdu_buffer);

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
                THROW(0x6D00);
                break;
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
            case 0x6000:
                // Wipe the transaction context and report the exception
                sw = e;
                memset(&displayContext, 0, sizeof(displayContext));
                break;
            case 0x9000:
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
                    THROW(0x6982);
                }

                handleApdu(&flags, &tx);
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    memset(&displayContext, 0, sizeof(displayContext));
                    break;
                case 0x9000:
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

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    memset(&displayContext, 0, sizeof(displayContext));

    // ensure exception will work as planned
    os_boot();

    for (;;) {
        UX_INIT();

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

                if (N_storage.initialized != 0x01) {
                    internalStorage_t storage;
                    storage.dataAllowed = 0x01;
                    storage.multiClauseAllowed = 0x01;
                    storage.initialized = 0x01;
                    nvm_write((void *)&N_storage, &storage, sizeof(internalStorage_t));
                }


#ifdef HAVE_BLE
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // HAVE_BLE

                USB_power(0);
                USB_power(1);

                ui_idle();


#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, NULL);
#endif // HAVE_BLE

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
    app_exit();

    return 0;
}
