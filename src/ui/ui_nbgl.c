
/*****************************************************************************
 *   Ledger NBGL
 *   (c) 2023 Ledger SAS.
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
 *****************************************************************************/

#ifdef HAVE_NBGL

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"

#include "ui_nbgl.h"
#include "main.h"

void app_quit(void) 
{
    // exit app here
    os_sched_exit(-1);
}

// home page defintion
void ui_menu_main(void) 
{
    #define SETTINGS_BUTTON_ENABLED (true)
    nbgl_useCaseHome(APPNAME, &C_stax_app_vechain_64px, NULL, SETTINGS_BUTTON_ENABLED, ui_menu_settings, app_quit);
}


//  ----------------------------------------------------------- 
//  --------------------- SETTINGS MENU -----------------------
//  ----------------------------------------------------------- 
static const char* const INFO_TYPES[] = {"Version", "Developer"};
static const char* const INFO_CONTENTS[] = {APPVERSION, "Vechain foundation"};

// settings switches definitions 
enum 
{
    CONTRACT_DATA_SWITCH_TOKEN = FIRST_USER_TOKEN,
    MULTI_CLAUSE_SWITCH_TOKEN
};

enum 
{
    CONTRACT_DATA_SWITCH_ID = 0,
    MULTI_CLAUSE_SWITCH_ID, 
    SETTINGS_SWITCHES_NB
};
 
static nbgl_layoutSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};

static bool nav_callback(uint8_t page, nbgl_pageContent_t *content) {
    UNUSED(page);
    // the first settings page contains only the version and the developer name
    // of the app
    if (page == 0) 
    {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = 2;
        content->infosList.infoTypes = INFO_TYPES;
        content->infosList.infoContents = INFO_CONTENTS;
    }
    // the second settings page contains 2 settings switches
    else if (page == 1) 
    {
        switches[CONTRACT_DATA_SWITCH_ID].initState = (nbgl_state_t)N_storage.dataAllowed;
        switches[CONTRACT_DATA_SWITCH_ID].text = "Contract data";
        switches[CONTRACT_DATA_SWITCH_ID].subText = "Allow contract data\nin transactions";
        switches[CONTRACT_DATA_SWITCH_ID].token = CONTRACT_DATA_SWITCH_TOKEN;
        switches[CONTRACT_DATA_SWITCH_ID].tuneId = TUNE_TAP_CASUAL;

        switches[MULTI_CLAUSE_SWITCH_ID].initState = (nbgl_state_t)N_storage.multiClauseAllowed;
        switches[MULTI_CLAUSE_SWITCH_ID].text = "Multi-clauses";
        switches[MULTI_CLAUSE_SWITCH_ID].subText = "Allow multi-clauses\nin transactions";
        switches[MULTI_CLAUSE_SWITCH_ID].token = MULTI_CLAUSE_SWITCH_TOKEN;
        switches[MULTI_CLAUSE_SWITCH_ID].tuneId = TUNE_TAP_CASUAL;

        content->type = SWITCHES_LIST;
        content->switchesList.nbSwitches = SETTINGS_SWITCHES_NB;
        content->switchesList.switches = (nbgl_layoutSwitch_t*)switches;
    }
    else 
    {
        return false;
    }
    // valid page so return true
    return true;
}
 
static void controls_callback(int token, uint8_t index) 
{
    UNUSED(index);
    uint8_t switch_value;
    if (token == CONTRACT_DATA_SWITCH_TOKEN)
    {
        // Contract data switch touched
        switch_value = !N_storage.dataAllowed;
        // store the new setting value in NVM
        nvm_write((void *)&N_storage.dataAllowed, &switch_value, 1);
    }
    else if (token == MULTI_CLAUSE_SWITCH_TOKEN)
    {
        // Contract data switch touched
        switch_value = !N_storage.multiClauseAllowed;
        // store the new setting value in NVM
        nvm_write((void *)&N_storage.multiClauseAllowed, &switch_value, 1);
    }
}
 
// settings menu definition
void ui_menu_settings() 
{
    #define NB_SETTINGS_PAGE   (2)
    #define INIT_SETTINGS_PAGE (0)
    nbgl_useCaseSettings("Vechain settings", INIT_SETTINGS_PAGE, NB_SETTINGS_PAGE, false, ui_idle, nav_callback, controls_callback);
}


//  ----------------------------------------------------------- 
//  --------------------- PUBLIC KEY FLOW ---------------------
//  ----------------------------------------------------------- 


static void ui_display_public_key_done(bool validated) {
    if (validated) {
        nbgl_useCaseStatus("ADDRESS\nVERIFIED", true, ui_idle);
    } else {
        nbgl_useCaseStatus("Address verification\ncancelled", false, ui_idle);
    }
}

static void address_verification_cancelled(void) {
    io_seproxyhal_touch_cancel();
    // Display "cancelled" screen
    ui_display_public_key_done(false);
}

static void display_address_callback(bool confirm) {
    if (confirm) 
    {
        io_seproxyhal_touch_address_ok();
        // Display "verified" screen
        ui_display_public_key_done(true);
    } 
    else 
    {
        address_verification_cancelled();
    }
}

// called when tapping on review start page to actually display address
static void display_addr(void) {
    nbgl_useCaseAddressConfirmation((const char *)fullAddress,
                                    &display_address_callback);
}

void ui_display_public_key_flow(void) {
    nbgl_useCaseReviewStart(&C_stax_app_vechain_64px,
                            "Verify Vechain\naddress", NULL, "Cancel",
                            display_addr, address_verification_cancelled);
}

//  ----------------------------------------------------------- 
//  ---------------- SIGN FLOW COMMON -------------------------
//  ----------------------------------------------------------- 
static void ui_display_action_sign_done(bool validated) 
{
    if(validated) 
    {
        nbgl_useCaseStatus("TRANSACTION\nSIGNED", true, ui_idle);
    }
    else 
    {
        nbgl_useCaseStatus("Transaction rejected", false, ui_idle);
    }
}

static void transaction_rejected(void) {
    io_seproxyhal_touch_cancel();
    // Display "rejected" screen
    ui_display_action_sign_done(false);
}

static void reject_confirmation(void) {
    nbgl_useCaseConfirm("Reject transaction?", NULL, "Yes, Reject", "Go back to transaction", transaction_rejected);
}
//  ----------------------------------------------------------- 
//  ---------------- SIGN TRANSACTION FLOW --------------------
//  ----------------------------------------------------------- 

#define MAX_TAG_VALUE_PAIRS_DISPLAYED (3)
static nbgl_layoutTagValue_t pairs[MAX_TAG_VALUE_PAIRS_DISPLAYED];
static nbgl_layoutTagValueList_t pair_list = {0};
static nbgl_pageInfoLongPress_t info_long_press;
static const char *warning_msg;

// called when long press button on 2nd page is long-touched or when reject footer is touched
static void review_choice(bool confirm) {
    if (confirm) {
        io_seproxyhal_touch_tx_ok();
        // Display "signed" screen
        ui_display_action_sign_done(true);
    } else {
        reject_confirmation();
    }
}

static void single_action_review_continue(void) 
{
    // Setup data to display
    pairs[0].item = "Amount";
    pairs[0].value = (const char *)fullAmount;
    pairs[1].item = "Fees";
    pairs[1].value = (const char *)maxFee;
    pairs[2].item = "To";
    pairs[2].value = (const char *)fullAddress;

    // Setup list
    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = MAX_TAG_VALUE_PAIRS_DISPLAYED;
    pair_list.pairs = pairs;

    // Info long press
    info_long_press.icon = &C_stax_app_vechain_64px;
    info_long_press.text = "Sign transaction\nto send VET?";
    info_long_press.longPressText = "Hold to sign";

    nbgl_useCaseStaticReview(&pair_list, &info_long_press, "Reject transaction", review_choice);
}

static void review_warning_choice(bool confirm) {
  if (confirm) 
  {
    // user has confirmed to continue the transaction review after warning display
    single_action_review_continue();
  }
  else 
  {
    // user has cancelled the transaction after warning display
    transaction_rejected();
  }
}

static void single_action_review(void) 
{  
    // update the transaction flow if data or multiple clauses are present
    if(!dataPresent && !multipleClauses)
    {
        single_action_review_continue();
    }
    else
    {
        // prepare the warning message 
        if(dataPresent && !multipleClauses)
        {
            warning_msg = "Data is present in\nthis transaction";
        }
        else if(!dataPresent && multipleClauses)
        {
            warning_msg = "Multiple clauses are\npresent in this\ntransaction";
        }
        else
        {
            warning_msg = "Multiple clauses and\ndata are present in\nthis transaction";
        }

        // Display the warning message and ask the user to confirm 
        nbgl_useCaseChoice(&C_Warning_64px,
                            warning_msg,
                            NULL,
                            "I understand, confirm","Cancel",
                            review_warning_choice);
    }
}

void ui_display_action_sign_tx_flow(void) 
{
    nbgl_useCaseReviewStart(&C_stax_app_vechain_64px,
                            "Review transaction\nto send VET",
                            NULL,
                            "Reject transaction",
                            single_action_review,
                            reject_confirmation);
}

//  ----------------------------------------------------------- 
//  --------------- SIGN MSG/CERTIFICATE FLOW -----------------
//  ----------------------------------------------------------- 

#define MSG_CERT_MAX_TAG_VALUE_PAIRS_DISPLAYED (1)
static nbgl_layoutTagValue_t msg_cert_pairs[MSG_CERT_MAX_TAG_VALUE_PAIRS_DISPLAYED];
static nbgl_layoutTagValueList_t msg_cert_pair_list = {0};
static nbgl_pageInfoLongPress_t msg_cert_info_long_press;
static const char *transaction_type_to_display;
static transactionType_t transaction_type = MSG_TRANSACTION;

// called when long press button on 2nd page is long-touched or when reject footer is touched
static void review_msg_cert_choice(bool confirm) {
    if (confirm) 
    {
        io_seproxyhal_touch_tx_ok();
        // Display "signed" screen
        ui_display_action_sign_done(true);
    } 
    else 
    {
        reject_confirmation();
    }
}

static void single_action_msg_cert_review(void) 
{
    // Setup data to display
    msg_cert_pairs[0].value = (const char *)fullAddress;
    if(transaction_type == MSG_TRANSACTION)
    {
        msg_cert_pairs[0].item = "Message hash";
    }
    else
    {
        msg_cert_pairs[0].item = "Certificate hash";
    }

    // Setup list
    msg_cert_pair_list.nbMaxLinesForValue = 0;
    msg_cert_pair_list.nbPairs = MSG_CERT_MAX_TAG_VALUE_PAIRS_DISPLAYED;
    msg_cert_pair_list.pairs = msg_cert_pairs;

    // Info long press
    msg_cert_info_long_press.icon = &C_Review_64px;
    msg_cert_info_long_press.longPressText = "Hold to sign";
    if(transaction_type == MSG_TRANSACTION)
    {
        msg_cert_info_long_press.text = "Sign message?";
    }
    else
    {
        msg_cert_info_long_press.text = "Sign certificate?";
    }
    nbgl_useCaseStaticReview(&msg_cert_pair_list, &msg_cert_info_long_press, "Reject transaction", review_msg_cert_choice);
}

// display message or certificate sign flow depending on "p_transaction_type" value
void ui_display_action_sign_msg_cert(transactionType_t p_transaction_type)
{
    transaction_type = p_transaction_type;
    if(transaction_type == MSG_TRANSACTION)
    {
        transaction_type_to_display = "Review message";
    }
    else
    {
        transaction_type_to_display = "Review certificate";
    }

    nbgl_useCaseReviewStart(&C_Review_64px,
                            transaction_type_to_display,
                            NULL,
                            "Reject transaction",
                            single_action_msg_cert_review,
                            reject_confirmation);
}

#endif
