
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

//  -----------------------------------------------------------
//  --------------------- SETTINGS MENU -----------------------
//  -----------------------------------------------------------
#define SETTING_INFO_NB 2
static const char *const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer"};
static const char *const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, "Vechain foundation"};

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

static nbgl_contentSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

static uint8_t initSettingPage;
static void review_warning_choice(bool confirm);
static void controls_callback(int token, uint8_t index, int page);
// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB,
     .content.switchesList.switches = switches,
     .contentActionCallback = controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};
static void controls_callback(int token, uint8_t index, int page)
{
    UNUSED(index);

    initSettingPage = page;

    uint8_t switch_value;
    if (token == CONTRACT_DATA_SWITCH_TOKEN)
    {
        // Contract data switch touched
        switch_value = !N_storage.dataAllowed;
        switches[CONTRACT_DATA_SWITCH_ID].initState = (nbgl_state_t)switch_value;
        // store the new setting value in NVM
        nvm_write((void *)&N_storage.dataAllowed, &switch_value, 1);
    }
    else if (token == MULTI_CLAUSE_SWITCH_TOKEN)
    {
        // Contract data switch touched
        switch_value = !N_storage.multiClauseAllowed;
        switches[MULTI_CLAUSE_SWITCH_ID].initState = (nbgl_state_t)switch_value;
        // store the new setting value in NVM
        nvm_write((void *)&N_storage.multiClauseAllowed, &switch_value, 1);
    }
}

// home page defintion
void ui_menu_main(void)
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
    nbgl_useCaseHomeAndSettings(APPNAME,
                                &C_stax_app_vechain_64px,
                                NULL,
                                INIT_HOME_PAGE,   // init page
                                &settingContents, // description of settings
                                &infoList,        // description of app info
                                NULL,             // no action button on home screen
                                app_quit);        // whe
}

//  ----------------------------------------------------------- 
//  --------------------- PUBLIC KEY FLOW ---------------------
//  ----------------------------------------------------------- 

static void ui_display_public_key_done(bool confirm) {
    if (confirm) {
        io_seproxyhal_touch_address_ok();
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        io_seproxyhal_touch_cancel();
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

void ui_display_public_key_flow() {
    nbgl_useCaseAddressReview((const char *)fullAddress,
                              NULL,
                              &C_stax_app_vechain_64px,
                              "Verify VeChain address",
                              NULL,
                              ui_display_public_key_done);
}
//  ----------------------------------------------------------- 
//  ---------------- SIGN FLOW COMMON -------------------------
//  ----------------------------------------------------------- 
static void ui_display_action_sign_done(bool validated) 
{
    if(validated) 
    {
        nbgl_useCaseStatus("Transaction\nsigned", true, ui_idle);
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
    info_long_press.text = "Sign transaction?"; //\nto send VET/VTHO
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
                            "Review transaction", //\nto send VET/VTHO
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
