#ifdef HAVE_NBGL

#pragma once

/* type to define if the transaction to sign is a personnal message
or a certificate */
typedef enum transactionType_e 
{
    MSG_TRANSACTION,
    CERTIFICATE_TRANSACTION
} transactionType_t;

/**
 * Show main menu (ready screen, version, about, quit).
 */
void ui_menu_main(void);

/**
 * Show about submenu (copyright, date).
 */
void ui_menu_settings(void);

/**
 * Show public key flow.
 */
void ui_display_public_key_flow(void);

/**
 * Show action sign flow.
 */
void ui_display_action_sign_flow(void);

/**
 * Show message or certicate sign flow depending on "p_transaction_type" value.
 */
void ui_display_action_sign_msg_certif(transactionType_t p_transaction_type);

#endif
