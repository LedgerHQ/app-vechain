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
#include "io.h"
#include "os_io_seproxyhal.h"
#include "main.h"
#include "handlers.h"
#include "crypto.h"

/**
 * @brief Appends the given status word (SW) to the APDU buffer.
 *
 * @param[in,out] tx Pointer to the apdu buffer size.
 * @param[in] sw The status word (SW) to be appended.
 */
static void apdu_buffer_append_state(uint32_t tx[static 1], unsigned short sw) {
    G_io_apdu_buffer[(*tx)++] = sw >> 8;
    G_io_apdu_buffer[(*tx)++] = sw;
}

/**
 * @brief Exits the touch operation and returns to the dashboard.
 *
 * @details This function exits the touch operation and returns to the dashboard by invoking the
 * operating system scheduler exit function. It follows these steps:
 * - Calls the operating system scheduler exit function to return to the dashboard.
 * - Returns 0 indicating that the widget should not be redrawn.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_exit() {
    // Go back to the dashboard
    os_sched_exit(0);
    return 0;  // do not redraw the widget
}

/**
 * @brief Handles the cancellation of a touch operation.
 *
 * @details This function cancels a touch operation by sending back a response with a cancellation
 * status code. It follows these steps:
 * - Sets the APDU buffer with a cancellation status code.
 * - Sends back the response and does not restart the event loop.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_cancel() {
    uint32_t tx = 0;
    apdu_buffer_append_state(&tx, SWO_CONDITIONS_NOT_SATISFIED);
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    return 0;  // do not redraw the widget
}

/**
 * @brief Handles the confirmation of an address.
 *
 * @details This function confirms an address by retrieving the public key and associated data,
 * and sends back the response containing the public key, address, and success status code.
 * It follows these steps:
 * - Calls the set_result_get_publicKey function to set the result containing the public key,
 * address, and chain code.
 * - Adds success status codes to the APDU buffer.
 * - Sends back the response and does not restart the event loop.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_address_ok() {
    uint32_t tx = set_result_get_publicKey();

    // Add success status code
    apdu_buffer_append_state(&tx, SWO_SUCCESS);

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    return 0;  // do not redraw the widget
}

/**
 * @brief Handles the confirmation of a transaction.
 *
 * @details This function confirms a transaction by signing the message with the provided
 * parameters, and sends back the response containing the signature and transaction status. It
 * follows these steps:
 * - Initializes variables for signature components and transaction status.
 * - Performs a heartbeat to ensure proper device operation.
 * - Calls the crypto_sign_message function to sign the message.
 * - Moves the signature components and transaction status to the APDU buffer.
 * - Sends back the response and does not restart the event loop.
 *
 * @return 0 indicating that the widget should not be redrawn.
 */
unsigned int io_seproxyhal_touch_tx_ok() {
    uint32_t tx = 0;
    uint8_t sig_r[SECP256K1_RS_LEN];
    uint8_t sig_s[SECP256K1_RS_LEN];
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
    memmove(G_io_apdu_buffer, sig_r, SECP256K1_RS_LEN);
    memmove(G_io_apdu_buffer + SECP256K1_RS_LEN, sig_s, SECP256K1_RS_LEN);
    tx = 2 * SECP256K1_RS_LEN;
    G_io_apdu_buffer[tx++] = v & 0x01;

    // Clear the signature components from memory after use.
    memset(sig_r, 0, SECP256K1_RS_LEN);
    memset(sig_s, 0, SECP256K1_RS_LEN);
    v = 0;

    // Add success status code
    apdu_buffer_append_state(&tx, SWO_SUCCESS);
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    return 0;  // do not redraw the widget
}

unsigned int io_seproxyhal_touch_eip712_ok() {
    uint32_t tx = 0;
    uint8_t sig_r[SECP256K1_RS_LEN];
    uint8_t sig_s[SECP256K1_RS_LEN];
    uint8_t v = 0;
    int error;

    io_seproxyhal_io_heartbeat();
    error = crypto_sign_hash(tmpCtx.transactionContext.hash, sig_r, sig_s, &v);
    io_seproxyhal_io_heartbeat();

    if (error != 0) {
        THROW(error);
    }

    memmove(G_io_apdu_buffer, sig_r, SECP256K1_RS_LEN);
    memmove(G_io_apdu_buffer + SECP256K1_RS_LEN, sig_s, SECP256K1_RS_LEN);
    tx = 2 * SECP256K1_RS_LEN;
    G_io_apdu_buffer[tx++] = v & 0x01;

    explicit_bzero(sig_r, SECP256K1_RS_LEN);
    explicit_bzero(sig_s, SECP256K1_RS_LEN);
    v = 0;

    apdu_buffer_append_state(&tx, SWO_SUCCESS);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    return 0;
}
