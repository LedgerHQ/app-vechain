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
#include "main.h"
#include "handlers.h"
#include "mem_buffer.h"

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
void app_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    io_init();

    // Initialize the dynamic allocator used by the EIP-712 typed-data parser.
    // Failure here is non-fatal: the legacy tx/message/cert flows do not need
    // the heap, and only EIP-712 (master switch OFF by default) does.
    bool eip712_heap_ready = app_mem_init();
    PRINTF("eip712_heap_ready=%d\n", (int) eip712_heap_ready);
    (void) eip712_heap_ready;

    // Initialize the display context.
    display_reset();

    // If the storage is uninitialized, initialize it with default settings.
    if (N_storage.initialized != 0x01) {
        internalStorage_t storage;
        storage.dataAllowed = 0x00;
        storage.multiClauseAllowed = 0x00;
        storage.eip712Allowed = 0x00;  // EIP-712 master switch (disabled)
        storage.blindSign712 = 0x00;   // EIP-712 v0 blind signing (disabled)
        storage.initialized = 0x01;
        nvm_write((void *) &N_storage, &storage, sizeof(internalStorage_t));
    }

    // Display the idle user interface.
    ui_idle();

    for (;;) {
        rx = tx;
        tx = 0;  // ensure no race in catch_other if io_exchange throws an error
        rx = io_exchange(CHANNEL_APDU | flags, rx);
        flags = 0;

        // no apdu received, well, reset the session, and reset the
        // bootloader configuration
        if (rx == 0) {
            THROW(SWO_SECURITY_CONDITION_NOT_SATISFIED);
        }

        handleApdu(&flags, &tx);
    }

    // return_to_dashboard:
    return;
}
