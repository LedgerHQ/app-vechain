#ifndef _MAIN_H_
#define _MAIN_H_

typedef struct internalStorage_t {
    uint8_t dataAllowed;
    uint8_t multiClauseAllowed;
    uint8_t initialized;
} internalStorage_t;

extern const internalStorage_t N_storage_real;
#define N_storage (*( volatile internalStorage_t *)PIC(&N_storage_real))

void ui_idle(void);

extern volatile char fullAddress[43];
extern volatile char fullAmount[50];
extern volatile char maxFee[60];
extern volatile bool dataPresent;
extern volatile bool multipleClauses;


unsigned int io_seproxyhal_touch_settings();
unsigned int io_seproxyhal_touch_exit();
unsigned int io_seproxyhal_touch_tx_ok();
unsigned int io_seproxyhal_touch_address_ok();
unsigned int io_seproxyhal_touch_cancel();

#endif
