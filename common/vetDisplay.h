#include "os.h"
#include "ustream.h"
#include "uint256.h"

#define DECIMALS_VET 18

uint32_t getStringLength(uint8_t *string);
void convertUint256BE(uint8_t *data, uint32_t length, uint256_t *target);
void addressToDisplayString(uint8_t *address, cx_sha3_t *sha3Context, uint8_t *displayString);
void sendAmountToDisplayString(txInt256_t *sendAmount, uint8_t *ticker, uint8_t decimals, uint8_t *displayString);
void maxFeeToDisplayString(txInt256_t *gasprice, txInt256_t *startgas, uint8_t *displayString);
void amountToDisplayString(uint256_t *amount256, uint8_t *ticker, uint8_t decimals, uint8_t *displayString);