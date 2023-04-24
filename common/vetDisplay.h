/*******************************************************************************
*   (c) 2018 Totient Labs
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

#include <string.h>
#include "os.h"
#include "ustream.h"
#include "uint256.h"

#define DECIMALS_VET 18
#define DECIMALS_VTHO 18

typedef struct feeComputationContext_t {
    // Constants
    uint256_t baseGasPrice;
    uint256_t maxGasCoef;
    // User Inputs
    uint256_t gasPriceCoef;
    uint256_t gas;
    // Intermediary
    uint256_t maxFeeBonus;
    uint256_t tmp;
    //Result
    uint256_t maxFee;
} feeComputationContext_t;

uint32_t getStringLength(uint8_t *string);
void convertUint256BE(const uint8_t *data, uint32_t length, uint256_t *target);
void addressToDisplayString(uint8_t *address, cx_sha3_t *sha3Context, uint8_t *displayString);
void sendAmountToDisplayString(txInt256_t *sendAmount, uint8_t *ticker, uint8_t decimals, uint8_t *displayString);
void maxFeeToDisplayString(txInt256_t *gaspricecoef, txInt256_t *gas, feeComputationContext_t *feeComputationContext, uint8_t *displayString);
void amountToDisplayString(uint256_t *amount256, uint8_t *ticker, uint8_t decimals, uint8_t *displayString);