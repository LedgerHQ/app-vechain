/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
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
#include <stdbool.h>
#include <blake2b.h>
#include "ustream.h"
#include "vetClausesUstream.h"

struct txContext_t;

typedef bool (*ustreamProcess_t)(struct txContext_t *context);

typedef enum rlpTxField_e {
    TX_RLP_NONE = 0,
    TX_RLP_CONTENT,
    TX_RLP_CHAINTAG,
    TX_RLP_BLOCKREF,
    TX_RLP_EXPIRATION,
    TX_RLP_CLAUSES,
    TX_RLP_GASPRICECOEF,
    TX_RLP_GAS,
    TX_RLP_DEPENDSON,
    TX_RLP_NONCE,
    TX_RLP_RESERVED,
    TX_RLP_DONE
} rlpTxField_e;

typedef struct txContent_t {
    txInt256_t gaspricecoef;
    txInt256_t gas;
    clausesContent_t *clauses;
} txContent_t;

typedef struct txContext_t {
    rlpTxField_e currentField;
    blake2b_ctx *blake2b;
    uint32_t currentFieldLength;
    uint32_t currentFieldPos;
    bool currentFieldIsList;
    bool processingField;
    bool fieldSingleByte;
    uint32_t dataLength;
    uint8_t rlpBuffer[5];
    uint32_t rlpBufferPos;
    uint8_t *workBuffer;
    uint32_t commandLength;
    ustreamProcess_t customProcessor;
    txContent_t *content;
    void *extra;
} txContext_t;

void initTx(txContext_t *context, txContent_t *content,
            clausesContext_t *clausesContext, clausesContent_t *clausesContent,
            clauseContext_t *clauseContext, clauseContent_t *clauseContent,
            blake2b_ctx *blake2b, ustreamProcess_t customProcessor, void *extra);
parserStatus_e processTx(txContext_t *context,
                         clausesContext_t *clausesContext, 
                         clauseContext_t *clauseContext, 
                         uint8_t *buffer,
                         uint32_t length);
void copyTxData(txContext_t *context, uint8_t *out, uint32_t length);
uint8_t readTxByte(txContext_t *context);
