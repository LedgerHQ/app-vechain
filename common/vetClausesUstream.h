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
#include <vetClauseUstream.h>

struct clausesContext_t;

typedef bool (*ustreamProcess_t)(struct clausesContext_t *context);

typedef enum rlpTxField_e {
    TX_RLP_NONE = 0,
    TX_RLP_CONTENT,
    TX_RLP_CLAUSE,
    TX_RLP_DONE
} rlpTxField_e;

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT
} parserStatus_e;

typedef struct clausesContent_t {
    clause_t* clauses[];
    uint8_t clausesLength;
} txContent_t;

typedef struct clausesContext_t {
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
    clausesContent_t *content;
} clausesContext_t;

void initClauses(clausesContext_t *context, blake2b_ctx *blake2b, clausesContent_t *content);
parserStatus_e processClauses(clausesContext_t *context, uint8_t *buffer, uint32_t length);
void copyClausesData(clausesContext_t *context, uint8_t *out, uint32_t length);
uint8_t readClausesByte(clausesContext_t *context);
