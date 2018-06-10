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

typedef enum rlpClauseField_e {
    CLAUSE_RLP_NONE = 0,
    CLAUSE_RLP_CONTENT,
    CLAUSE_RLP_TO,
    CLAUSE_RLP_VALUE,
    CLAUSE_RLP_DATA,
    CLAUSE_RLP_DONE
} rlpClauseField_e;

typedef struct clauseContent_t {
    uint8_t to[20];
    uint8_t toLength;
    txInt256_t value;
    uint8_t data[4 + 32 + 32];
    bool dataPresent;
} clauseContent_t;

typedef struct clauseContext_t {
    rlpClauseField_e currentField;
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
    clauseContent_t *content;
} clauseContext_t;

void initClause(clauseContext_t *context, clauseContent_t *content);
parserStatus_e processClause(clauseContext_t *context, uint8_t *buffer, uint32_t length);
void copyClauseData(clauseContext_t *context, uint8_t *out, uint32_t length);
uint8_t readClauseByte(clauseContext_t *context);