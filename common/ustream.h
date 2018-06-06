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

#ifndef LIB_USTREAM
#define LIB_USTREAM

typedef enum rlpClauseField_e {
    CLAUSE_RLP_NONE = 0,
    CLAUSE_RLP_CONTENT,
    CLAUSE_RLP_TO,
    CLAUSE_RLP_VALUE,
    CLAUSE_RLP_DATA,
    CLAUSE_RLP_DONE
} rlpClauseField_e;

typedef enum rlpClausesField_e {
    CLAUSES_RLP_NONE = 0,
    CLAUSES_RLP_CONTENT,
    CLAUSES_RLP_CLAUSE,
    CLAUSES_RLP_DONE
} rlpClausesField_e;

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT
} parserStatus_e;

typedef struct txInt256_t {
    uint8_t value[32];
    uint8_t length;
} txInt256_t;

typedef struct clauseContent_t {
    uint8_t to[20];
    uint8_t toLength;
    txInt256_t value;
} clauseContent_t;

typedef struct clauseContext_t {
    rlpClauseField_e currentField;
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
    clauseContent_t *content;
} clauseContext_t;

typedef struct clausesContent_t {
    clauseContent_t *firstClause;
    uint8_t clausesLength;
} clausesContent_t;

typedef struct clausesContext_t {
    rlpClausesField_e currentField;
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

#endif