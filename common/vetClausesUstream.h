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
#include "vetClauseUstream.h"

typedef enum rlpClausesField_e {
    CLAUSES_RLP_NONE = 0,
    CLAUSES_RLP_CONTENT,
    CLAUSES_RLP_CLAUSE,
    CLAUSES_RLP_DONE
} rlpClausesField_e;

typedef struct clausesContent_t {
    clauseContent_t *firstClause;
    uint8_t clausesLength;
    bool dataPresent;
} clausesContent_t;

typedef struct clausesContext_t {
    rlpClausesField_e currentField;
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

void initClauses(clausesContext_t *context, clausesContent_t *content, clauseContext_t *clauseContext, clauseContent_t *clauseContent);
parserStatus_e processClauses(clausesContext_t *context, clauseContext_t *clauseContext, uint8_t *buffer, uint32_t length);
void copyClausesData(clausesContext_t *context, clauseContext_t *clauseContext, uint32_t length);
uint8_t readClausesByte(clausesContext_t *context);