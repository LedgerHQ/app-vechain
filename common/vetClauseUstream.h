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

void initClause(clauseContext_t *context, clauseContent_t *content, blake2b_ctx *blake2b);
parserStatus_e processClause(clauseContext_t *context, uint8_t *buffer, uint32_t length);
void copyClauseData(clauseContext_t *context, uint8_t *out, uint32_t length);
uint8_t readClauseByte(clauseContext_t *context);