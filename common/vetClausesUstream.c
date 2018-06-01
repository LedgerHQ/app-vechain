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

#include "ethUstream.h"
#include "ethUtils.h"

#define MAX_INT256 32
#define MAX_INT64 8
#define MAX_INT32 4
#define MAX_INT8 1
#define MAX_ADDRESS 20
#define MAX_V 2

void initClauses(clausesContext_t *context, clausesContent_t *content, clauseContext_t *context, clauseContent_t *content, blake2b_ctx *blake2b) {
    os_memset(context, 0, sizeof(clausesContext_t));
    context->blake2b = blake2b;
    context->content = content;
    context->content->clausesLength = 0
    context->currentField = TX_RLP_CONTENT;
    initClause(clauseContext, clauseContent, blake2b);
}

uint8_t readByte(clausesContext_t *context) {
    uint8_t data;
    if (context->commandLength < 1) {
        PRINTF("readTxByte Underflow\n");
        THROW(EXCEPTION);
    }
    data = *context->workBuffer;
    context->workBuffer++;
    context->commandLength--;
    if (context->processingField) {
        context->currentFieldPos++;
    }
    if (!(context->processingField && context->fieldSingleByte)) {
        blake2b_update((blake2b_ctx *)context->blake2b, &data, 1);
    }
    return data;
}

void copyClausesData(clausesContext_t *context, clauseContent_t *clauseContext, uint32_t length) {
    if (context->commandLength < length) {
        PRINTF("copyTxData Underflow\n");
        THROW(EXCEPTION);
    }
    processClause(clauseContext, context->workBuffer, length);
    if (!(context->processingField && context->fieldSingleByte)) {
        blake2b_update((blake2b_ctx *)context->blake2b, context->workBuffer, length);
    }
    context->workBuffer += length;
    context->commandLength -= length;
    if (context->processingField) {
        context->currentFieldPos += length;
    }
}

static void processContent(clausesContext_t *context) {
    // Keep the full length for sanity checks, move to the next field
    if (!context->currentFieldIsList) {
        PRINTF("Invalid type for RLP_CONTENT\n");
        THROW(EXCEPTION);
    }
    context->dataLength = context->currentFieldLength;
    context->currentField++;
    context->processingField = false;
}

static void processClause(clausesContext_t *context, clauseContext_t *clauseContext) {
    if (!context->currentFieldIsList) {
        PRINTF("Invalid type for RLP_CLAUSES\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyClausesData(context,
                        clauseContext,
                        copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->content->clauses[context->content->clausesLength - 1] = clauseContext->content;
        context->processingField = false;
    }
}

static parserStatus_e processClausesInternal(clausesContext_t *context, clauseContext_t *clauseContext) {
    for (;;) {
        if (context->commandLength == 0) {
            return USTREAM_FINISHED;
        }
        if (!context->processingField) {
            bool canDecode = false;
            uint32_t offset;
            while (context->commandLength != 0) {
                bool valid;
                // Feed the RLP buffer until the length can be decoded
                context->rlpBuffer[context->rlpBufferPos++] =
                    readTxByte(context);
                if (rlpCanDecode(context->rlpBuffer, context->rlpBufferPos,
                                 &valid)) {
                    // Can decode now, if valid
                    if (!valid) {
                        PRINTF("RLP pre-decode error\n");
                        return USTREAM_FAULT;
                    }
                    canDecode = true;
                    break;
                }
                // Cannot decode yet
                // Sanity check
                if (context->rlpBufferPos == sizeof(context->rlpBuffer)) {
                    PRINTF("RLP pre-decode logic error\n");
                    return USTREAM_FAULT;
                }
            }
            if (!canDecode) {
                return USTREAM_PROCESSING;
            } 
            // Ready to process this field
            if (!rlpDecodeLength(context->rlpBuffer, context->rlpBufferPos,
                                 &context->currentFieldLength, &offset,
                                 &context->currentFieldIsList)) {
                PRINTF("RLP decode error\n");
                return USTREAM_FAULT;
            }
            if (offset == 0) {
                // Hack for single byte, self encoded
                context->workBuffer--;
                context->commandLength++;
                context->fieldSingleByte = true;
            } else {
                context->fieldSingleByte = false;
            }
            context->currentFieldPos = 0;
            context->rlpBufferPos = 0;
            context->processingField = true;
            if (context->content->clausesLength == 0) {
                context->content->clausesLength = 1
                context->content->clauses = malloc(sizeof(clauseContent_t))
            } else {
                context->content->clausesLength++
                context->content->clauses = realloc(context->content->clausesLength * sizeof(clauseContent_t));
                if (!context->content->clauses) {
                    THROW(EXCEPTION)  // Failed to reallocate clauses array
                }
            }
        }
        switch (context->currentField) {
        case TX_RLP_CONTENT:
            processContent(context);
            break;
        case TX_RLP_CLAUSE:
            processClause(context, clauseContext);
            break;
        default:
            PRINTF("Invalid RLP decoder context\n");
            return USTREAM_FAULT;
        }
    }
}

parserStatus_e processClauses(clausesContext_t *context,
                              clauseContext_t *clauseContext,
                              uint8_t *buffer,
                              uint32_t length) {
    parserStatus_e result;
    BEGIN_TRY {
        TRY {
            context->workBuffer = buffer;
            context->commandLength = length;
            result = processClausesInternal(context, clauseContext);
        }
        CATCH_OTHER(e) {
            result = USTREAM_FAULT;
        }
        FINALLY {
        }
    }
    END_TRY;
    return result;
}
