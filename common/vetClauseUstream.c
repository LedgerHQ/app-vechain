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

#include "vetClauseUstream.h"
#include "vetUtils.h"

#define MAX_INT256 32
#define MAX_INT64 8
#define MAX_INT32 4
#define MAX_INT8 1
#define MAX_ADDRESS 20
#define MAX_V 2

void initClause(clauseContext_t *context, clauseContent_t *content) {
    os_memset(context, 0, sizeof(clauseContext_t));
    context->content = content;
    context->currentField = CLAUSE_RLP_TO;
}

uint8_t readClauseByte(clauseContext_t *context) {
    uint8_t data;
    if (context->commandLength < 1) {
        PRINTF("readClauseByte Underflow\n");
        THROW(0x6a08);
    }
    data = *context->workBuffer;
    context->workBuffer++;
    context->commandLength--;
    if (context->processingField) {
        context->currentFieldPos++;
    }
    return data;
}

void copyClauseData(clauseContext_t *context, uint8_t *out, uint32_t length) {
    if (context->commandLength < length) {
        PRINTF("copyClauseData Underflow\n");
        THROW(0x6a01);
    }
    if (out != NULL) {
        os_memmove(out, context->workBuffer, length);
    }
    context->workBuffer += length;
    context->commandLength -= length;
    if (context->processingField) {
        context->currentFieldPos += length;
    }
}

static void processContent(clauseContext_t *context) {
    // Keep the full length for sanity checks, move to the next field
    if (!context->currentFieldIsList) {
        PRINTF("Invalid type for RLP_CONTENT\n");
        THROW(0x6a02);
    }
    context->dataLength = context->currentFieldLength;
    context->currentField++;
    context->processingField = false;
}

static void processToField(clauseContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for RLP_TO\n");
        THROW(0x6a05);
    }
    if (context->currentFieldLength > MAX_ADDRESS) {
        PRINTF("Invalid length for RLP_TO\n");
        THROW(0x6a06);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyClauseData(context,
                       context->content->to + context->currentFieldPos,
                      copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->content->toLength = context->currentFieldLength;
        context->currentField++;
        context->processingField = false;
    }
}

static void processValueField(clauseContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for RLP_VALUE\n");
        THROW(0x6a03);
    }
    if (context->currentFieldLength > MAX_INT256) {
        PRINTF("Invalid length for RLP_VALUE\n");
        THROW(0x6a04);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyClauseData(context,
                       context->content->value.value + context->currentFieldPos,
                       copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->content->value.length = context->currentFieldLength;
        context->currentField++;
        context->processingField = false;
    }
}

static void processDataField(clauseContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for RLP_DATA\n");
        THROW(0x6a07);
    }
    context->content->dataPresent = (context->currentFieldLength != 0);
    if (context->currentFieldLength == sizeof(context->content->data)) {
        if (context->currentFieldPos < context->currentFieldLength) {
            uint32_t copySize = (context->commandLength <
                                            ((context->currentFieldLength -
                                            context->currentFieldPos))
                                        ? context->commandLength
                                        : context->currentFieldLength -
                                            context->currentFieldPos);
            copyClauseData(context,
                           context->content->data + context->currentFieldPos,
                           copySize);
        }
        if (context->currentFieldPos == context->currentFieldLength) {
            context->currentField++;
            context->processingField = false;
        }
    }
}

static parserStatus_e processClauseInternal(clauseContext_t *context) {
    for (;;) {
        // EIP 155 style transasction
        if (context->currentField == CLAUSE_RLP_DONE) {
            return USTREAM_FINISHED;
        }
        if (context->commandLength == 0) {
            return USTREAM_PROCESSING;
        }
        if (!context->processingField) {
            bool canDecode = false;
            uint32_t offset;
            while (context->commandLength != 0) {
                bool valid;
                // Feed the RLP buffer until the length can be decoded
                context->rlpBuffer[context->rlpBufferPos++] =
                    readClauseByte(context);
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
        }
        switch (context->currentField) {
        case CLAUSE_RLP_CONTENT:
            processContent(context);
            break;
        case CLAUSE_RLP_TO:
            processToField(context);
            break;
        case CLAUSE_RLP_VALUE:
            processValueField(context);
            break;
        case CLAUSE_RLP_DATA:
            processDataField(context);
            break;
        default:
            PRINTF("Invalid RLP decoder context\n");
            return USTREAM_FAULT;
        }
    }
}

parserStatus_e processClause(clauseContext_t *context, uint8_t *buffer,
                         uint32_t length) {
    parserStatus_e result;
    /*BEGIN_TRY {
        TRY {*/
            context->workBuffer = buffer;
            context->commandLength = length;
            result = processClauseInternal(context);
        /*}
        CATCH_OTHER(e) {
            result = USTREAM_FAULT;
        }
        FINALLY {
        }
    }
    END_TRY;*/
    return result;
}
