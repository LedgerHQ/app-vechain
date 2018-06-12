/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*   (c) 2018 Totient Labs
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

#include "vetUstream.h"
#include "vetUtils.h"

#define MAX_INT256 32
#define MAX_INT64 8
#define MAX_INT32 4
#define MAX_INT8 1
#define MAX_ADDRESS 20
#define MAX_V 2

void initTx(txContext_t *context, txContent_t *content,
            clausesContext_t *clausesContext, clausesContent_t *clausesContent,
            clauseContext_t *clauseContext, clauseContent_t *clauseContent,
            blake2b_ctx *blake2b, void *extra) {
    os_memset(context, 0, sizeof(txContext_t));
    context->blake2b = blake2b;
    context->content = content;
    context->extra = extra;
    context->currentField = TX_RLP_CONTENT;
    blake2b_init(context->blake2b, 32, NULL, 0);
    initClauses(clausesContext, clausesContent, clauseContext, clauseContent);
}

uint8_t readTxByte(txContext_t *context) {
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

void copyTxDataClauses(txContext_t *context,
                       clausesContext_t *clausesContext,
                       clauseContext_t *clauseContext,
                       uint32_t length) {
    parserStatus_e result;
    result = processClauses(clausesContext, clauseContext, context->workBuffer, length);
    if (result == USTREAM_FAULT) {
        THROW(EXCEPTION);
    }
    copyTxData(context, NULL, length);
}

void copyTxData(txContext_t *context, uint8_t *out, uint32_t length) {
    if (context->commandLength < length) {
        PRINTF("copyTxData Underflow\n");
        THROW(EXCEPTION);
    }
    if (out != NULL) {
        os_memmove(out, context->workBuffer, length);
    }
    if (!(context->processingField && context->fieldSingleByte)) {
        blake2b_update((blake2b_ctx *)context->blake2b, context->workBuffer, length);
    }
    context->workBuffer += length;
    context->commandLength -= length;
    if (context->processingField) {
        context->currentFieldPos += length;
    }
}

static void processContent(txContext_t *context) {
    // Keep the full length for sanity checks, move to the next field
    if (!context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_CONTENT\n");
        THROW(EXCEPTION);
    }
    context->dataLength = context->currentFieldLength;
    context->currentField++;
    context->processingField = false;
}

static void processChainTagField(txContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_CHAINTAG\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > MAX_INT32) {
        PRINTF("Invalid length for TX_RLP_CHAINTAG\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxData(context, NULL, copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentField++;
        context->processingField = false;
    }
}

static void processBlockRefField(txContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_BLOCKREF\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > MAX_INT64) {
        PRINTF("Invalid length for TX_RLP_BLOCKREF\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxData(context, NULL, copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentField++;
        context->processingField = false;
    }
}

static void processExpirationField(txContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_EXPIRATION\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > MAX_INT32) {
        PRINTF("Invalid length for TX_RLP_EXPIRATION\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxData(context, NULL, copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentField++;
        context->processingField = false;
    }
}

static void processClausesField(txContext_t *context, clausesContext_t *clausesContext, clauseContext_t *clauseContext) {
    if (!context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_CLAUSES\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxDataClauses(context,
                          clausesContext,
                          clauseContext,
                          copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->content->clauses = clausesContext->content;
        context->currentField++;
        context->processingField = false;
    }
}

static void processGasPriceCoefField(txContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_GASPRICECOEF\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > MAX_INT8) {
        PRINTF("Invalid length for TX_RLP_GASPRICECOEF\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxData(context,
                   context->content->gaspricecoef.value + context->currentFieldPos,
                   copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->content->gaspricecoef.length = context->currentFieldLength;
        context->currentField++;
        context->processingField = false;
    }
}

static void processGasField(txContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_GAS\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > MAX_INT64) {
        PRINTF("Invalid length for TX_RLP_GAS %d\n",
               context->currentFieldLength);
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxData(context,
                   context->content->gas.value + context->currentFieldPos,
                   copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->content->gas.length = context->currentFieldLength;
        context->currentField++;
        context->processingField = false;
    }
}

static void processDependsOnField(txContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_DEPENDSON\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > MAX_INT256) {
        PRINTF("Invalid length for TX_RLP_DEPENDSON\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxData(context, NULL, copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentField++;
        context->processingField = false;
    }
}

static void processNonceField(txContext_t *context) {
    if (context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_NONCE\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > MAX_INT64) {
        PRINTF("Invalid length for TX_RLP_NONCE\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldPos < context->currentFieldLength) {
        uint32_t copySize =
            (context->commandLength <
                     ((context->currentFieldLength - context->currentFieldPos))
                 ? context->commandLength
                 : context->currentFieldLength - context->currentFieldPos);
        copyTxData(context, NULL, copySize);
    }
    if (context->currentFieldPos == context->currentFieldLength) {
        context->currentField++;
        context->processingField = false;
    }
}

static void processReservedField(txContext_t *context) {
    if (!context->currentFieldIsList) {
        PRINTF("Invalid type for TX_RLP_RESERVED\n");
        THROW(EXCEPTION);
    }
    if (context->currentFieldLength > 1 || context->commandLength > 0) {
        PRINTF("Invalid length for TX_RLP_RESERVED\n");
        THROW(EXCEPTION);
    }
    context->currentField++;
    context->processingField = false;
}

static parserStatus_e processTxInternal(txContext_t *context, clausesContext_t *clausesContext, clauseContext_t *clauseContext) {
    for (;;) {
        bool processedCustom = false;
        if (context->currentField == TX_RLP_DONE) {
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
        }   
        switch (context->currentField) {
            case TX_RLP_CONTENT:
                processContent(context);
                break;
            case TX_RLP_CHAINTAG:
                processChainTagField(context);
                break;
            case TX_RLP_BLOCKREF:
                processBlockRefField(context);
                break;
            case TX_RLP_EXPIRATION:
                processExpirationField(context);
                break;
            case TX_RLP_CLAUSES:
                processClausesField(context, clausesContext, clauseContext);
                break;
            case TX_RLP_GASPRICECOEF:
                processGasPriceCoefField(context);
                break;
            case TX_RLP_GAS:
                processGasField(context);
                break;
            case TX_RLP_DEPENDSON:
                processDependsOnField(context);
                break;
            case TX_RLP_NONCE:
                processNonceField(context);
                break;
            case TX_RLP_RESERVED:
                processReservedField(context);
                break;
            default:
                PRINTF("Invalid RLP decoder context\n");
                return USTREAM_FAULT;
        }
    }
}

parserStatus_e processTx(txContext_t *context,
                         clausesContext_t *clausesContext,
                         clauseContext_t *clauseContext,
                         uint8_t *buffer,
                         uint32_t length) {
    parserStatus_e result;
    BEGIN_TRY {
        TRY {
            context->workBuffer = buffer;
            context->commandLength = length;
            result = processTxInternal(context, clausesContext, clauseContext);
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
