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

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT
} parserStatus_e;

typedef struct txInt256_t {
    uint8_t value[32];
    uint8_t length;
} txInt256_t;

#endif