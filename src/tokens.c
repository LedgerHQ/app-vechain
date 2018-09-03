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

#include "tokens.h"

const tokenDefinition_t const TOKENS[NUM_TOKENS] = {
    {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x45, 0x6e, 0x65, 0x72, 0x67, 0x79},
     "VTHO ",
     18},
    {{0x0c, 0xe6, 0x66, 0x1b, 0x4b, 0xa8, 0x6a, 0x0e, 0xa7, 0xca,
      0x2b, 0xd8, 0x6a, 0x0d, 0xe8, 0x7b, 0x0b, 0x86, 0x0f, 0x14},
     "OCE ",
     18},
    {{0x89, 0x82, 0x7f, 0x7b, 0xb9, 0x51, 0xfd, 0x8a, 0x56, 0xf8,
      0xef, 0x13, 0xc5, 0xbf, 0xee, 0x38, 0x52, 0x2f, 0x2e, 0x1f},
     "PLA ",
     18}
};
