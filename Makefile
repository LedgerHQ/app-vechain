# ****************************************************************************
#    Ledger App Boilerplate
#    (c) 2020 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "VeChain"

# Application version
APPVERSION_M = 1
APPVERSION_N = 4
APPVERSION_P = 0
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

APP_SOURCE_PATH += src common

# Application icons
ICON_NANOX = icons/nanox_app_vechain.gif
ICON_NANOSP = icons/nanox_app_vechain.gif
ICON_STAX = icons/stax_app_vechain_32px.gif
ICON_FLEX = icons/flex_app_vechain_40px.gif
ICON_APEX_P = icons/apex_app_vechain_32px.png

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS2))
    # With the Nano NBGL Design, the Home Screen icon is the reverse of the App icon:
    ICON_HOME_NANO = glyphs/home_vechain_14px.gif
endif

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS = secp256k1

# Application allowed derivation paths.
PATH_APP_LOAD_PARAMS = "44'/818'" "44'/1'"

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = vechain
ifndef COIN
    COIN=vechain
endif

# Enabling DEBUG flag will enable PRINTF and disable optimizations
#DEBUG = 1

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_STAX TARGET_FLEX TARGET_APEX_P))
    HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
endif
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1

########################################
#         NBGL custom features         #
########################################
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_STAX TARGET_FLEX TARGET_APEX_P))
    ENABLE_NBGL_QRCODE = 1
endif
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
#DISABLE_STANDARD_APP_FILES = 1
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration
#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1
#DISABLE_DEBUG_LEDGER_ASSERT = 1
#DISABLE_DEBUG_THROW = 1


########################################
#        Main app configuration        #
########################################

DEFINES += U2F_PROXY_MAGIC=\"VeX\"
APP_WEBUSB_URL = www.ledgerwallet.com

# EIP-712 needs dynamic allocation (linked-list typed-data registry,
# nested struct hash context stack, paths/field hash buffers).
ENABLE_DYNAMIC_ALLOC = 1

# Heap size dedicated to the EIP-712 typed-data parser. Larger on touchscreen
# targets (Stax/Flex/Apex P) where flash and RAM budgets are bigger.
ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_STAX TARGET_FLEX TARGET_APEX_P))
    DEFINES += APP_MEM_BUFFER_SIZE=16384
else
    DEFINES += APP_MEM_BUFFER_SIZE=8192
endif

########################################
#       Build flags: validation        #
########################################
# Set EIP712_MEMORY_PROFILING=1 on the make command line to enable runtime
# heap usage logs from lib_alloc (printed on the Speculos debug output).
ifeq ($(EIP712_MEMORY_PROFILING),1)
    DEFINES += HAVE_MEMORY_PROFILING
endif

include $(BOLOS_SDK)/Makefile.standard_app

########################################
#       Helper validation targets      #
########################################
# `make size` prints the .text and .data section size of the linked ELF so it
# is easy to track flash and RAM footprint regressions across phases.
.PHONY: size
size: $(BUILD_DIR)/bin/app.elf
	@echo "==== app.elf section sizes ===="
	@$(SIZE) $(BUILD_DIR)/bin/app.elf || size $(BUILD_DIR)/bin/app.elf
	@echo
	@echo "==== sections > 256 bytes ===="
	@$(OBJDUMP) -h $(BUILD_DIR)/bin/app.elf | awk '/^[ ]+[0-9]+/ && strtonum("0x"$$3) > 256 { print $$2, $$3 }' || true
