import struct
from enum import IntEnum
from typing import Tuple, Generator, List, Optional
from contextlib import contextmanager
from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import pack_derivation_path

CLA = 0xE0
MAX_APDU_LEN = 255

class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX   = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01

class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80

class InsType(IntEnum):
    INS_GET_PUBLIC_KEY              = 0x02
    INS_GET_APP_CONFIGURATION       = 0x06
    INS_SIGN                        = 0x04
    INS_SIGN_PERSONAL_MESSAGE       = 0x08
    INS_SIGN_CERTIFICATE            = 0x09
    INS_SIGN_EIP_712                = 0x0C
    INS_EIP712_SEND_STRUCT_DEF      = 0x1A
    INS_EIP712_SEND_STRUCT_IMPL     = 0x1C

class EIP712P2(IntEnum):
    EIP712_P2_V0   = 0x00  # blind sign: domainSeparator + hashStruct provided
    EIP712_P2_V1   = 0x01  # clear sign: types/values streamed beforehand
    EIP712_DEF_NAME  = 0x00
    EIP712_DEF_FIELD = 0xFF
    EIP712_IMPL_ROOT  = 0x00
    EIP712_IMPL_ARRAY = 0x0F
    EIP712_IMPL_FIELD = 0xFF

class EIP712P1(IntEnum):
    EIP712_IMPL_COMPLETE = 0x00
    EIP712_IMPL_PARTIAL  = 0x01

class Errors(IntEnum):
    SW_TRANSACTION_CANCELLED  = 0x6985
    SW_NON_ZERO_AMOUNT        = 0x6A87
    SW_UNKNOWN_DESTINATION    = 0x6A88
    SW_SUCCESS                = 0x9000

def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x:x + max_size] for x in range(0, len(message), max_size)]

def split_tx(path:str, tx:bytes):
    paths = pack_derivation_path(path)
    return split_message(paths + tx, MAX_APDU_LEN)

# remainder, data_len, data
def pop_size_prefixed_buf_from_buf(buffer:bytes) -> Tuple[bytes, int, bytes]:
    data_len = buffer[0]
    return buffer[1+data_len:], data_len, buffer[1:data_len+1]

# remainder, data_len, data
def pop_sized_buf_from_buffer(buffer:bytes, size:int) -> Tuple[bytes, bytes]:
    return buffer[size:], buffer[0:size]

# Unpack from response:
# response = pub_key_len (1)
#            pub_key (var)
def unpack_get_public_key_response(response: bytes) -> Tuple[int, bytes]:
    response, pub_key_len, pub_key = pop_size_prefixed_buf_from_buf(response)

    assert pub_key_len == 65
    return pub_key_len, pub_key


# Unpack from response:
# response = der_sig_len (1)
#            der_sig (var)
#            v (1)
def unpack_sign_tx_response(response: bytes) -> Tuple[int, bytes, int]:
    response, der_sig_len, der_sig = pop_size_prefixed_buf_from_buf(response)
    response, buf = pop_sized_buf_from_buffer(response, 1)

    assert len(response) == 0

    return der_sig_len, der_sig, int.from_bytes(buf, byteorder='big')

class VechainClient:
    def __init__(self, backend: BackendInterface):
        self._backend = backend

    def exchange(self, ins: int, p1: int, p2: int, data: bytes) -> RAPDU:
        """Direct synchronous APDU exchange. Used by EIP-712 helpers that
        stream multiple SEND_STRUCT_DEFINITION / SEND_STRUCT_IMPLEMENTATION
        APDUs in a row without needing the high-level wrappers."""
        return self._backend.exchange(cla=CLA, ins=ins, p1=p1, p2=p2, data=data)

    def get_app_configuration(self) -> Tuple[int, int, int, int]:
        rapdu: RAPDU = self._backend.exchange(cla=CLA,
                                              ins=InsType.INS_GET_APP_CONFIGURATION,
                                              p1=P1.P1_START,
                                              p2=P2.P2_LAST,
                                              data=b"")
        response = rapdu.data
        assert len(response) == 4

        settings_flags = int(response[0])
        major = int(response[1])
        minor = int(response[2])
        patch = int(response[3])
        return (settings_flags, major, minor, patch)


    def get_public_key(self, path: str) -> RAPDU:
        return self._backend.exchange(cla=CLA,
                                      ins=InsType.INS_GET_PUBLIC_KEY,
                                      p1=P1.P1_START,
                                      p2=P2.P2_LAST,
                                      data=pack_derivation_path(path))

    @contextmanager
    def get_public_key_with_confirmation(self, path: str) -> Generator[None, None, None]:
        with self._backend.exchange_async(cla=CLA,
                                         ins=InsType.INS_GET_PUBLIC_KEY,
                                         p1=P1.P1_CONFIRM,
                                         p2=P2.P2_LAST,
                                         data=pack_derivation_path(path)) as response:
            yield response

    @contextmanager
    def sign_certificate(self, path: str, data: bytes) -> Generator[None, None, None]:
        with self._backend.exchange_async(cla=CLA,
                                        ins=InsType.INS_SIGN_CERTIFICATE,
                                        p1=P1.P1_START,
                                        p2=P2.P2_LAST,
                                        data=pack_derivation_path(path)+data) as response:
            yield response

    @contextmanager
    def sign_message(self, path: str, data: bytes) -> Generator[None, None, None]:
        with self._backend.exchange_async(cla=CLA,
                                        ins=InsType.INS_SIGN_PERSONAL_MESSAGE,
                                        p1=P1.P1_START,
                                        p2=P2.P2_LAST,
                                        data=pack_derivation_path(path)+data) as response:
            yield response

    @contextmanager
    def sign_tx(self, path: str, transaction: bytes) -> Generator[None, None, None]:
        with self._backend.exchange_async(cla=CLA,
                                         ins=InsType.INS_SIGN,
                                         p1=P1.P1_START,
                                         p2=P2.P2_LAST,
                                         data=pack_derivation_path(path)+transaction) as response:
            yield response

    @contextmanager
    def sing_tx_long(self, path: str, transaction: bytes) -> Generator[None, None, None]:
        messages = split_tx(path,transaction)

        for i in range(0, len(messages) - 1):
            try:
                self._backend.exchange(cla=CLA,
                                    ins=InsType.INS_SIGN,
                                    p1= P1.P1_START if i==0 else P2.P2_MORE,
                                    p2= P2.P2_LAST,
                                    data=messages[i])
            except Exception:
                pass

        with self._backend.exchange_async(cla=CLA,
                                         ins=InsType.INS_SIGN,
                                         p1=P2.P2_MORE,
                                         p2=P2.P2_LAST,
                                         data=messages[-1]) as response:
            yield response

    def get_async_response(self) -> Optional[RAPDU]:
        return self._backend.last_async_response

    @contextmanager
    def sign_eip712_v0(self,
                       path: str,
                       domain_separator: bytes,
                       hash_struct: bytes) -> Generator[None, None, None]:
        """Send INS_SIGN_EIP_712 with P2=0x00 (blind sign)."""
        if len(domain_separator) != 32 or len(hash_struct) != 32:
            raise ValueError("domain_separator and hash_struct must be 32 bytes each")
        data = pack_derivation_path(path) + domain_separator + hash_struct
        with self._backend.exchange_async(cla=CLA,
                                          ins=InsType.INS_SIGN_EIP_712,
                                          p1=0x00,
                                          p2=EIP712P2.EIP712_P2_V0,
                                          data=data) as response:
            yield response

    def eip712_send_struct_name(self, name: str) -> RAPDU:
        return self._backend.exchange(cla=CLA,
                                      ins=InsType.INS_EIP712_SEND_STRUCT_DEF,
                                      p1=0x00,
                                      p2=EIP712P2.EIP712_DEF_NAME,
                                      data=name.encode("utf-8"))

    def eip712_send_struct_field(self, field_apdu: bytes) -> RAPDU:
        return self._backend.exchange(cla=CLA,
                                      ins=InsType.INS_EIP712_SEND_STRUCT_DEF,
                                      p1=0x00,
                                      p2=EIP712P2.EIP712_DEF_FIELD,
                                      data=field_apdu)

    def eip712_send_impl_root(self, name: str) -> RAPDU:
        return self._backend.exchange(cla=CLA,
                                      ins=InsType.INS_EIP712_SEND_STRUCT_IMPL,
                                      p1=EIP712P1.EIP712_IMPL_COMPLETE,
                                      p2=EIP712P2.EIP712_IMPL_ROOT,
                                      data=name.encode("utf-8"))

    def eip712_send_impl_field(self, value: bytes) -> RAPDU:
        if len(value) > 0xFFFF:
            raise ValueError("value too large")
        prefixed = struct.pack(">H", len(value)) + value
        return self._backend.exchange(cla=CLA,
                                      ins=InsType.INS_EIP712_SEND_STRUCT_IMPL,
                                      p1=EIP712P1.EIP712_IMPL_COMPLETE,
                                      p2=EIP712P2.EIP712_IMPL_FIELD,
                                      data=prefixed)

    @contextmanager
    def sign_eip712_v1(self, path: str) -> Generator[None, None, None]:
        """Send INS_SIGN_EIP_712 with P2=0x01 (clear sign).
        Caller must have already streamed all SEND_STRUCT_DEFINITION and
        SEND_STRUCT_IMPLEMENTATION APDUs."""
        with self._backend.exchange_async(cla=CLA,
                                          ins=InsType.INS_SIGN_EIP_712,
                                          p1=0x00,
                                          p2=EIP712P2.EIP712_P2_V1,
                                          data=pack_derivation_path(path)) as response:
            yield response

    def eip712_send_impl_array(self, size: int) -> RAPDU:
        return self._backend.exchange(cla=CLA,
                                      ins=InsType.INS_EIP712_SEND_STRUCT_IMPL,
                                      p1=EIP712P1.EIP712_IMPL_COMPLETE,
                                      p2=EIP712P2.EIP712_IMPL_ARRAY,
                                      data=bytes([size & 0xFF]))
