from pathlib import Path
from hashlib import blake2b

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey


ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

# Check if a signature of a given message is valid
def check_signature_validity(public_key: bytes, signature: bytes, message: bytes) -> bool:
    pk: VerifyingKey = VerifyingKey.from_string(
        public_key,
        curve=SECP256k1,
    )

    digest = blake2b(message, digest_size=32).digest()
    return pk.verify_digest(signature=signature[:64],digest=digest)

