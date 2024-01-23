import mcl
import hashlib

from utils.data_utils import extract_pem_key_from_message, get_file_contents
from utils.hashing import Hasher, pad_message, unpad_message, xor_bytes

# [TODO] Temporary solution
_SEC_PAR = b"abc"
GENERATOR = mcl.G1.hashAndMapTo(_SEC_PAR)

# [TODO] Temporary solution?
_HASH_FUNCTION = hashlib.sha3_512
_HASH_LENGTH = _HASH_FUNCTION().digest_size

class SecrecyEngine:
    # [TODO] Currently only supports G1, not parametrized
    def __init__(self, secret_key_path: str, public_key_path: str):
        self.hasher = Hasher(_HASH_FUNCTION, _HASH_LENGTH)

        # print(f"Initialized secrecy engine with {_HASH_FUNCTION.__name__} and {_HASH_LENGTH} hash length")

        sk_file_contents = get_file_contents(secret_key_path, "r")
        self.secret_key = extract_pem_key_from_message(sk_file_contents)
        # [TODO] Never used since session private and public keys are generated
        # using the master key and only session public key is shared
        pk_file_contents = get_file_contents(public_key_path, "r")
        self.public_key = extract_pem_key_from_message(pk_file_contents)

        self.generator = GENERATOR
        self.session_sk = mcl.Fr()
        self.session_pk = mcl.G1()

    def gen_session_keys(self):
        random_fr = mcl.Fr.rnd()
        self.session_sk = mcl.Fr.setHashOf(
            random_fr.getStr() + bytes(self.secret_key, "utf-8")
        )
        self.session_pk = self.generator * self.session_sk

    def get_session_pk_as_byte_str(self) -> bytes:
        return self.session_pk.getStr()

    def get_session_pk_as_int(self) -> int:
        pk_b_str = self.session_pk.getStr()
        return int.from_bytes(pk_b_str, byteorder="big")

    def encrypt_hash_elgamal(
        self,
        message: bytes,
        encryption_key_bytes: bytes
    ) -> (bytes, bytes):
        secret_eph: mcl.Fr = mcl.Fr.rnd()
        public_eph: mcl.G1 = self.generator * secret_eph

        encryption_key: mcl.G1 = mcl.G1()
        encryption_key.setStr(encryption_key_bytes)

        hash_key: mcl.G1 = encryption_key * secret_eph
        hash_key_bytes: bytes = hash_key.getStr()

        # Add 1 byte for guaranteed padding
        # Otherwise if message is divisible by hash length
        # we might have a case with unpadded message
        encryption_bytes = self.hasher.concatenated_hashes(
            len(message) + 1,
            hash_key_bytes
        )
        padded_message: bytes = pad_message(message, len(encryption_bytes))

        encrypted_message: bytes = xor_bytes(padded_message, encryption_bytes)
        return (public_eph.getStr(), encrypted_message)

    def decrypt_hash_elgamal(
        self,
        public_eph_bytes: bytes,
        encrypted_message: bytes
    ) -> bytes:
        public_eph: mcl.G1 = mcl.G1()
        public_eph.setStr(public_eph_bytes)

        hash_key: mcl.G1 = public_eph * self.session_sk
        hash_key_bytes: bytes = hash_key.getStr()

        assert len(encrypted_message) % _HASH_LENGTH == 0, \
            f"Encrypted {len(encrypted_message)=} not divisible by {self.hasher.hash_length}"

        decryption_bytes: bytes = self.hasher.concatenated_hashes(
            len(encrypted_message),
            hash_key_bytes
        )
        decrypted_padded_message = xor_bytes(encrypted_message, decryption_bytes)
        decrypted_message = unpad_message(decrypted_padded_message)

        return decrypted_message
