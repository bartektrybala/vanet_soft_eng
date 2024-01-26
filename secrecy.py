import hashlib

import mcl

from utils.data_utils import extract_pem_key_from_message, get_file_contents
from utils.hashing import Hasher, pad_message, unpad_message, xor_bytes
import random as rand

# [TODO] Temporary solution
_SEC_PAR = b"abc"
GENERATOR_G1 = mcl.G1.hashAndMapTo(_SEC_PAR)
GENERATOR_G2 = mcl.G2.hashAndMapTo(_SEC_PAR)

# [TODO] Temporary solution?
_HASH_FUNCTION = hashlib.sha3_512
_HASH_LENGTH = _HASH_FUNCTION().digest_size


class SecrecyEngine:
    # [TODO] Currently only supports G1, not parametrized
    def __init__(self, secret_key_path: str, public_key_path: str):
        self.hasher = Hasher(_HASH_FUNCTION, _HASH_LENGTH)

        # print(f"Initialized secrecy engine with
        #   {_HASH_FUNCTION.__name__} and {_HASH_LENGTH} hash length")

        sk_file_contents = get_file_contents(secret_key_path, "r")
        self.secret_key = extract_pem_key_from_message(sk_file_contents)
        # [TODO] Never used since session private and public keys are generated
        # using the master key and only session public key is shared
        pk_file_contents = get_file_contents(public_key_path, "r")
        self.public_key = extract_pem_key_from_message(pk_file_contents)

        self.generator1 = GENERATOR_G1
        self.generator2 = GENERATOR_G2
        self.session_sk = mcl.Fr()
        self.session_pk1 = mcl.G1()
        self.session_pk2 = mcl.G2()

    def gen_session_keys(self):
        random_fr = mcl.Fr.rnd()
        self.session_sk = mcl.Fr.setHashOf(
            random_fr.getStr() + bytes(self.secret_key, "utf-8")
        )
        self.session_pk1 = self.generator1 * self.session_sk
        self.session_pk2 = self.generator2 * self.session_sk

    def get_session_pk1_as_byte_str(self) -> bytes:
        return self.session_pk1.getStr()

    def get_session_pk1_as_int(self) -> int:
        pk_b_str = self.session_pk1.getStr()
        return int.from_bytes(pk_b_str, byteorder="big")

    def get_session_pk2_as_byte_str(self) -> bytes:
        return self.session_pk2.getStr()

    def get_session_pk2_as_int(self) -> int:
        pk_b_str = self.session_pk2.getStr()
        return int.from_bytes(pk_b_str, byteorder="big")

    def encrypt_hash_elgamal(
        self, message: bytes, encryption_key_bytes: bytes
    ) -> (bytes, bytes):
        secret_eph: mcl.Fr = mcl.Fr.rnd()
        public_eph: mcl.G1 = self.generator1 * secret_eph

        encryption_key: mcl.G1 = mcl.G1()
        encryption_key.setStr(encryption_key_bytes)

        hash_key: mcl.G1 = encryption_key * secret_eph
        hash_key_bytes: bytes = hash_key.getStr()

        # Add 1 byte for guaranteed padding
        # Otherwise if message is divisible by hash length
        # we might have a case with unpadded message
        encryption_bytes = self.hasher.concatenated_hashes(
            len(message) + 1, hash_key_bytes
        )
        padded_message: bytes = pad_message(message, len(encryption_bytes))

        encrypted_message: bytes = xor_bytes(padded_message, encryption_bytes)
        return (public_eph.getStr(), encrypted_message)

    def decrypt_hash_elgamal(
        self, public_eph_bytes: bytes, encrypted_message: bytes
    ) -> bytes:
        public_eph: mcl.G1 = mcl.G1()
        public_eph.setStr(public_eph_bytes)

        hash_key: mcl.G1 = public_eph * self.session_sk
        hash_key_bytes: bytes = hash_key.getStr()

        assert (
            len(encrypted_message) % _HASH_LENGTH == 0
        ), f"{len(encrypted_message)=} not divisible by {self.hasher.hash_length}"

        decryption_bytes: bytes = self.hasher.concatenated_hashes(
            len(encrypted_message), hash_key_bytes
        )
        decrypted_padded_message = xor_bytes(encrypted_message, decryption_bytes)
        decrypted_message = unpad_message(decrypted_padded_message)

        return decrypted_message

    def ring_sign(self, message: bytes, public_keys_g2: list) -> (list, int):
        rand_val = mcl.Fr.rnd().getStr()[27:]
        main_sig_idx = int.from_bytes(rand_val, byteorder="big") % (
            len(public_keys_g2) + 1
        )

        signatures = [None] * len(public_keys_g2)

        fr_one = mcl.Fr.setHashOf(b"1") / mcl.Fr.setHashOf(b"1")
        big_product = self.generator2 - self.generator2
        for idx, pk_b in enumerate(public_keys_g2):
            pk: mcl.G2 = mcl.G2()
            pk.setStr(pk_b)

            eph = mcl.Fr.rnd()
            pk_raised = pk * eph
            big_product += pk_raised
            signatures[idx] = self.generator2 * eph
            # print(f"Pairing value[{idx}][:8]:
            #   {mcl.GT.pairing(GENERATOR_G1, pk_raised).getStr()[:8]}")

        hash: mcl.G2 = mcl.G2.hashAndMapTo(message)
        rev_sk: mcl.Fr = fr_one / self.session_sk

        main_sig: mcl.G2 = (hash - big_product) * rev_sk
        signatures.insert(main_sig_idx, main_sig)
        # print(f"Pairing value[{main_sig_idx}][:8]:
        #   {mcl.GT.pairing(self.session_pk1, main_sig).getStr()[:8]}")

        return ([sig.getStr() for sig in signatures], main_sig_idx)

    def ring_verify(
        self, message: bytes, signatures: list, public_keys_g1: list
    ) -> bool:
        assert len(signatures) == len(public_keys_g1)
        hash: mcl.G2 = mcl.G2.hashAndMapTo(message)
        left_side = mcl.GT.pairing(self.generator1, hash)

        right_side = mcl.GT.pairing(
            self.generator1 - self.generator1, self.generator2 - self.generator2
        )
        for idx in range(len(public_keys_g1)):
            pk_b = public_keys_g1[idx]
            pk: mcl.G1 = mcl.G1()
            pk.setStr(pk_b)

            sig_b = signatures[idx]
            sig_g2: mcl.G2 = mcl.G2()
            sig_g2.setStr(sig_b)

            right_side *= mcl.GT.pairing(pk, sig_g2)

        return left_side == right_side

    def secure_shuffle(self, array: list) -> (list, list):
        # [TODO] not secure
        indices = list(range(len(array)))
        rand.shuffle(indices)
        shuffled_array = [array[i] for i in indices]
        return (shuffled_array, indices)
