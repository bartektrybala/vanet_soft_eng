# [TODO] Improve project structure
# This file should be in the "test" subfolder

import unittest
import secrecy as se
import mcl

def encrypt_decrypt_routine(
    encyrption_fn: callable,
    decryption_fn: callable,
    key: bytes,
    message: bytes
) -> bytes:
    public_eph, encrypted_message = encyrption_fn(
        message,
        key
    )
    print(f"{len(encrypted_message)=}")

    decrypted_message = decryption_fn(
        public_eph,
        encrypted_message
    )

    print(f"{decrypted_message=}")
    return decrypted_message

class TestSecrecyEngine(unittest.TestCase):
    def setUp(self):
        self.secret_key_path = "./secret_keys/secret_key_1.pem"
        self.public_key_path = "./public_keys/public_key_1.pem"
        self.engine = se.SecrecyEngine(self.secret_key_path, self.public_key_path)

    def test_conversions(self):
        self.engine.gen_session_keys()

        key_as_str = self.engine.session_pk.getStr()
        key_back_to_mcl = mcl.G1()
        key_back_to_mcl.setStr(key_as_str)

        self.assertEqual(self.engine.session_pk, key_back_to_mcl)

    def test_encrypt_decrypt(self):
        self.engine.gen_session_keys()

        message = b"Hello world!"
        encryption_key = self.engine.session_pk.getStr()

        decrypted_message = encrypt_decrypt_routine(
            self.engine.encrypt_hash_elgamal,
            self.engine.decrypt_hash_elgamal,
            encryption_key,
            message
        )

        self.assertEqual(message, decrypted_message)


    def test_encrypt_decrypt_divisible_by_hash_size(self):
        self.engine.gen_session_keys()
        message = b"a" * se._HASH_LENGTH

        encryption_key = self.engine.session_pk.getStr()

        decrypted_message = encrypt_decrypt_routine(
            self.engine.encrypt_hash_elgamal,
            self.engine.decrypt_hash_elgamal,
            encryption_key,
            message
        )

        self.assertEqual(message, decrypted_message)

if __name__ == "__main__":
    unittest.main()