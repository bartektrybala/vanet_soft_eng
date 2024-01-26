# [TODO] Improve project structure
# This file should be in the "test" subfolder

import unittest

import mcl

import secrecy as se


def encrypt_decrypt_routine(
    encyrption_fn: callable, decryption_fn: callable, key: bytes, message: bytes
) -> bytes:
    public_eph, encrypted_message = encyrption_fn(message, key)
    print(f"{len(encrypted_message)=}")

    decrypted_message = decryption_fn(public_eph, encrypted_message)

    print(f"{decrypted_message=}")
    return decrypted_message


def produce_random_public_pk_key_pairs(
    generator1: mcl.G1, generator2: mcl.G2
) -> (mcl.G1, mcl.G2):
    secret_key: mcl.Fr = mcl.Fr.rnd()
    public_key1: mcl.G1 = generator1 * secret_key
    public_key2: mcl.G2 = generator2 * secret_key

    return (public_key1, public_key2)


class TestSecrecyEngineElGamal(unittest.TestCase):
    def setUp(self):
        self.secret_key_path = "./secret_keys/secret_key_1.pem"
        self.public_key_path = "./public_keys/public_key_1.pem"
        self.engine = se.SecrecyEngine(self.secret_key_path, self.public_key_path)

    def test_conversions(self):
        self.engine.gen_session_keys()

        key_as_str = self.engine.session_pk1.getStr()
        key_back_to_mcl = mcl.G1()
        key_back_to_mcl.setStr(key_as_str)

        self.assertEqual(self.engine.session_pk1, key_back_to_mcl)

    def test_encrypt_decrypt(self):
        self.engine.gen_session_keys()

        message = b"Hello world!"
        encryption_key = self.engine.session_pk1.getStr()

        decrypted_message = encrypt_decrypt_routine(
            self.engine.encrypt_hash_elgamal,
            self.engine.decrypt_hash_elgamal,
            encryption_key,
            message,
        )

        self.assertEqual(message, decrypted_message)

    def test_encrypt_decrypt_divisible_by_hash_size(self):
        self.engine.gen_session_keys()
        message = b"a" * se._HASH_LENGTH

        encryption_key = self.engine.session_pk1.getStr()

        decrypted_message = encrypt_decrypt_routine(
            self.engine.encrypt_hash_elgamal,
            self.engine.decrypt_hash_elgamal,
            encryption_key,
            message,
        )

        self.assertEqual(message, decrypted_message)


class TestSecrecyEngineRingSignature(unittest.TestCase):
    def setUp(self):
        self.secret_key_path = "./secret_keys/secret_key_1.pem"
        self.public_key_path = "./public_keys/public_key_1.pem"
        self.other_public_keys = [
            produce_random_public_pk_key_pairs(se.GENERATOR_G1, se.GENERATOR_G2)
            for _ in range(2)
        ]

        self.engine = se.SecrecyEngine(self.secret_key_path, self.public_key_path)

    def test_sign_verify(self):
        self.engine.gen_session_keys()

        message = b"Hello world!"
        signature, main_sig_idx = self.engine.ring_sign(
            message, [pk[1].getStr() for pk in self.other_public_keys]
        )

        pk1_set = [pk[0].getStr() for pk in self.other_public_keys]
        pk1_set.insert(main_sig_idx, self.engine.session_pk1.getStr())
        self.assertTrue(self.engine.ring_verify(message, signature, pk1_set))

    def test_sign_verify_divisible_by_hash_size(self):
        self.engine.gen_session_keys()

        message = b"a" * se._HASH_LENGTH
        signature, main_sig_idx = self.engine.ring_sign(
            message, [pk[1].getStr() for pk in self.other_public_keys]
        )

        pk1_set = [pk[0].getStr() for pk in self.other_public_keys]
        pk1_set.insert(main_sig_idx, self.engine.session_pk1.getStr())
        self.assertTrue(self.engine.ring_verify(message, signature, pk1_set))

    def test_sign_verify_wrong_message(self):
        self.engine.gen_session_keys()

        message = b"Hello world!"
        signature, main_sig_idx = self.engine.ring_sign(
            message, [pk[1].getStr() for pk in self.other_public_keys]
        )

        pk1_set = [pk[0].getStr() for pk in self.other_public_keys]
        pk1_set.insert(main_sig_idx, self.engine.session_pk1.getStr())
        self.assertFalse(self.engine.ring_verify(b"Hello world", signature, pk1_set))

    def test_sign_verify_wrong_pk_set(self):
        self.engine.gen_session_keys()

        message = b"Hello world!"
        signature, main_sig_idx = self.engine.ring_sign(
            message, [pk[1].getStr() for pk in self.other_public_keys]
        )

        pk1_set = [pk[0].getStr() for pk in self.other_public_keys]
        pk1_set.insert(main_sig_idx, self.engine.session_pk1.getStr())

        fake_pk = self.engine.session_pk1.getStr()
        fake_pk = fake_pk[:1] + bytes([fake_pk[1] ^ 0xFF]) + fake_pk[2:]
        pk1_set[0] = fake_pk

        self.assertFalse(self.engine.ring_verify(message, signature, pk1_set))

    def test_sign_verify_wrong_signature(self):
        self.engine.gen_session_keys()

        message = b"Hello world!"
        signature, main_sig_idx = self.engine.ring_sign(
            message, [pk[1].getStr() for pk in self.other_public_keys]
        )

        pk1_set = [pk[0].getStr() for pk in self.other_public_keys]
        pk1_set.insert(main_sig_idx, self.engine.session_pk1.getStr())
        signature[0] = self.engine.session_pk1.getStr()
        self.assertFalse(self.engine.ring_verify(message, signature, pk1_set))


if __name__ == "__main__":
    unittest.main()
