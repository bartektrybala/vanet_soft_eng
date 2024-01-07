import mcl

from data_utils import extract_pem_key_from_message, get_file_contents

# [TODO] Temporary solution
_SEC_PAR = b"abc"
GENERATOR = mcl.G1.hashAndMapTo(_SEC_PAR)


class SecrecyEngine:
    def __init__(self, secret_key_path: str, public_key_path: str):
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

    def get_session_pk_as_str(self) -> str:
        return self.session_pk.getStr().decode("utf-8")

    def get_session_pk_as_int(self) -> int:
        pk_b_str = self.session_pk.getStr()
        return int.from_bytes(pk_b_str, byteorder="big")
