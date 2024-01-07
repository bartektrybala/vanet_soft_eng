import mcl

# [TODO] Temporary solution
_SEC_PAR = b"abc"
GENERATOR = mcl.G1.hashAndMapTo(_SEC_PAR)


class SecrecyEngine:
    def __init__(self, secret_key_path: str, public_key_path: str):
        self.secret_key = self._get_key_from_file(secret_key_path)
        # [TODO] Never used since session private and public keys are generated
        # using the master key and only session public key is shared
        self.public_key = self._get_key_from_file(public_key_path)
        self.generator = GENERATOR
        self.session_sk = mcl.Fr()
        self.session_pk = mcl.G1()

    def _get_key_from_file(self, key_path: str) -> str:
        try:
            with open(key_path, "r") as key_file:
                file_contents = key_file.read()
                return file_contents
        except FileNotFoundError:
            print(f"Could not find key file " f"{key_path}")
            exit(1)

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
