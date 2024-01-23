import re

from cryptography.hazmat.primitives import serialization

def serialize_pem_pk_to_int(pem_pk: str) -> int:
    public_key = serialization.load_pem_public_key(pem_pk.encode("utf-8"))
    return public_key.public_numbers().n


# [TODO] probably add some enum for key_type to be sure we get the kind
# of key we expected (i.e. if somebody passed a message with a private key but we
# needed a public key we wouldn't notice we extraced a private key instead)
def extract_pem_key_from_message(message: str) -> str:
    """
    Extracts either public or private key from message
    """
    pem_regex_pattern = (
        r"-----BEGIN (PUBLIC|PRIVATE) KEY-----"
        r"([\s\S]*?)"
        r"-----END (PUBLIC|PRIVATE) KEY-----"
    )
    pk_pem = re.search(pem_regex_pattern, message)
    return pk_pem.group(0)


# [TODO] poor utility but eh does the job
def get_file_contents(file_path: str, open_mode: str) -> str:
    try:
        with open(file_path, open_mode) as file:
            return file.read()
    except FileNotFoundError:
        print(f"Could not find file {file_path}")
        exit(1)
