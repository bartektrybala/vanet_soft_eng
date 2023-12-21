from cryptography.hazmat.primitives import serialization


def serialize_pem_pk_to_int(pem_pk: str) -> int:
    public_key = serialization.load_pem_public_key(pem_pk.encode("utf-8"))
    return public_key.public_numbers().n
