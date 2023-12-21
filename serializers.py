from cryptography.hazmat.primitives import serialization


def serialize_pem_pk_to_int(message: str) -> int:
    public_key = serialization.load_pem_public_key(message.encode("utf-8"))
    return public_key.public_numbers().n
