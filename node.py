import re
from dataclasses import dataclass, field

from rich import print

from serializers import serialize_pem_pk_to_int


@dataclass
class Node:
    pk: str
    public_keys: list[int] = field(default_factory=list)

    def add_public_key(self, message: str):
        pk_pem = extract_pem_public_key_from_message(message=message)
        public_key = serialize_pem_pk_to_int(message=pk_pem)

        if public_key not in self.public_keys:
            self.public_keys.append(public_key)
            self.sort_public_keys()

        print("------------------PUBLIC KEYS------------------")
        print(self.public_keys)

    def sort_public_keys(self):
        self.public_keys.sort()


def extract_pem_public_key_from_message(message: str) -> str:
    pem_regex_pattern = r"-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----"
    pk_pem = re.search(pem_regex_pattern, message)
    return pk_pem.group(0)
