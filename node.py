from functools import cached_property
import re
from dataclasses import dataclass, field
import time

from rich import print

from serializers import serialize_pem_pk_to_int
from settings import MASTER_CLOCK_PREFIX


@dataclass
class Node:
    pk: str
    public_keys: list[int] = field(default_factory=list)
    timestamp: float = field(init=False, default_factory=time.time)

    @cached_property
    def pk_int(self) -> int:
        return serialize_pem_pk_to_int(pem_pk=self.pk)

    @property
    def is_master(self) -> bool:
        if len(self.public_keys) == 0:
            return False
        return self.public_keys[0] == self.pk_int

    def add_public_key(self, message: str):
        pem_pk = extract_pem_public_key_from_message(message=message)
        public_key = serialize_pem_pk_to_int(pem_pk=pem_pk)

        if public_key not in self.public_keys:
            self.public_keys.append(public_key)
            self._sort_public_keys()

        print("\n------------------PUBLIC KEYS------------------")
        print(self.public_keys)

    def update_timestamp(self, message: str):
        message = message.replace(MASTER_CLOCK_PREFIX, "")
        self.timestamp = float(message)

        print("\n------------------TIMESTAMP------------------")
        print(self.timestamp)

    def _sort_public_keys(self):
        self.public_keys.sort()


def extract_pem_public_key_from_message(message: str) -> str:
    pem_regex_pattern = r"-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----"
    pk_pem = re.search(pem_regex_pattern, message)
    return pk_pem.group(0)
