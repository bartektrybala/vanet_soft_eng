import re
import time
from dataclasses import dataclass, field
from functools import cached_property

from rich import print

from message import MessageTimeGenerator
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
        # Master is the first node on the list
        return self.public_keys[0] == self.pk_int

    @property
    def node_number(self) -> int:
        return self.public_keys.index(self.pk_int) + 1

    @property
    def next_message_timestamp(self) -> float:
        return next(MessageTimeGenerator(self.timestamp))

    def add_public_key(self, message: str):
        pem_pk = extract_pem_key_from_message(message=message)
        public_key = serialize_pem_pk_to_int(pem_pk=pem_pk)

        if public_key not in self.public_keys:
            self.public_keys.append(public_key)
            self._sort_public_keys()

        print("\n------------------PUBLIC KEYS [NEW ADDED] ------------------")
        print(self.public_keys)

    def remove_public_key(self, message: str):
        pem_pk = extract_pem_key_from_message(message=message)
        public_key = serialize_pem_pk_to_int(pem_pk=pem_pk)

        if public_key in self.public_keys:
            self.public_keys.remove(public_key)
            self._sort_public_keys()
        else:
            print(
                f"[!!!] Did not find public key {public_key} in the list of "
                f"public keys. Might be a malicious node trying to disconnect."
            )

        print("\n------------------PUBLIC KEYS [ONE REMOVED] ------------------")
        print(self.public_keys)

    def update_timestamp(self, message: str):
        message = message.replace(MASTER_CLOCK_PREFIX, "")
        self.timestamp = float(message)

        print("\n------------------TIMESTAMP------------------")
        print(self.timestamp)

    def setup_periodic_message_broadcast(self):
        ...

    def _sort_public_keys(self):
        self.public_keys.sort()


# [TODO] probably add some enum for key_type to be sure we get the kind
# of key we expected (i.e. if somebody passed a message with a private key but we
# needed a public key we wouldn't notice we extraced a private key instead)
#
# On the other hand, next step is usually serialization which would probably
# crash anyway
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
