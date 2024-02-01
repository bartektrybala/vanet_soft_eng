import time
from dataclasses import dataclass, field
from functools import cached_property

from rich import print

from message import MessageTimeGenerator
from secrecy import SecrecyEngine
from settings import MASTER_CLOCK_PREFIX


@dataclass
class Node:
    secrecy_engine: SecrecyEngine
    node_id: int
    public_keys_g1: list[int] = field(default_factory=list)
    public_keys_g2: list[int] = field(default_factory=list)
    timestamp: float = field(init=False, default_factory=time.time)
    onion_list = []

    @cached_property
    def session_pk1_str(self) -> str:
        return self.secrecy_engine.get_session_pk1_as_byte_str().decode("utf-8")

    @cached_property
    def session_pk2_str(self) -> str:
        return self.secrecy_engine.get_session_pk2_as_byte_str().decode("utf-8")

    @cached_property
    def session_pk1_int(self) -> int:
        return self.secrecy_engine.get_session_pk1_as_int()

    @cached_property
    def session_pk2_int(self) -> int:
        return self.secrecy_engine.get_session_pk2_as_int()

    @property
    def is_master(self) -> bool:
        if len(self.public_keys_g1) == 0:
            return False
        # Master is the first node on the list
        return self.public_keys_g1[0] == self.session_pk1_int

    @property
    def node_number(self) -> int:
        return self.public_keys_g1.index(self.session_pk1_int) + 1

    @property
    def next_message_timestamp(self) -> float:
        return next(MessageTimeGenerator(self.timestamp))

    def add_public_key(self, pk1_str: str, pk2_str: str):
        public_key_g1 = int.from_bytes(bytes(pk1_str, "utf-8"), byteorder="big")
        public_key_g2 = int.from_bytes(bytes(pk2_str, "utf-8"), byteorder="big")

        if public_key_g1 not in self.public_keys_g1:
            self.public_keys_g1.append(public_key_g1)
            self.public_keys_g2.append(public_key_g2)
            self._sort_public_keys()

        print("\n------------------PUBLIC KEYS [NEW ADDED] ------------------")
        print(f"Public Keys G1: {self.public_keys_g1}")
        print(f"Public Keys G2: {self.public_keys_g2}")
        print(f"KEYS LIST: {self.public_keys_g1}")

    def remove_public_key(self, pk1_str: str, pk2_str: str):
        # pem_pk = extract_pem_key_from_message(message=message)
        # public_key = serialize_pem_pk_to_int(pem_pk=pem_pk)
        public_key_g1 = int.from_bytes(bytes(pk1_str, "utf-8"), byteorder="big")
        public_key_g2 = int.from_bytes(bytes(pk2_str, "utf-8"), byteorder="big")

        if public_key_g1 in self.public_keys_g1 and public_key_g2 in self.public_keys_g2:
            self.public_keys_g1.remove(public_key_g1)
            self.public_keys_g2.remove(public_key_g2)
            self._sort_public_keys()
        else:
            print(
                f"[!!!] Did not find public key {public_key_g1} or {public_key_g2} in the list of "
                f"public keys. Might be a malicious node trying to disconnect."
            )

        print("\n------------------PUBLIC KEYS [ONE REMOVED] ------------------")
        print(f"Public Keys G1: {self.public_keys_g1}")
        print(f"Public Keys G2: {self.public_keys_g2}")

    def update_timestamp(self, message: str):
        message = message.replace(MASTER_CLOCK_PREFIX, "")
        self.timestamp = float(message)

        print("\n------------------TIMESTAMP------------------")
        print(self.timestamp)

    def setup_periodic_message_broadcast(self):
        ...

    def _sort_public_keys(self):
        self.public_keys_g1.sort()
        self.public_keys_g2.sort()
