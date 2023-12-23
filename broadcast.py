from __future__ import annotations

import json
import socket
from dataclasses import dataclass, field
from threading import Thread
from typing import TypedDict, cast

from rich import print

from node import Node
from scheduler import MessageScheduler
from settings import (
    BROADCAST_HOST,
    BROADCAST_PORT,
    COLLECT_PK_LIST_PREFIX,
    MASTER_CLOCK_PREFIX,
    PUBLIC_KEY_BROADCAST_PREFIX,
    SECURITY_MESSAGE_PREFIX,
    SYNCHRONIZE_CLOCK_PREFIX,
)


class BroadcastMessage(TypedDict):
    prefix: str
    message: str


class BroadcastSocket(socket.socket):
    node: Node
    listen_thread: Thread | None
    periodic_message_thread: Thread | None

    def __init__(
        self, node: Node, host: str = BROADCAST_HOST, port: int = BROADCAST_PORT
    ):
        super().__init__(socket.AF_INET, socket.SOCK_DGRAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.bind((host, port))

        self.node = node
        self.listen_thread = None
        self.periodic_message_thread = None

    def broadcast(self, message: str):
        Broadcaster.broadcast(prefix="", message=message, socket=self)

    def start_listen(self):
        print("Listening...")
        if self.listen_thread is None or not self.listen_thread.is_alive():
            self.listen_thread = Thread(target=self._listen_to_broadcast)
            self.listen_thread.start()

    def parse_message(self, message: BroadcastMessage):
        parser = Parser(message=message)
        if parser.is_pk_broadcast_message:
            # someone broadcasted their pk, so add it to your list
            self.node.add_public_key(message=message["message"])
        elif parser.is_pk_collection_message:
            # someone wants to collect all the pks, so broadcast yours
            Broadcaster.broadcast_public_key(node=self.node, socket=self)
        elif parser.is_sync_clock_message and self.node.is_master:
            # someone wants to synchronize clocks, so master broadcasts his timestamp
            # TODO: sign timestamp with master's private key
            Broadcaster.broadcast_master_clock(node=self.node, socket=self)
        elif parser.is_master_clock_message:
            # master broadcasted his timestamp, so update yours
            # TODO: validate master's signature
            self.node.update_timestamp(message=message["message"])
            self._start_periodic_messaging()

    def _start_periodic_messaging(self):
        if (
            self.periodic_message_thread is None
            or not self.periodic_message_thread.is_alive()
        ):
            self.periodic_message_thread = Thread(
                target=lambda: MessageScheduler.setup_periodic_messaging(
                    node=self.node,
                    task=lambda: Broadcaster.broadcast(
                        prefix=SECURITY_MESSAGE_PREFIX,
                        message=str(self.node.node_number),
                        socket=self,
                    ),
                )
            )
            self.periodic_message_thread.start()

    def _listen_to_broadcast(self):
        while True:
            data, addr = self.recvfrom(1024)
            message = cast(BroadcastMessage, json.loads(data.decode("utf-8")))
            print("\n------------------MESSAGE------------------")
            print(message)
            self.parse_message(message=message)


class Broadcaster:
    @staticmethod
    def broadcast(prefix: str, message: str, socket: BroadcastSocket):
        message = BroadcastMessage(prefix=prefix, message=message)
        bytes = json.dumps(message).encode("utf-8")
        socket.sendto(bytes, ("<broadcast>", BROADCAST_PORT))

    @staticmethod
    def broadcast_public_key(node: Node, socket: BroadcastSocket):
        Broadcaster.broadcast(
            prefix=PUBLIC_KEY_BROADCAST_PREFIX,
            message=node.pk,
            socket=socket,
        )

    @staticmethod
    def collect_public_keys(socket: BroadcastSocket):
        Broadcaster.broadcast(
            prefix=COLLECT_PK_LIST_PREFIX,
            message="",
            socket=socket,
        )

    @staticmethod
    def synchronize_clock(socket: BroadcastSocket):
        Broadcaster.broadcast(
            prefix=SYNCHRONIZE_CLOCK_PREFIX,
            message="",
            socket=socket,
        )

    @staticmethod
    def broadcast_master_clock(node: Node, socket: BroadcastSocket):
        Broadcaster.broadcast(
            prefix=MASTER_CLOCK_PREFIX,
            message=str(node.timestamp),
            socket=socket,
        )


@dataclass
class Parser:
    message: BroadcastMessage
    is_pk_broadcast_message: bool = field(init=False, default=False)
    is_pk_collection_message: bool = field(init=False, default=False)
    is_sync_clock_message: bool = field(init=False, default=False)
    is_master_clock_message: bool = field(init=False, default=False)

    def __post_init__(self):
        if self.message["prefix"] == PUBLIC_KEY_BROADCAST_PREFIX:
            self.is_pk_broadcast_message = True
        elif self.message["prefix"] == COLLECT_PK_LIST_PREFIX:
            self.is_pk_collection_message = True
        elif self.message["prefix"] == SYNCHRONIZE_CLOCK_PREFIX:
            self.is_sync_clock_message = True
        elif self.message["prefix"] == MASTER_CLOCK_PREFIX:
            self.is_master_clock_message = True
