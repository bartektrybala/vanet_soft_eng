from __future__ import annotations

import json
import socket
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
    MESSAGE_DATA,
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

    def handle_message(self, message: BroadcastMessage):
        message_prefix = message["prefix"]
        if message_prefix == PUBLIC_KEY_BROADCAST_PREFIX:
            # someone broadcasted their pk, so add it to your list
            self.node.add_public_key(message=message["message"])
        elif message_prefix == COLLECT_PK_LIST_PREFIX:
            # someone wants to collect all the pks, so broadcast yours
            Broadcaster.broadcast(
                prefix=PUBLIC_KEY_BROADCAST_PREFIX,
                socket=self,
                node_pk=self.node.pk,
            )
        elif message_prefix == SYNCHRONIZE_CLOCK_PREFIX:
            # someone wants to synchronize clocks, so master broadcasts his timestamp
            # TODO: sign timestamp with master's private key
            Broadcaster.broadcast(
                prefix=MASTER_CLOCK_PREFIX,
                socket=self,
                timestamp=str(self.node.timestamp),
            )
        elif message_prefix == MASTER_CLOCK_PREFIX:
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
                        socket=self,
                        node_number=str(self.node.node_number),
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
            self.handle_message(message=message)


class Broadcaster:
    @staticmethod
    def broadcast(prefix: str, socket: BroadcastSocket, **kwargs):
        message_format = MESSAGE_DATA[prefix].get("message_fmt")
        if message_format:
            try:
                message = message_format.format(**kwargs)
            except KeyError:
                print(
                    f'Message format "{message_format}" could not be formatted. '
                    f"Broadcast with prefix {prefix} failed."
                )
                return
        else:
            if kwargs:
                print(
                    f'Message format is "{message_format}" but some message was provided: {kwargs}. '
                    f"Broadcast with prefix {prefix} failed."
                )
                return
            message = ""

        message = BroadcastMessage(prefix=prefix, message=message)
        bytes = json.dumps(message).encode("utf-8")
        socket.sendto(bytes, ("<broadcast>", BROADCAST_PORT))
