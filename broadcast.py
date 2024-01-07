from __future__ import annotations

import json
import sched
import socket
import time
from threading import Thread
from typing import Callable, TypedDict, cast

from rich import print

from node import Node
from settings import (
    BROADCAST_HOST,
    BROADCAST_PORT,
    COLLECT_PK_LIST_PREFIX,
    MASTER_CLOCK_PREFIX,
    MESSAGE_DATA,
    NODE_DISCONNECT_PREFIX,
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
    scheduler: sched.scheduler
    stop_threads: bool = False

    def __init__(
        self, node: Node, host: str = BROADCAST_HOST, port: int = BROADCAST_PORT
    ):
        # Use IPv4 and UDP
        super().__init__(socket.AF_INET, socket.SOCK_DGRAM)

        # SOL_SOCKET specifies that parameters are set at the socket layer itself
        # and e.g. not at the TCP layer
        # Allow multiple application to listen to the same port
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        # Allow broadcast
        self.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.bind((host, port))

        self.node = node
        # Each socket has its own scheduler
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.listen_thread = None
        self.periodic_message_thread = None

    def stop_threads_and_close(self):
        self.stop_threads = True

        if self.listen_thread is not None:
            # Will wait one MESSAGE_INTERVAL since it is blocked on recvfrom
            print("Waiting for listen thread to finish...")
            self.listen_thread.join()
        if self.periodic_message_thread is not None:
            print("Waiting for periodic message thread to finish...")
            self.periodic_message_thread.join()

        Broadcaster.broadcast(
            prefix=NODE_DISCONNECT_PREFIX, socket=self, node_pk=self.node.pk
        )
        self.close()

    def start_listen(self):
        print("Listening...")
        if self.listen_thread is None or not self.listen_thread.is_alive():
            self.listen_thread = Thread(target=self._listen_to_broadcast)
            self.listen_thread.start()

    def _listen_to_broadcast(self):
        while not self.stop_threads:
            data, addr = self.recvfrom(1024)
            message = cast(BroadcastMessage, json.loads(data.decode("utf-8")))
            print("\n------------------MESSAGE------------------")
            print(message)
            self._handle_message(message=message)

    def _handle_message(self, message: BroadcastMessage):
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
        elif message_prefix == NODE_DISCONNECT_PREFIX:
            # someone wants to disconnect, so remove their pk from your list
            self.node.remove_public_key(message=message["message"])

    def _start_periodic_messaging(self):
        if (
            self.periodic_message_thread is None
            or not self.periodic_message_thread.is_alive()
        ):
            self.periodic_message_thread = Thread(
                target=lambda: self._periodic_messaging_thread(
                    task=lambda: Broadcaster.broadcast(
                        prefix=SECURITY_MESSAGE_PREFIX,
                        socket=self,
                        node_number=str(self.node.node_number),
                    ),
                )
            )
            self.periodic_message_thread.start()

    def _periodic_messaging_thread(self, task: Callable):
        while not self.stop_threads:
            self.scheduler.enterabs(
                time=self.node.next_message_timestamp, priority=1, action=task
            )
            self.scheduler.run()


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
                    f'Message format is "{message_format}" but some message'
                    f"was provided: {kwargs}. "
                    f"Broadcast with prefix {prefix} failed."
                )
                return
            message = ""

        message = BroadcastMessage(prefix=prefix, message=message)
        bytes = json.dumps(message).encode("utf-8")
        socket.sendto(bytes, ("<broadcast>", BROADCAST_PORT))
