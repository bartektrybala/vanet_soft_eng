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
    LISTEN_THREAD_TIMEOUT,
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
        # Stop blocking for a moment every 5 seconds - needed to stop the thread in
        # case of KeyboardInterrupt and some code failure
        self.settimeout(LISTEN_THREAD_TIMEOUT)

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

        node_pks = self.node.session_pk1_str + "#" + self.node.session_pk2_str
        Broadcaster.broadcast(
            prefix=NODE_DISCONNECT_PREFIX, socket=self, node_pks=node_pks
        )
        self.close()

    def start_listen(self):
        print("Listening...")
        if self.listen_thread is None or not self.listen_thread.is_alive():
            self.listen_thread = Thread(target=self._listen_to_broadcast)
            self.listen_thread.start()

    def _listen_to_broadcast(self):
        while not self.stop_threads:
            try:
                # [TODO] Read as until the string termination is found
                # otherwise will break for longer key lists
                data, addr = self.recvfrom(16384)
                print(f"\n------------------MESSAGE FROM {addr} ------------------")
                message = cast(BroadcastMessage, json.loads(data.decode("utf-8")))
                print(message)
                self._handle_message(message=message)
            except socket.timeout:
                # Give the thread a chance to stop if it was interrupted
                pass

    def _handle_message(self, message: BroadcastMessage):
        message_prefix = message["prefix"]
        if message_prefix == PUBLIC_KEY_BROADCAST_PREFIX:
            # someone broadcasted their pk, so add it to your list
            # Split the message into two pks
            node_pks = message["message"].split("#")
            self.node.add_public_key(node_pks[0], node_pks[1])
        elif message_prefix == COLLECT_PK_LIST_PREFIX:
            # someone wants to collect all the pks, so broadcast yours
            node_pks = self.node.session_pk1_str + "#" + self.node.session_pk2_str
            Broadcaster.broadcast(
                prefix=PUBLIC_KEY_BROADCAST_PREFIX,
                socket=self,
                node_pks=node_pks,
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
            node_pks = message["message"].split("#")
            self.node.remove_public_key(node_pks[0], node_pks[1])

    def _start_periodic_messaging(self):
        if (
            self.periodic_message_thread is None
            or not self.periodic_message_thread.is_alive()
        ):
            self.periodic_message_thread = Thread(
                target=lambda: self._periodic_messaging_thread(
                    task=lambda: self._periodic_messaging_task()
                )
            )
            self.periodic_message_thread.start()

    def _periodic_messaging_task(self):
        # [TODO] should not send its node number but some message
        data_to_sign = str(self.node.node_number) + "##" + str(self.node.timestamp)

        # Sign the message using the ring signature
        public_keys2_as_bytes = [
            bytes(str(pk), "utf-8") for pk in self.node.public_keys_g2
        ]

        signatures, main_sig_index = self.node.secrecy_engine.ring_sign(
            message=bytes(data_to_sign, "utf-8"), public_keys_g2=public_keys2_as_bytes
        )

        public_keys2_as_bytes.insert(main_sig_index, self.node.session_pk2_str)
        shuffled_pks, indices = self.node.secrecy_engine.secure_shuffle(
            public_keys2_as_bytes
        )
        for i in range(len(signatures)):
            signatures[i] = signatures[indices[i]]

        # Create a string of the whole array using a join
        # [TODO] DO NOT SEND whole keys, can send indices instead
        signatures_as_str = "#".join([str(sig) for sig in signatures])
        pks_as_str = "#".join([str(pk) for pk in shuffled_pks])

        node_data =  data_to_sign + "##" + signatures_as_str + "##" + pks_as_str
        Broadcaster.broadcast(
            prefix=SECURITY_MESSAGE_PREFIX,
            socket=self,
            node_data=node_data,
        )

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
