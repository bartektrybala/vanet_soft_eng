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
    DELAYER_MESSAGE_PREFIX,
)


class BroadcastMessage(TypedDict):
    prefix: str
    message: str
    received_from: str
    bytes_msg: bytes


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
                data, addr = self.recvfrom(32768)
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
                received_from = self.node.node_id,
            )
        elif message_prefix == SYNCHRONIZE_CLOCK_PREFIX:
            # someone wants to synchronize clocks, so master broadcasts his timestamp
            # TODO: sign timestamp with master's private key
            if self.node.is_master:
                Broadcaster.broadcast(
                    prefix=MASTER_CLOCK_PREFIX,
                    socket=self,
                    timestamp=str(self.node.timestamp),
                    received_from = self.node.node_id,
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
        elif message_prefix == SECURITY_MESSAGE_PREFIX:
            if self.node.node_number == len(self.node.public_keys_g1):
                message_ = message["message"].split("#####")
                ctext = message_[0]
                eph_list = message_[1:]
                self.node.onion_list.append((ctext, eph_list, message["received_from"]))
                if len(self.node.onion_list) == len(self.node.public_keys_g1):
                    print("Received all cipher text")
                    print(f"Onion list length: {len(self.node.onion_list)}")
                    self.delayer(len(self.node.public_keys_g1))
        elif message_prefix == DELAYER_MESSAGE_PREFIX:

            
            message = message['message'].split("###")
            delayer_node_id = int(message[0])
            self.node.onion_list = [(message[mes], message[mes + 1].split("##"), message[mes + 2]) for mes in range(1, 3, len(message[1:]) + 1)]
            if self.node.node_number == delayer_node_id:
                self.delayer(delayer_node_id)
                if self.node.node_number == 1:
                    c_list = [onion[0] for onion in self.node.onion_list]
                    self.verify(c_list)
                self.node.onion_list.clear()
                
    def verify(self, c_list):
        for c in c_list:
            print("-----------WERYFIKACJA PODPISU---------")
            # print(f"data = {str(bytes.fromhex(c))}")
            c = bytes.fromhex(c)
            data = c.split(b'#')
            # print(f"{data[0]=}")
            # print(f"{data[0].hex()=}")
            message = data[0]
            # print(f"{message=}")
            # print(data)
            signatures = [eval(d.decode('utf-8')) for d in data[1:len(self.node.public_keys_g1)+1]]
            keys = [eval(d.decode('utf-8')) for d in data[len(self.node.public_keys_g1)+1:]]
            # print(keys)
            # print(signatures)
            # print(f"{len(keys)=}")
            # print(f"{len(signatures)=}")
            verified = self.node.secrecy_engine.ring_verify(message, signatures, keys)
            print(f"message: {message}, verification: {verified}")
        
    def delayer(self, delayer_node_id):
        print(f"ROZPOCZYNAM ZDEJMOWANIE LAYERA NUMER {delayer_node_id}")
        for i in range(len(self.node.onion_list)):
            onion_structure = self.node.onion_list[i]
            print(onion_structure)
            ctext = onion_structure[0]
            eph = onion_structure[1][-1]
            print(f"EPH= {eph}")
            sender_id = int(onion_structure[2])
            # print(f"Bytes of ctext: {bytes.fromhex(ctext)}")
            # print(f"Bytes of eph: {bytes.fromhex(eph)}")
            self.node.onion_list[i] \
                = (self.node.secrecy_engine.decrypt_hash_elgamal(bytes.fromhex(eph), bytes.fromhex(ctext)).hex(), onion_structure[1][:1], sender_id)
            # decrypted = self.node.secrecy_engine.decrypt_hash_elgamal(bytes(str(self.node.secrecy_engine.secret_key), "utf-8"), ctext.encode('ISO-8859-1'))
            # print(self.node.secrecy_engine.secret_key)
            print(f"decrypted: { self.node.onion_list[i]}")
            print(f'ITERACJA: {sender_id}')
        self.node.onion_list, _ = self.node.secrecy_engine.secure_shuffle(self.node.onion_list)
        node_data = str(delayer_node_id - 1) + "###" + "###".join(onion[0] + "###" + "##".join(str(o) for o in onion[1]) + "###" + str(onion[2]) for onion in self.node.onion_list)
        # print("SZUFLA PRZESZLA")
        Broadcaster.broadcast(
            prefix=DELAYER_MESSAGE_PREFIX,
            socket=self,
            node_data=node_data,
            received_from = self.node.node_id,
        )

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
        data_to_sign = str(self.node.node_number) + "-" + str(self.node.timestamp)
        
        # Sign the message using the ring signature
        public_keys2_as_bytes = [
            int.to_bytes(pk, (pk.bit_length() + 7)//8, byteorder="big") for pk in self.node.public_keys_g2
        ]

        public_keys1_as_bytes = [
            int.to_bytes(pk, (pk.bit_length() + 7)//8, byteorder="big") for pk in self.node.public_keys_g1
        ]
        key: int= self.node.session_pk2_int
        public_keys2_as_bytes.remove(int.to_bytes(key, (key.bit_length() + 7)//8, byteorder="big"))
        
        # for pk in self.node.public_keys_g2:
        #     if pk != self.node.secrecy_engine.get_session_pk2_as_int:
        #         public_keys1_as_bytes.append(int.to_bytes(pk, (pk.bit_length() + 7)//8, byteorder="big"))

        signatures, main_sig_index = self.node.secrecy_engine.ring_sign(
            message=bytes(data_to_sign, "utf-8"), public_keys_g2=public_keys2_as_bytes
        )
        
        public_keys2_as_bytes.insert(main_sig_index, self.node.session_pk2_str.encode('utf-8'))
        shuffled_pks, indices = self.node.secrecy_engine.secure_shuffle(
            public_keys2_as_bytes
        )
        for i in range(len(signatures)):
            signatures[i] = signatures[indices[i]]
        print(shuffled_pks)
        print(signatures)
        print(f"{len(shuffled_pks)=}")
        print(f"{len(signatures)=}")
        signature = data_to_sign + "#" + "#".join([str(sig) for sig in signatures]) + "#" + "#".join(str(pk) for pk in shuffled_pks)
        eph_list = []
        onion_encrypt = bytes(signature, "utf-8")
        print(f"Data to encrypt {onion_encrypt}" )
        for i in range(len(self.node.public_keys_g1)):
            # print(f"{onion_encrypt=}")
            eph, onion_encrypt = self.node.secrecy_engine.encrypt_hash_elgamal(onion_encrypt, public_keys1_as_bytes[i])
            eph_list.append(eph)
           
        print("WYSYLAM C")
            # try: 
            #     print(f"{eph=}")
            #     print(f"{onion_encrypt=}")
            #     self.node.secrecy_engine.decrypt_hash_elgamal(eph, onion_encrypt)
            #     print("DECRYPT PASSED")
            # except:
            #     print("DECRYPT FAILED")
            # print(f"{i}th onion encryption, {self.node.node_number} node number, current onion_encrypt: {onion_encrypt}")
            # print(f"encrypted iteraton {i} with key {public_keys1_as_bytes[i]}")
        
        # print(f"Full onion encrypt {onion_encrypt} ")
        # print("EPH_DATA")
        # print(eph_list)

        data_to_send = onion_encrypt.hex() + "#####" + "#####".join(eph.hex() for eph in eph_list)
        # print("DATA TO SEND")
        # print(data_to_send)
        
        

        # onion_encrypt = str(onion_encrypt, encoding='ascii')
        # self.node.secrecy_engine.decrypt_hash_elgamal(bytes(str(self.node.secrecy_engine.secret_key), "utf-8"), onion_encrypt)


        # Create a string of the whole array using a join
        # [TODO] DO NOT SEND whole keys, can send indices instead
        # signatures_as_str = "#".join([str(sig) for sig in signatures])
        # pks_as_str = "#".join([str(pk) for pk in shuffled_pks])

        # node_data =  data_to_sign + "##" + signatures_as_str + "##" + pks_as_str
        Broadcaster.broadcast(
            prefix=SECURITY_MESSAGE_PREFIX,
            socket=self,
            node_data=data_to_send,
            received_from = self.node.node_number,
        )

    def _periodic_messaging_thread(self, task: Callable):
        while not self.stop_threads:
            self.scheduler.enterabs(
                time=self.node.next_message_timestamp, priority=1, action=task
            )
            self.scheduler.run()


class Broadcaster:
    @staticmethod
    def broadcast(prefix: str, socket: BroadcastSocket, received_from: str, **kwargs):
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

        message = BroadcastMessage(prefix=prefix, message=message, received_from = received_from)
        bytes = json.dumps(message).encode("utf-8")
        socket.sendto(bytes, ("<broadcast>", BROADCAST_PORT))
