import signal
import sys
from argparse import ArgumentParser, FileType

from broadcast import Broadcaster, BroadcastSocket
from node import Node
from secrecy import SecrecyEngine
from settings import (
    COLLECT_PK_LIST_PREFIX,
    PUBLIC_KEY_FILE_FORMAT,
    PUBLIC_KEYS_FOLDER,
    SECRET_KEY_FILE_FORMAT,
    SECRET_KEYS_FOLDER,
    SYNCHRONIZE_CLOCK_PREFIX,
)

# from io import TextIOWrapper
# from typing import cast


client: BroadcastSocket | None = None


def signal_handler(sig, frame):
    global client
    if client is None:
        print("Interrupted by user, stopping the main thread...")
        sys.exit(0)
    else:
        print("Interrupted by user, informing other nodes and stopping threads...")
        client.stop_threads_and_close()
        sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    parser = ArgumentParser(description="Node in VANET network")

    # Either --pki or --pkp must be provided.
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pkp", type=FileType("r"), help="Public key path [PEM format]")
    group.add_argument(
        "--pki",
        type=int,
        help="Public key index."
        "Will read the public key from ./keys/public_key<index>.pem",
    )

    args = parser.parse_args()
    if args.pki is not None:
        keys_index = args.pki
        public_key_file = (
            f"{PUBLIC_KEYS_FOLDER}/{PUBLIC_KEY_FILE_FORMAT.format(keys_index)}"
        )
        secret_key_file = (
            f"{SECRET_KEYS_FOLDER}/{SECRET_KEY_FILE_FORMAT.format(keys_index)}"
        )
    else:
        # [TODO] fix the flag
        # pk_file = cast(TextIOWrapper, args.pk)
        # public_key = pk_file.read()
        # Inform the user that the flag is not currently supported and that
        # they should provide the index instead
        print(
            "This flag is not currently supported. "
            "Please provide the index of the public key instead, e.g --pki 1."
        )
        exit(1)

    global client
    secrecy_engine = SecrecyEngine(
        secret_key_path=secret_key_file, public_key_path=public_key_file
    )
    secrecy_engine.gen_session_keys()
    print(f"Session public key: {secrecy_engine.get_session_pk_as_int()}")

    node = Node(secrecy_engine=secrecy_engine)
    client = BroadcastSocket(node=node)
    client.start_listen()

    Broadcaster.broadcast(prefix=COLLECT_PK_LIST_PREFIX, socket=client)
    Broadcaster.broadcast(prefix=SYNCHRONIZE_CLOCK_PREFIX, socket=client)


if __name__ == "__main__":
    main()
