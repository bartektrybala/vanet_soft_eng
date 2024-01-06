from argparse import ArgumentParser, FileType
from io import TextIOWrapper
from typing import cast

from broadcast import Broadcaster, BroadcastSocket
from node import Node
from settings import (
    KEYS_FOLDER,
    KEYFILE_FORMAT,
    COLLECT_PK_LIST_PREFIX,
    SYNCHRONIZE_CLOCK_PREFIX,
)


def get_key(key_idx: int) -> str:
    """
    Provides a "lazier" way to get the public key from the file using the
    node's index.
    """
    print(f"Getting key from file {KEYS_FOLDER}/{KEYFILE_FORMAT.format(key_idx)}")
    try:
        with open(f"{KEYS_FOLDER}/{KEYFILE_FORMAT.format(key_idx)}", "r") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"Could not find key file {KEYS_FOLDER}/{KEYFILE_FORMAT.format(key_idx)}")
        exit(1)


def main():
    parser = ArgumentParser(description="Node in VANET network")

    # Either --pki or --pk must be provided.
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
        public_key = get_key(args.pki)
    else:
        pk_file = cast(TextIOWrapper, args.pk)
        public_key = pk_file.read()

    node = Node(pk=public_key)
    client = BroadcastSocket(node=node)
    client.start_listen()

    Broadcaster.broadcast(prefix=COLLECT_PK_LIST_PREFIX, socket=client)
    Broadcaster.broadcast(prefix=SYNCHRONIZE_CLOCK_PREFIX, socket=client)


if __name__ == "__main__":
    main()
