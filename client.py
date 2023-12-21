from argparse import ArgumentParser, FileType
from io import TextIOWrapper
from typing import cast

from node import Node
from vanet_soft_eng.socket import BroadcastSocket, Broadcaster

parser = ArgumentParser(description="Node in VANET network")
parser.add_argument(
    "--pk", type=FileType("r"), required=True, help="Public key path [PEM format]"
)
args = parser.parse_args()

pk_file = cast(TextIOWrapper, args.pk)
public_key = pk_file.read()

node = Node(pk=public_key)
client = BroadcastSocket(node=node)
client.start_listen()

Broadcaster.collect_public_keys(socket=client)
