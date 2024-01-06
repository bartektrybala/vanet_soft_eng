BROADCAST_HOST = ""
BROADCAST_PORT = 50000

KEYS_FOLDER = "./keys"
KEYFILE_FORMAT = "public_key{}.pem"

MESSAGE_INTERVAL = 10

PUBLIC_KEY_BROADCAST_PREFIX = "PUBLIC_KEY_BROADCAST_PREFIX#"
COLLECT_PK_LIST_PREFIX = "COLLECT_PK_LIST_PREFIX#"
SYNCHRONIZE_CLOCK_PREFIX = "SYNCHRONIZE_CLOCK_PREFIX#"
SECURITY_MESSAGE_PREFIX = "SECURITY_MESSAGE_PREFIX#"
MASTER_CLOCK_PREFIX = "MASTER_CLOCK_PREFIX#"

# Specified as a dictionary of dictionaries for extensibility
# Messages are defined by their prefix
MESSAGE_DATA = {
    PUBLIC_KEY_BROADCAST_PREFIX: {"message_fmt": "{node_pk}"},
    COLLECT_PK_LIST_PREFIX: {"message_fmt": ""},
    SYNCHRONIZE_CLOCK_PREFIX: {"message_fmt": ""},
    SECURITY_MESSAGE_PREFIX: {"message_fmt": "{node_number}"},
    MASTER_CLOCK_PREFIX: {"message_fmt": "{timestamp}"},
}
