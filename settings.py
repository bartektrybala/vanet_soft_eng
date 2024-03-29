BROADCAST_HOST = ""
BROADCAST_PORT = 50000

PUBLIC_KEYS_FOLDER = "./public_keys"
PUBLIC_KEY_FILE_FORMAT = "public_key_{}.pem"

SECRET_KEYS_FOLDER = "./secret_keys"
SECRET_KEY_FILE_FORMAT = "secret_key_{}.pem"

MESSAGE_INTERVAL = 10
LISTEN_THREAD_TIMEOUT = 5.0

PUBLIC_KEY_BROADCAST_PREFIX = "PUBLIC_KEY_BROADCAST_PREFIX##"
COLLECT_PK_LIST_PREFIX = "COLLECT_PK_LIST_PREFIX##"
SYNCHRONIZE_CLOCK_PREFIX = "SYNCHRONIZE_CLOCK_PREFIX##"
SECURITY_MESSAGE_PREFIX = "SECURITY_MESSAGE_PREFIX##"
MASTER_CLOCK_PREFIX = "MASTER_CLOCK_PREFIX##"
NODE_DISCONNECT_PREFIX = "NODE_DISCONNECT_PREFIX##"

# Specified as a dictionary of dictionaries for extensibility
# Messages are defined by their prefix
MESSAGE_DATA = {
    PUBLIC_KEY_BROADCAST_PREFIX: {"message_fmt": "{node_pks}"},
    COLLECT_PK_LIST_PREFIX: {"message_fmt": ""},
    SYNCHRONIZE_CLOCK_PREFIX: {"message_fmt": ""},
    SECURITY_MESSAGE_PREFIX: {"message_fmt": "{node_data}"},
    MASTER_CLOCK_PREFIX: {"message_fmt": "{timestamp}"},
    NODE_DISCONNECT_PREFIX: {"message_fmt": "{node_pks}"},
}
