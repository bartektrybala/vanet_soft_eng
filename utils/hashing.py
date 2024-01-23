
def pad_message(message: bytes, target_len: int) -> bytes:
    """
    Pads message to target length one 0x01 byte and 0x00 bytes
    """
    assert len(message) < target_len, "Pad: Message is longer than target length"
    return message + b"\x01" + b"\x00" * (target_len - len(message) - 1)

def unpad_message(message: bytes) -> bytes:
    """
    Unpads message by removing all trailing 0x00 bytes and 0x01 byte
    """
    message = message.rstrip(b"\x00")
    assert message[-1] == 1, "Unpad: Message does not end with 0x01 byte"
    return message[:-1]

def xor_bytes(ba1: bytes, ba2: bytes) -> bytes:
    """
    XORs two byte arrays of equal length
    """
    assert len(ba1) == len(ba2), f'XOR {len(ba1)=} != {len(ba2)=}'

    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

class Hasher:
    def __init__(self, hash_function: callable, hash_length: int):
        self.hash_function = hash_function
        self.hash_length = hash_length

    def compute_hash(self, msg: bytes) -> bytes:
        return self.hash_function(msg).digest()

    def _get_number_of_blocks(self, msg_len: int) -> int:
        num_of_blocks = (msg_len)//self.hash_length
        if msg_len % self.hash_length != 0:
            num_of_blocks += 1

        return num_of_blocks

    def concatenated_hashes(self, msg_len: int, key: bytes) -> bytes:
        num_of_blocks = self._get_number_of_blocks(msg_len)
        int_len = num_of_blocks.bit_length()
        return b''.join(
            self.compute_hash(key + idx.to_bytes(int_len, 'little'))
            for idx in range(num_of_blocks))
