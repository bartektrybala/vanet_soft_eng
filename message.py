import time

from settings import MESSAGE_INTERVAL


class MessageTimeGenerator:
    def __init__(self, timestamp: float):
        self.timestamp = timestamp

    def __next__(self) -> float:
        while self.timestamp + MESSAGE_INTERVAL < time.time():
            self.timestamp += MESSAGE_INTERVAL
        return self.timestamp + MESSAGE_INTERVAL
