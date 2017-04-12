import os, struct, time, helper
import constants as constansts
from cryptographer import Cryptographer


class Message:
    def __init__(self, message_type, time_stamp="", key="", signature="", payload=""):
        self.message_type = message_type
        self.key = key
        self.time_stamp = time_stamp
        self.payload = payload
        self.signature = signature

    def __str__(self):
        message_type = struct.pack("!B", self.message_type)
        time_stamp = struct.pack("!L", self.time_stamp)
        return message_type + self.key + self.signature + time_stamp + self.payload


class MessageCryptographer:

    def plain_message(self, message):
        if message.payload != "":
            message.payload = helper.string_from_tuple(message.payload)
        message.timestamp = helper.get_time()
        return message


