import pickle
from constants import message_dictionary
from Cryptographer import Cryptographer

cryptographer = Cryptographer()

class Message:
    def __init__(self, msg_type, payload, signature="", timestamp="", iv_tag=""):
        self.msg_type = msg_type
        self.payload = payload
        self.signature = signature
        self.timestamp = timestamp
        self.iv_tag = iv_tag


class MessageParser:

    @staticmethod
    def get_message_type(message):
        message = pickle.loads(message)
        m_type = message['msg_type']
        return message_dictionary[m_type]

class MessageCryptographer:

    def encrypt_with_public_key(self, public_key, msg):
        return cryptographer.rsa_encryption(public_key, msg)

    def decrypt_with_private_key(self, private_key, ct):
        return cryptographer.rsa_decryption(private_key, ct)

    def sign_message(self, private_key, msg):
        return cryptographer.sign_message(private_key, msg)
