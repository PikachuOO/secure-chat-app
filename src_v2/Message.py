import os
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

    def symmetric_encryption(self, msg, sym_key, dest_pub_key):
        iv = os.urandom(16)
        ad = os.urandom(16)
        tag, encrypted_payload = cryptographer.symmetric_encryption(sym_key, iv, msg, ad)
        iv_ad_tag = self.encrypt_with_public_key(dest_pub_key, iv+ad+tag)
        encrypted_message = Message(msg_type= "", payload=encrypted_payload, iv_tag=iv_ad_tag)
        return encrypted_message


    def symmetric_decryption(self, msg, sym_key, my_priv_key):
        aes_enc_payload = msg.payload
        iv_ad_tag_enc = msg.iv_tag
        iv_ad_tag_dec = self.decrypt_with_private_key(my_priv_key, iv_ad_tag_enc)
        iv = iv_ad_tag_dec[0:16]
        ad = iv_ad_tag_dec[16:32]
        tag = iv_ad_tag_dec[32:]
        payload_dec = cryptographer.symmetric_decryption(sym_key, iv, aes_enc_payload, tag, ad)
        return payload_dec
