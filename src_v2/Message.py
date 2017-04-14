import pickle
from constants import message_dictionary

class Message:
    def __init__(self, msg_type, payload):
        self.msg_type = msg_type
        self.payload = payload



class MessageParser:

    @staticmethod
    def get_message_type(message):
        message = pickle.loads(message)
        m_type = message['msg_type']
        return message_dictionary[m_type]
