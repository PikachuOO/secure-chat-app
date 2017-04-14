import pickle
from constants import message_dictionary


class MessageParser:
    # Get Message Type
    @staticmethod
    def get_message_type(message):
        message = pickle.loads(message)
        m_type = message['type']
        return message_dictionary[m_type]
