import socket

class ServerUser:
    def __init__(self):
        self.username = None
        self.password_hash = None
        self.aes_key = None
        self.last_valid_nonce = None
        self.public_key = None
        self.address = None


class ServerKeyChain:
    def __init__(self):
        pass
        self.usernames = {}
        self.address_dict = {}
        self.public_key = None
        self.private_key = None


class ChatServer:
    def __init__(self, server_ip, server_port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((server_ip, server_port))
        self.keychain = ServerKeyChain()

    def keep_listenting(self):
        while 1:
            content = self.socket.recvfrom(2**16)
            print content[0]


def run_server():
    server_ip = ''
    server_port = 8888
    new_server = ChatServer(server_ip=server_ip, server_port=server_port)
    new_server.keep_listenting()

if __name__ == '__main__':
    run_server()