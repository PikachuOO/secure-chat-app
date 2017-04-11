import threading, sys, json
import constants as constants
from udp import UDP
from cryptomethods import Cryptographer

udpserver = UDP()
cryptographer = Cryptographer()


class ServerKeySet:
    def __init__(self):
        self.clientnames = {}
        self.address_dict = {}
        server_public_key = open(constants.SERVER_PUBLIC_KEY, 'rb')
        server_private_key = open(constants.SERVER_PRIVATE_KEY, 'rb')
        self.public_key = cryptographer.load_public_key(server_public_key)
        self.private_key = cryptographer.load_private_key(server_private_key)

    def add_client(self, client):
        self.address_dict[client.address] = client
        self.clientnames[client.username] = client

    def list_clients(self):
        return self.clientnames

class ChatServer:
    def __init__(self):
        self.socket = udpserver.socket
        self.keychain = ServerKeySet()




class LoadServer:
    def __init__(self):
        self.serverip = None
        self.serverport = None
        self.live_threads = None

    def getserverdetails(self, filename):
        server_file = open(filename)
        try:
            server_cred = json.load(server_file)
            self.serverip = server_cred['server-ip']
            self.serverport = server_cred['server-port']
            self.live_threads = server_cred['live-threads']
        except:
            print "Error in Server Config file"


def run_server():
    args = sys.argv
    try:
        if len(args) != 2:
            server_config = LoadServer()
            server_config.getserverdetails(constants.SERVER_CONFIG_FILE)
    except:
        print "Please start the server properly"





if __name__ == "__main__":
    run_server()