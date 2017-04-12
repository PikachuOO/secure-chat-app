import threading, time, os, struct, json
import constants as constants
from message import MessageCryptographer
from udp import UDP
from cryptographer import Cryptographer
import helper

udpserver = UDP()
cryptographer = Cryptographer()
app_status = True


class ServerReceiver:
    def __init__(self):
        self.username = None
        self.password_hash = None
        self.address = None
        self.public_key = None
        self.aes_key = None
        self.salt = None
        self.last_alive_time = None  # The Timestamp of the Last Heartbeat Received
        self.last_list_recv = 0


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

    def remove_client(self, client):
        self.address_dict.pop(client.address, None)
        self.clientnames.pop(client.username, None)


class ChatServer:
    def __init__(self):
        self.socket = udpserver.socket
        self.keychain = ServerKeySet()
        self.m_cryptographer = MessageCryptographer()
        self.puzzle = None
        self.nonce_list = {}
        self.puzzle_thread = threading.Thread(target=self.generate_puzzle)
        self.puzzle_thread.daemon = True
        self.puzzle_thread.start()
        self.check_live_clients_thread = threading.Thread(target=self.check_live_clients)
        self.check_live_clients_thread.daemon = True
        self.check_live_clients_thread.start()

    def generate_puzzle(self):
        while True:
            t_now = time.time()
            n1 = os.urandom(16)
            diff = chr(1)
            valid_till = long(t_now + 60)
            packed_valid_till = struct.pack("!L", valid_till)
            signature = cryptographer.sign_message(self.keychain.private_key, packed_valid_till+diff+n1)
            self.puzzle = (packed_valid_till, diff, n1, signature)
            self.nonce_list = {}
            time.sleep(60)

    def check_live_clients(self):
        while True:
            logged_out_users = []
            time1 = helper.get_time()
            for eachuser in self.keychain.list_clients().itervalues():
                if eachuser.last_alive_time is not None and helper.get_time() >= eachuser.last_alive_time:
                    logged_out_users.append(eachuser)
                    print eachuser.username + " is logged out"

            for eachuser in logged_out_users:
                self.keychain.remove_client(eachuser)
                self.broadcast_logout(eachuser)
            time2 = helper.get_time()
            if 5 - (time2 - time1) > 0:
                time.sleep(5 - (time2 - time1))

    def broadcast_logout(self, client):
        return None


class LoadServerDetails:
    def __init__(self, filename):
        self.serverip = None
        self.serverport = None
        self.live_threads = None
        self.filename = filename

    def getserverdetails(self):
        server_file = open(self.filename)
        try:
            server_cred = json.load(server_file)
            self.serverip = server_cred['server-ip']
            self.serverport = server_cred['server-port']
            self.live_threads = server_cred['live-threads']
        except:
            print "Error in Server Config file"


class CommandLineServer:
    def __init__(self, app_config):
        serverip = app_config["serverip"]
        serverport = app_config["serverport"]
        live_threads = app_config['live_threads']
        self.new_server = ChatServer()
        udpserver.start_udp(self.new_server, serverip, serverport, live_threads)


def run_server():

    serverip = "127.0.0.1"
    serverport = 9090
    app_config = dict()
    app_config["serverip"] = serverip
    app_config["serverport"] = serverport
    app_config["live_threads"] = 5
    cli_server = CommandLineServer(app_config)
    print "Server Started and Running...."
    cli_server.new_server.check_live_clients_thread.join()



if __name__ == "__main__":
    run_server()