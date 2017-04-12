import constants as constants
from constants import message_type
from cryptographer import Cryptographer
from message import *
from udp import UDP
import getpass, threading, socket

app_status = True
udpserver = UDP()
cryptographer = Cryptographer()


class ClientReceiver:
    def __init__(self):
        self.username = None
        self.public_key = None
        self.dh_private_key = None
        self.aes_key = None
        self.address = None
        self.last_msg = 0


class ClientKeySet:
    def __init__(self):
        self.clientnames = {}
        self.address_dict = {}
        self.public_key, self.private_key = cryptographer.create_rsa_pair()
        server_public_key = open(constants.SERVER_PUBLIC_KEY, 'rb')
        self.server_public_key = cryptographer.load_public_key(server_public_key)
        self.server_dh_key = None

    def add_client(self, client):
        self.address_dict[client.address] = client
        self.clientnames[client.username] = client

    def list_clients(self):
        return self.clientnames

    def remove_client(self, client):
        self.address_dict.pop(client.address, None)
        self.clientnames.pop(client.username, None)


class CommandLineClient:
    def __init__(self, app_config):
        serverip = app_config["serverip"]
        serverport = app_config["serverport"]
        self.new_client = ChatClient((serverip, serverport))
        udpserver.start_udp(self.new_client, app_config["clientip"], app_config["clientport"], 1)

    def sign_in(self):
        while True:
            un = raw_input("Enter your username: ")
            pswd = getpass.getpass("Enter your password: ")
            userdetails = (un, pswd)
            if self.new_client.sign_in(userdetails):
                print "Sign in successfull..."
                break
            else:
                print "Sign in failed...please try again"

    def options(self):
        valid_commands = ["list", "send", "exit"]
        global app_status
        print "Welcome to chat..\n"
        print "Enter your commnand \n"
        print "1. list\n2. send USER MESSAGE\n3. exit"
        while True:
            user_input = raw_input()
            user_input = user_input.split(" ", 2)
            main_command = user_input[0]
            if main_command in valid_commands:
                if main_command == valid_commands[0]:
                    lst = self.new_client.get_client_list()
                    if lst is None:
                        print "Failed in getting the list"
                        continue
                    if len(lst) > 0:
                        list_of_clients = " ".join(lst)
                        print list_of_clients
                    else:
                        print "No one else loggedin..please try later"
                elif main_command == valid_commands[1]:
                    if len(user_input) == 3:
                        receiver = user_input[1]
                        message = user_input[2]
                        self.new_client.send_message(receiver, message)
                    else:
                        print "User and message missing..."
                elif main_command == valid_commands[2]:
                    self.new_client.app_logout()
                    print "Closing the application..."
            else:
                print "Please Enter a valid command"


class ChatClient:
    def __init__(self, server_address):
        self.socket = udpserver.socket
        self.server_address = server_address
        self.keychain = ClientKeySet()
        client = ClientReceiver()
        client.username = ""
        client.address = self.server_address
        self.keychain.add_client(client)
        self.username = ""
        self.password_hash = ""
        self.m_cryptographer = MessageCryptographer()

    def sign_in(self, user_details):
        username, password = user_details
        if len(username) == 0:
            print "Please enter a valid username"
        if len(password) == 0:
            print "Password cannot be empty"
        self.username = username

        if self.password_thread is not None and self.password_thread.isAlive():
            self.password_thread.join()
        self.password_thread = threading.Thread(target=self.get_password_hash,
                                              args=(password,))
        self.password_thread.daemon = True
        self.password_thread.start()
        message = Message(message_type=message_type['SIGN_IN'], payload=(self.username))
        message = self.m_cryptographer.plain_message(message)
        try:
            message, address = helper.send_recv_msg(self.socket, udpserver, self.server_address, message)
            return True
        except socket.timeout:
            print "Timeout, please try again"
            return False

    def get_password_hash(self, password):
        self.password_hash = cryptographer.compute_hash_from_client_password(self.password_hash, password)




def run_client():
    serverip = "127.0.0.1"
    serverport = 9090
    clientip = "127.0.0.1"
    clientport = 5050
    app_config = dict()
    app_config["serverip"] = serverip
    app_config["serverport"] = serverport
    app_config["clientip"] = clientip
    app_config["clientport"] = clientport
    cli_client = CommandLineClient(app_config)
    # cli_client.sign_in()
    cli_client.options()


if __name__ == "__main__":
    run_client()