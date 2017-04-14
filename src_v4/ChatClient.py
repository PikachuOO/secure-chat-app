import socket
import getpass
import os
import constants as constants
from Cryptographer import Cryptographer

cryptographer = Cryptographer()

class ClientUser:
    def __init__(self):
        self.username = None
        self.public_key = None
        self.aes_key = None
        self.last_valid_nonce = None
        self.address = None


class ClientKeyChain:
    def __init__(self):
        pass
        self.usernames = {}
        self.address_dict = {}
        self.public_key, self.private_key = cryptographer.create_rsa_pair()
        server_public_key = open(constants.SERVER_PUBLIC_KEY, 'rb')
        self.server_public_key = cryptographer.load_public_key(server_public_key)


class ChatClient:
    def __init__(self, config):
        self.server_address = (config['serverip'], config['serverport'])
        self.my_address = (config['clientip'], config['clientport'])
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.my_address)
        self.keychain = ClientKeyChain()

    def keep_listening(self):
        while True:
            content = self.socket.recvfrom(2**16)
            print content

    def sign_in(self):
        while True:
            un = raw_input("Enter your username: ")
            # pswd = getpass.getpass("Enter your password: ")

            user_details = un
            self.socket.sendto(un, self.server_address)
            if self.sign_in_status(user_details):
                print "Sign in successfull..."
                break
            else:
                print "Sign in failed...please try again"

    def options(self):
        valid_commands = ["list", "send", "exit"]
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

    def sign_in_status(self, user_details):
        return True


def run_client():
    serverip = "127.0.0.1"
    serverport = 8888
    clientip = "127.0.0.1"
    clientport = 5050
    app_config = dict()
    app_config["serverip"] = serverip
    app_config["serverport"] = serverport
    app_config["clientip"] = clientip
    app_config["clientport"] = clientport
    new_client = ChatClient(app_config)
    new_client.sign_in()
    new_client.options()


if __name__ == '__main__':
    run_client()