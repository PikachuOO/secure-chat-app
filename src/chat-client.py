import constants as constants
from cryptographer import Cryptographer
from udp import UDP
import getpass

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


class CommandLine:
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
        while app_status:
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
    cli = CommandLine(app_config)
    # cli.sign_in()
    cli.options()


if __name__ == "__main__":
    run_client()