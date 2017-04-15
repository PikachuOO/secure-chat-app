import time

from Message import *
from UDP import *
from Helper import *
from constants import message_type
import exception
import constants as constants
from Cryptographer import Cryptographer
udp = UDP()
cryptographer = Cryptographer()


class ClientKeyChain:
    def __init__(self):
        pass
        self.usernames = {}
        self.address_dict = {}
        self.public_key, self.private_key = cryptographer.create_rsa_pair()
        server_public_key = open(constants.SERVER_PUBLIC_KEY, 'rb')
        self.server_public_key = cryptographer.load_public_key(server_public_key)

    def get_user_from_address(self, address):
        return self.address_dict[address]

    def get_user_from_username(self, username):
        return self.usernames[username]

    def add_user(self, user):
        self.address_dict[user.address] = user
        self.usernames[user.username] = user

    def remove_user(self, user):
        self.address_dict.pop(user.address, None)
        self.usernames.pop(user.username, None)


class ClientUser:
    def __init__(self):
        self.username = None
        self.public_key = None
        self.dh_private_key = None
        self.key = None
        self.address = None
        self.last_recv_msg = 0


class ChatClient:
    def __init__(self, saddr):
        self.saddr = saddr
        self.keychain = ClientKeyChain()
        user = ClientUser()
        user.username = ""
        user.address = self.saddr
        self.keychain.add_user(user)
        self.socket = udp.socket
        self.msg_parser = MessageParser()
        self.username = ""
        self.password_hash = ""
        self.heartbeat_thread = threading.Thread(target=self.heartbeat)
        self.heartbeat_thread.daemon = True
        self.pass_thread = None

    def login(self, username, password):
        if len(username) == 0:
            print "Invalid Username"
            return False

        if len(password) == 0:
            print "Invalid password"
            return False

        self.username = username
        self.password_hash = ""

        if self.pass_thread is not None and self.pass_thread.isAlive():
            self.pass_thread.join()
        self.pass_thread = threading.Thread(target=self.compute_hash, args=(password,))
        self.pass_thread.daemon = True
        self.pass_thread.start()

        try:
            login_msg = Message("Login", self.username)
            msg, address = send_receive_msg(self.socket, self.saddr, login_msg, udp)

            if msg.payload != "Reject":
                if msg.msg_type == "Challenge":
                    challenge_received = msg.payload
                    solution = solve_puzzle(challenge_received)
                    n1 = os.urandom(16)
                    p = self.password_hash
                    my_public_key = cryptographer.public_key_to_bytes(self.keychain.public_key)
                    payload = (str(solution), n1, p, my_public_key)
                    solution = Message(msg_type="Solution", )

                print msg.payload
            return True
        except socket.timeout:
            print "Socket Timed Out, Try Again Later"
            return False
        except exception.SecurityException as e:
            print str(e)
            return False

    @udp.endpoint("test")
    def test(self, msg, addr):
        print "testdfdf"

    def compute_hash(self, password):
        self.password_hash = cryptographer.compute_hash_from_client_password(self.username, password)

    def list(self):

        return None

    def heartbeat(self):
        while True:
            msg= ''
            # msg = Message(message_type["Heartbeat"], payload=(self.username,
            #                                                   "HEARTBEAT"))
            usr = self.keychain.get_user_with_addr(self.saddr)
            # msg = self.converter.sym_key_with_sign(msg, usr.key,
            #                                        self.keychain.private_key)
            send_msg(self.socket, self.saddr, msg)
            time.sleep(constants.SEND_HEARTBEAT_TIMEOUT)


import cli

if __name__ == '__main__':
    cli.run()
