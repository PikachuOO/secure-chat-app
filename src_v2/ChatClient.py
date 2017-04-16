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
        self.dh_private_key, self.dh_public_key = cryptographer.get_dh_pair()

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
        self.aes_key = None
        self.address = None
        self.last_recv_msg = 0
        self.nonces_used = []


class ChatClient:
    def __init__(self, server_address):
        self.server_address = server_address
        self.keychain = ClientKeyChain()
        user = ClientUser()
        user.username = ""
        user.address = self.server_address
        self.keychain.add_user(user)
        self.socket = udp.socket
        self.msg_parser = MessageParser()
        self.msg_cryptographer = MessageCryptographer()
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
            login_msg = Message("Login", payload=self.username)
            msg, address = send_receive_msg(self.socket, self.server_address, login_msg, udp)

            if msg.msg_type != "Reject":
                if msg.msg_type == "Challenge":
                    n1 = msg.payload[2]
                    challenge_received = (msg.payload[0], msg.payload[1])
                    n2 = os.urandom(16)
                    server_user = ClientUser()
                    server_user.public_key = self.keychain.server_public_key
                    server_user.address = self.server_address
                    server_user.nonces_used.append(n2)
                    self.keychain.add_user(server_user)
                    response = solve_puzzle(challenge_received)
                    dh_public_key = cryptographer.public_key_to_bytes(self.keychain.dh_public_key)
                    payload = (str(response), n1, n2, dh_public_key)
                    payload = string_from_tuple(payload)
                    encrypted_payload = self.msg_cryptographer.encrypt_with_public_key(self.keychain.server_public_key, payload)
                    response_message = Message(msg_type="Solution", payload=encrypted_payload)
                    msg,address = send_receive_msg(self.socket, self.server_address, response_message, udp)
                    if msg.msg_type != "Server_DH":
                        return False
                    else:
                        payload = tuple_from_string(msg.payload)
                        payload_sign = msg.signature
                        nonce_verified = n2 == payload[0]
                        n3 = payload[1]
                        cryptographer.verify_message(self.keychain.server_public_key, msg.payload, payload_sign)
                        if nonce_verified:
                            n4 = os.urandom(16)
                            server_user.nonces_used.append(n4)
                            server_dh = cryptographer.bytes_to_public_key(payload[2])
                            server_user.aes_key = cryptographer.get_symmetric_key(server_dh, self.keychain.dh_private_key)
                            payload = string_from_tuple((n3, n4, self.password_hash, cryptographer.public_key_to_bytes(self.keychain.public_key)))
                            pass_msg = self.msg_cryptographer.symmetric_encryption(payload, server_user.aes_key, self.keychain.server_public_key)
                            pass_msg.msg_type = "Password"
                            final_message, address = send_receive_msg(self.socket, address, pass_msg, udp)
                            if final_message.msg_type != "Reject":
                                ln = self.msg_cryptographer.symmetric_decryption(final_message, server_user.aes_key, self.keychain.private_key)
                                return final_message.msg_type == "Accept" and ln == n4
                            else:
                                print "Wrong Password\n"
                                return False
                        else:
                            print "Sign not verified"
                            return False
            else:
                print msg.payload
                return False
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
            usr = self.keychain.get_user_with_addr(self.server_address)
            # msg = self.converter.sym_key_with_sign(msg, usr.key,
            #                                        self.keychain.private_key)
            send_msg(self.socket, self.server_address, msg)
            time.sleep(constants.SEND_HEARTBEAT_TIMEOUT)


import cli

if __name__ == '__main__':
    cli.run()
