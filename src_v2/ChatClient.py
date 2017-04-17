import time

from Message import *
from UDP import *
from Helper import *
from security_exceptions import SecurityException
import exception_message as EM
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
        if address in self.address_dict:
            return self.address_dict[address]
        else:
            return None

    def get_user_from_username(self, username):
        if username in self.usernames:
            return self.usernames[username]
        else:
            return None

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
        self.is_authenticated = False


class ChatClient:
    def __init__(self, server_address):
        self.server_address = (get_server_ip(), get_server_port())
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
        self.heartbeat_thread = threading.Thread(target=self.generate_heartbeat)
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
        self.password_hash = cryptographer.compute_hash_from_client_password(self.username, password)
        # if self.pass_thread is not None and self.pass_thread.isAlive():
        #     self.pass_thread.join()
        # self.pass_thread = threading.Thread(target=self.compute_hash, args=(password,))
        # self.pass_thread.daemon = True
        # self.pass_thread.start()

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
                                self.heartbeat_thread.start()
                                self.keychain.add_user(server_user)
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
        except:
            return False

    def compute_hash(self, password):
        self.password_hash = cryptographer.compute_hash_from_client_password(self.username, password)

    def list(self):
        try:
            n1 = os.urandom(16)
            server = self.keychain.get_user_from_address(self.server_address)
            payl = self.msg_cryptographer.symmetric_encryption(n1, server.aes_key, server.public_key)
            payl.msg_type = "List"
            list_resp, address = send_receive_msg(self.socket, server.address, payl, udp)
            if address == self.server_address:
                dec_user_list = self.msg_cryptographer.symmetric_decryption(list_resp, server.aes_key, self.keychain.private_key)
                user_list, n1_resp = tuple_from_string(dec_user_list)
                if n1_resp == n1:
                    return user_list
                else:
                    pass
            else:
                pass
        except socket.timeout:
            print "Socket timed out, while req list"

    def send(self,recipient_un, message_to_send):
        if recipient_un == self.username:
            print "Cannot send a message to yourself"
        else:
            recp = self.keychain.get_user_from_username(recipient_un)
            if recp is not None and recp.is_authenticated:
                enc_msg = self.msg_cryptographer.symmetric_encryption(message_to_send, recp.aes_key, recp.public_key)
                enc_msg.msg_type = "Message"
                send_msg(self.socket, recp.address, enc_msg)
            else:
                self.send_with_handshake(recipient_un, message_to_send)

    def send_with_handshake(self, recipient_un, message_to_send):
        n1 = os.urandom(16)
        pl = string_from_tuple((recipient_un, n1))
        server = self.keychain.get_user_from_address(self.server_address)
        req_msg = self.msg_cryptographer.symmetric_encryption(pl, server.aes_key, self.keychain.server_public_key)
        req_msg.msg_type = "RequestDetail"
        msg, address = send_receive_msg(self.socket, server.address, req_msg, udp)
        if address == self.server_address and msg.msg_type == "ResponseDetail":
            access_token_b = self.msg_cryptographer.symmetric_decryption(msg, server.aes_key, self.keychain.private_key)
            resp_detail = tuple_from_string(access_token_b)
            n1_resp = resp_detail[0]
            if n1_resp == n1:
                if len(resp_detail) == 2:
                    print resp_detail[1]
                else:
                    n1_resp, b_pub_key, b_address, b_token = resp_detail
                    b_pub_key = cryptographer.bytes_to_public_key(b_pub_key)
                    b_address = convert_bytes_to_addr(b_address)
                    n1 = os.urandom(16)
                    pl = string_from_tuple((self.username, n1))
                    msg = self.msg_cryptographer.encrypt_with_public_key(b_pub_key, pl)
                    hello_msg = Message(msg_type="Hello", payload=msg, iv_tag=b_token)
                    msg, address = send_receive_msg(self.socket, b_address, hello_msg, udp)
                    if msg.msg_type == "HelloResponse":
                        dec_msg = self.msg_cryptographer.decrypt_with_private_key(self.keychain.private_key, msg.payload)
                        (n1_resp, n2, peer_dh) = tuple_from_string(dec_msg)
                        if n1 == n1_resp and address == b_address:
                            peer = ClientUser()
                            peer.username = recipient_un
                            peer.address = b_address
                            peer.public_key = b_pub_key
                            peer.nonces_used.append(n1)
                            priv_key_dh_peer, pub_key_dh_peer = cryptographer.get_dh_pair()
                            pkb = cryptographer.public_key_to_bytes(pub_key_dh_peer)
                            n3 = os.urandom(16)
                            pl = string_from_tuple((n2, n3, pkb))
                            peer.nonces_used.append(n3)
                            pl = self.msg_cryptographer.encrypt_with_public_key(b_pub_key, pl)
                            dh_resp = Message(msg_type="PeerDHResponse", payload=pl)
                            peer_dh = cryptographer.bytes_to_public_key(peer_dh)
                            peer.aes_key = cryptographer.get_symmetric_key(peer_dh, priv_key_dh_peer)
                            msg, address = send_receive_msg(self.socket, b_address, dh_resp, udp)
                            self.keychain.add_user(peer)
                            if msg.msg_type == "PeerAccept":
                                n3_resp = self.msg_cryptographer.symmetric_decryption(msg, peer.aes_key, self.keychain.private_key)
                                if n3_resp == n3:
                                    peer.is_authenticated = True
                                    self.keychain.add_user(peer)
                                    enc_msg = self.msg_cryptographer.symmetric_encryption(message_to_send, peer.aes_key,
                                                                                          peer.public_key)
                                    enc_msg.msg_type = "InitialMessage"
                                    send_msg(self.socket, peer.address, enc_msg)
                                else:
                                    self.keychain.remove_user(peer)
                            else:
                                print "Invalid Message"
                        else:
                            print "Not verdsfsdf"

                    else:
                        print "Invalid Message type"
                        pass
            else:
                pass
        else:
            print "Invalid sender"
            pass

    @udp.endpoint("Message")
    def receive_message(self, msg, address, options=""):
        msg = unpickle_message(msg)
        sender = self.keychain.get_user_from_address(address)
        if sender is not None and sender.is_authenticated:
            dec_msg = self.msg_cryptographer.symmetric_decryption(msg, sender.aes_key, self.keychain.private_key)
            print "<Message from " + sender.username + '>: ' + dec_msg

    @udp.endpoint("Hello")
    def receive_hello(self, msg, address):
        server = self.keychain.get_user_from_address(self.server_address)
        msg = unpickle_message(msg)
        dec_msg = self.msg_cryptographer.decrypt_with_private_key(self.keychain.private_key, msg.payload)
        (peer_name, n1) = tuple_from_string(dec_msg)
        b_token = pickle.loads(msg.iv_tag)
        try:
            b_token = self.msg_cryptographer.symmetric_decryption(b_token, server.aes_key, self.keychain.private_key)
            (a_public_key, a_address) = tuple_from_string(b_token)
            a_public_key = cryptographer.bytes_to_public_key(a_public_key)
            a_address = convert_bytes_to_addr(a_address)
            if a_address == address:
                peer = ClientUser()
                peer.username = peer_name
                peer.address = address
                peer.public_key = a_public_key
                peer.nonces_used.append(n1)
                self.keychain.add_user(peer)
                priv_key_dh_peer, pub_key_dh_peer = cryptographer.get_dh_pair()
                pkb = cryptographer.public_key_to_bytes(pub_key_dh_peer)
                n2 = os.urandom(16)
                pl = string_from_tuple((n1, n2, pkb))
                pl = self.msg_cryptographer.encrypt_with_public_key(a_public_key, pl)
                hello_resp = Message(msg_type="HelloResponse", payload=pl)
                msg, address = send_receive_msg(self.socket, peer.address, hello_resp, udp)
                if msg.msg_type == "PeerDHResponse":
                    dec_msg = self.msg_cryptographer.decrypt_with_private_key(self.keychain.private_key, msg.payload)
                    (n2_resp, n3, peer_dh) = tuple_from_string(dec_msg)
                    peer_dh = cryptographer.bytes_to_public_key(peer_dh)
                    peer.aes_key = cryptographer.get_symmetric_key(peer_dh, priv_key_dh_peer)
                    peer.nonces_used.append(n3)
                    status_msg = self.msg_cryptographer.symmetric_encryption(n3, peer.aes_key, a_public_key)
                    status_msg.msg_type = "PeerAccept"
                    peer.is_authenticated = True
                    self.keychain.add_user(peer)
                    final_msg, address = send_receive_msg(self.socket, a_address, status_msg, udp)
                    if address == peer.address:
                        dec_f_msg = self.msg_cryptographer.symmetric_decryption(final_msg, peer.aes_key, self.keychain.private_key)
                        print "<Message from " + peer.username + '>: ' + dec_f_msg
                else:
                    print "Incalkddsnds"

            else:
                print "Invlid Hello"
                pass
        except:
            print "Cannot decrypt the server permission token"

    def quit(self):
        server = self.keychain.get_user_from_address(self.server_address)
        logout_msg = self.msg_cryptographer.symmetric_encryption(self.username, server.aes_key, server.public_key)
        logout_msg.msg_type = "Quit"
        logout_resp, address = send_receive_msg(self.socket, server.address, logout_msg, udp)
        dec_msg = self.msg_cryptographer.symmetric_decryption(logout_resp, server.aes_key, self.keychain.private_key)
        return logout_resp.msg_type == "LogoutResp" and dec_msg == self.username


    @udp.endpoint("Logout")
    def receive_logout_broadcast(self, msg, address):
        server = self.keychain.get_user_from_address(address)
        msg = unpickle_message(msg)
        if address == self.server_address:
            dec_msg = self.msg_cryptographer.symmetric_decryption(msg, server.aes_key, self.keychain.private_key)
            add = convert_bytes_to_addr(dec_msg)
            u = self.keychain.get_user_from_address(add)
            if u is not None:
                self.keychain.remove_user(u)

        else:
            print "Invalid Sender"

    def generate_heartbeat(self):
        while True:
            server = self.keychain.get_user_from_address(self.server_address)
            ts = str(get_time())
            pl = string_from_tuple((self.username, ts))
            ht_msg = self.msg_cryptographer.symmetric_encryption(pl, server.aes_key, self.keychain.server_public_key)
            ht_msg.msg_type = "HeartBeat"
            send_msg(self.socket, self.server_address, ht_msg)
            time.sleep(10)


import cli

def main(argv):
    try:
        if len(argv) == 2 and argv[0] == '-p':
            cli.run(int(argv[1]))
        else:
            raise SecurityException(EM.INVALID_ARGUMENT)
    except (SecurityException,Exception) as e:
        print str(e)

if __name__ == '__main__':
    argv=sys.argv
    try:
        if len(argv) == 0:
            raise SecurityException(EM.INVALID_ARGUMENT)
        main(sys.argv[1:])
    except (SecurityException,Exception) as e:
        print str(e)