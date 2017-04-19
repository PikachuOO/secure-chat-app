import sys
import threading
import time
import socket
from Message import *
from UDP import UDP
from Helper import *
from Cryptographer import Cryptographer
import constants as constants

udp = UDP()
cryptographer = Cryptographer()


# To save the user details a particular client or server
class ServerKeyChain:
    def __init__(self):
        self.usernames = {}
        self.address_dict = {}
        server_public_key = open(constants.SERVER_PUBLIC_KEY, 'rb')
        server_private_key = open(constants.SERVER_PRIVATE_KEY, 'rb')
        self.public_key = cryptographer.load_public_key(server_public_key)
        self.private_key = cryptographer.load_private_key(server_private_key)
        self.dh_private_key, self.dh_public_key = cryptographer.get_dh_pair()

    # Returns all the list of al client
    def list_users(self):
        return self.usernames

    # Returns the user based on this address
    def get_user_from_address(self, address):
        if address in self.address_dict:
            return self.address_dict[address]
        else:
            return None

    # Returns the user bases on his username
    def get_user_from_username(self, username):
        if username in self.usernames:
            return self.usernames[username]
        else:
            return None

    # Adding the user to the keychain
    def add_user(self, user):
        self.address_dict[user.address] = user
        self.usernames[user.username] = user

    # Removing the user from the keychain
    def remove_user(self, user):
        self.address_dict.pop(user.address, None)
        self.usernames.pop(user.username, None)


# A client on the point of view of the server
class ServerUser:
    def __init__(self):
        self.username = None
        self.pass_hash = None
        self.salt = None
        self.public_key = None
        self.aes_key = None
        self.address = None
        self.is_logged = None
        self.last_hearbeat_recv = None
        self.next_expected = None
        self.challenge_given = None
        self.nonces_used = []

# Handling methods of client
class ChatServer:
    def __init__(self):
        self.socket = udp.socket
        self.keychain = ServerKeyChain()
        self.msg_parser = MessageParser()
        self.msg_cryptographer = MessageCryptographer()
        self.certificate = None
        self.used_nonce_list = []
        self.check_heartbeat_thread = threading.Thread(target=self.check_heartbeat)
        self.check_heartbeat_thread.daemon = True
        self.check_heartbeat_thread.start()
        self.registered_users = load_hasehed_pwd()

    # Receiving a Login request from a client
    @udp.endpoint("Login")
    def receive_new_login(self, msg, address):
        msg = unpickle_message(msg)
        new_username = msg.payload
        print "received login from", new_username
        if new_username in self.registered_users:
            if new_username not in self.keychain.usernames:
                new_user = ServerUser()
                new_user.username = new_username
                new_user.address = address
                new_user.is_logged = False
                new_user.challenge_given = get_challenge(self.used_nonce_list)
                n1 = os.urandom(16)
                new_user.nonces_used.append(n1)
                self.used_nonce_list.append(new_user.challenge_given[0])
                new_user.next_expected = "Solution"
                self.keychain.add_user(new_user)
                final_challenege = new_user.challenge_given + (n1, )
                challenge_message = Message(msg_type="Challenge", payload=final_challenege)
                send_msg(self.socket, address, challenge_message)
            else:
                temp = "You are already logged in!!"
                reject_msg = Message(msg_type="Reject", payload=temp)
                send_msg(self.socket, address, reject_msg)
        else:
            temp = "You are not registered!"
            reject_msg = Message(msg_type="Reject", payload=temp)
            send_msg(self.socket, address, reject_msg)

    # Receiving a solution for the puzzle
    @udp.endpoint("Solution")
    def receive_solution(self, msg, address):
        user = self.keychain.get_user_from_address(address)
        if user is not None:
            msg = unpickle_message(msg)
            if user.next_expected == "Solution":
                payload = msg.payload
                decrypted_payload = self.msg_cryptographer.decrypt_with_private_key(self.keychain.private_key, payload)
                payload = tuple_from_string(decrypted_payload)
                received_solution = int(payload[0])
                match_solution = verify_challenge_solution(user.challenge_given[0], received_solution, user.challenge_given[1])
                n1 = payload[1]
                solution_verified = match_solution == received_solution
                if n1 == user.nonces_used[len(user.nonces_used)-1] and solution_verified:
                    n2 = payload[2]
                    n3 = os.urandom(16)
                    client_dh = payload[3]
                    client_dh = cryptographer.bytes_to_public_key(client_dh)
                    server_dh = self.keychain.dh_private_key
                    user.aes_key = cryptographer.get_symmetric_key(client_dh, server_dh)
                    payload = (n2, n3, cryptographer.public_key_to_bytes(self.keychain.dh_public_key))
                    payload = string_from_tuple(payload)
                    payload_sign = cryptographer.sign_message(self.keychain.private_key, payload)

                    # Diffie Hellman contribution from client
                    resp = Message(msg_type="Server_DH", payload=payload, signature=payload_sign)
                    user.nonces_used.append(n3)
                    self.keychain.add_user(user)
                    msg, address = send_receive_msg(self.socket, address, resp, udp)
                    payload_dec = self.msg_cryptographer.symmetric_decryption(msg, user.aes_key, self.keychain.private_key)
                    payload_dec = tuple_from_string(payload_dec)
                    nonce_verified = n3 == payload_dec[0]
                    n4 = payload_dec[1]
                    pass_hash = payload_dec[2]
                    if pass_hash == self.registered_users[user.username] and nonce_verified:
                        user.public_key = cryptographer.bytes_to_public_key(payload_dec[3])
                        self.keychain.add_user(user)
                        print "password matched from", user.username
                        result_msg = self.msg_cryptographer.symmetric_encryption(n4, user.aes_key, user.public_key)
                        result_msg.msg_type = "Accept"
                        send_msg(self.socket, address, result_msg)
                    else:
                        print "password not matched from", user.username
                        self.keychain.remove_user(user)
                        result_msg = Message(msg_type="Reject", payload="Password Did not match")
                        send_msg(self.socket, address, result_msg)
                        pass
                else:
                    self.keychain.remove_user(user)
                    pass
            else:
                self.keychain.remove_user(user)

    # Client requests online userlist
    @udp.endpoint("List")
    def request_list(self, msg, address):
        msg = unpickle_message(msg)
        list_requester = self.keychain.get_user_from_address(address)
        if list_requester is not None:
            n1 = self.msg_cryptographer.symmetric_decryption(msg, list_requester.aes_key, self.keychain.private_key)
            if n1 not in list_requester.nonces_used:
                all_users = []
                for each in self.keychain.list_users():
                    all_users.append(each)
                list_users = ' '.join(all_users)
                pl = string_from_tuple((list_users, n1))
                enc_user_list = self.msg_cryptographer.symmetric_encryption(pl, list_requester.aes_key, list_requester.public_key)
                enc_user_list.msg_type = "UserList"
                send_msg(self.socket, address, enc_user_list)
            else:
                pass
        else:
            pass

    # Client request Details for a particular client
    @udp.endpoint("RequestDetail")
    def request_detail(self, msg, address):
        msg = unpickle_message(msg)
        user = self.keychain.get_user_from_address(address)
        if user is not None:
            dec_msg = self.msg_cryptographer.symmetric_decryption(msg, user.aes_key, self.keychain.private_key)
            recipient_un, n1 = tuple_from_string(dec_msg)
            if recipient_un in self.keychain.list_users():
                recipient = self.keychain.get_user_from_username(recipient_un)
                rec_pub_key = cryptographer.public_key_to_bytes(recipient.public_key)
                recp_address = convert_addr_to_bytes(recipient.address)
                a_pub_key = cryptographer.public_key_to_bytes(user.public_key)
                a_address = convert_addr_to_bytes(address)
                a_details = string_from_tuple((a_pub_key, a_address))
                b_token = self.msg_cryptographer.symmetric_encryption(a_details, recipient.aes_key, recipient.public_key)
                b_token = pickle.dumps(b_token)
                pl = string_from_tuple((n1, rec_pub_key, recp_address, b_token))
                pl = self.msg_cryptographer.symmetric_encryption(pl, user.aes_key, user.public_key)
                pl.msg_type = "ResponseDetail"
                send_msg(self.socket, address, pl)
            else:
                temp = "No user named " + recipient_un
                m = string_from_tuple((n1, temp))
                m = self.msg_cryptographer.symmetric_encryption(m, user.aes_key, user.public_key)
                m.msg_type = "ResponseDetail"
                send_msg(self.socket, address, m)

    # Client issues a quit command
    @udp.endpoint("Quit")
    def receive_quit(self, msg, address):
        msg = unpickle_message(msg)
        user = self.keychain.get_user_from_address(address)
        if user is None or user.public_key is None:
            print "Invalid user"
        else:
            dec_msg = self.msg_cryptographer.symmetric_decryption(msg, user.aes_key, self.keychain.private_key)
            if dec_msg == user.username:
                logout_resp = self.msg_cryptographer.symmetric_encryption(user.username, user.aes_key, user.public_key)
                logout_resp.msg_type = "LogoutResp"
                send_msg(self.socket, user.address, logout_resp)
                self.keychain.remove_user(user)
                self.send_broadcast_user_logout(user)
            else:
                print "Invalid Logout req"
                pass

    # Client issues a logout broadcast details of a particular client
    def send_broadcast_user_logout(self, user):
        ip = convert_addr_to_bytes(user.address)
        for client in self.keychain.list_users().itervalues():
            if client.aes_key is not None:
                log = self.msg_cryptographer.symmetric_encryption(ip, client.aes_key, client.public_key)
                log.msg_type = "Logout"
                send_msg(self.socket, client.address, log)

    # server periodically checks the status of the online clients
    def check_heartbeat(self):
        while True:
            logged_out_users = []
            for user in self.keychain.list_users().itervalues():
                if user.last_hearbeat_recv is not None and get_time() - user.last_hearbeat_recv >= 10:
                    logged_out_users.append(user)
                    print user.username, "Logged out"
            for user in logged_out_users:
                self.keychain.remove_user(user)
                self.send_broadcast_user_logout(user)
            time.sleep(5)

    # Server receives heartbeat from a client
    @udp.endpoint("HeartBeat")
    def receive_heartbeat(self, msg, address):
        msg = unpickle_message(msg)
        user = self.keychain.get_user_from_address(address)
        if user is None:
            raise "Invalid User"
        print "received heartbeat from", user.username
        dec_msg = self.msg_cryptographer.symmetric_decryption(msg, user.aes_key, self.keychain.private_key)
        dec_msg = tuple_from_string(dec_msg)
        rec_ts = long(dec_msg[1])
        rec_un = dec_msg[0]
        if rec_un == user.username and rec_ts <= get_time() :
            user.last_hearbeat_recv = rec_ts
            self.keychain.add_user(user)
        else:
            raise "Invalid Hearbeat"

def run():
    try:
        server = ChatServer()
        udp.start_udp(server, '127.0.0.1', 9090, 5)
        print "Server Running!!"
        server.check_heartbeat_thread.join()
    except (socket.error, Exception) as e:
        print str(e)

if __name__ == "__main__":
    run()
