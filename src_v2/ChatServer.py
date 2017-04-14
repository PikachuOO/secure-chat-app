import sys
import threading
import time

from Message import *
from UDP import UDP
from Helper import send_msg, get_timestamp
from Cryptographer import Cryptographer
import constants as constants

udp = UDP()
cryptographer = Cryptographer()


class ServerKeyChain:
    def __init__(self):
        pass
        self.usernames = {}
        self.address_dict = {}
        server_public_key = open(constants.SERVER_PUBLIC_KEY, 'rb')
        server_private_key = open(constants.SERVER_PRIVATE_KEY, 'rb')
        self.public_key = cryptographer.load_public_key(server_public_key)
        self.private_key = cryptographer.load_private_key(server_private_key)

    def list_users(self):
        return self.usernames

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


class ServerUser:
    def __init__(self):
        self.username = None
        self.pass_hash = None
        self.salt = None
        self.public_key = None
        self.key = None
        self.addr = None
        self.last_heartbeat_recv = None
        self.last_list_recv = 0


class ChatServer:
    def __init__(self):
        self.socket = udp.socket
        self.keychain = ServerKeyChain()

        self.msg_parser = MessageParser()
        self.certificate = None
        self.nc_list = {}

        self.puz_thread = threading.Thread(
            target=self.__generate_puz_certificate)
        self.puz_thread.daemon = True
        self.puz_thread.start()

        self.check_heartbeat_thread = threading.Thread(
            target=self.check_heartbeat)
        self.check_heartbeat_thread.daemon = True
        self.check_heartbeat_thread.start()

    def __generate_puz_certificate(self):
        while True:
            t1 = time.time()
            d = chr(1) # Default Difficulty
            expiry_time = long(t1 + 15)
            self.certificate = ""
            self.nc_list = {}
            time.sleep(15)

    @udp.endpoint("Login")
    def got_login_packet(self, msg, addr):
        print "sdsdsdsd"
        # msg = Message(message_type["Puzzle"],
        #               payload=self.certificate)
        # msg = self.converter.nokey_nosign(msg)
        msg = {'type':"test", 'payload':'palala'}
        msg = pickle.dumps(msg)
        send_msg(self.socket, addr, msg)


    def check_heartbeat(self):
        while True:
            logged_out = []
            t1 = get_timestamp()
            for user in self.keychain.list_users().itervalues():
                if user.last_heartbeat_recv is not None and get_timestamp() >= user.last_heartbeat_recv:
                    logged_out.append(user)
                    print "Logged out", user.username

            for user in logged_out:
                self.keychain.remove_user(user)
                self.__send_logout_broadcast(user)

            t2 = get_timestamp()
            sleep_time = 30 - (t2 - t1)
            if sleep_time > 0:
                time.sleep(sleep_time)


def run():
    try:
        server = ChatServer()
        udp.start_udp(server, '127.0.0.1', 9090, 5)
        print "Server Running!!"
        server.check_heartbeat_thread.join()
    except (exception.SecurityException, IOError) as e:
        print str(e)

if __name__ == "__main__":
    run()
