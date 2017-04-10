import threading, sys, json
import constants as constants

class ChatServer:
    def __init__(self):
        return None


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