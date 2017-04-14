import getpass
import socket
import sys

import ChatClient as client
import exception as exception


class TextInterface:
    def __init__(self):
        self.client = client.ChatClient(('127.0.0.1', 9090))
        client.udp.start_udp(self.client, '127.0.0.1', 8888, 1)

    def login(self):
        while True:
            usernm = raw_input("Enter your user name:\n")
            passwd = getpass.getpass("Enter your password:\n")
            print "Logging In"
            if self.client.login(usernm, passwd):
                print ("Successfully Logged in")
                break
            else:
                print ("Unsuccessful login")

    def show_menu(self):
        print "Enter a command:\n1. list\n2. send <USER> <MESSAGE>\n3. quit\n"
        while True:
            command = raw_input()
            userinput = command.split(" ", 2)
            if userinput[0] == "list":
                l = self.client.list()

                if l is None:  # List Failed
                    print "List Failed"
                    continue

                if len(l) > 0:
                    print " ".join(l)
                else:
                    print "Only you are logged in"
            elif userinput[0] == "send":
                if len(userinput) == 3:
                    self.client.send(userinput[1], userinput[2])
                else:
                    print "Give user and message also"
            elif userinput[0] == "quit":
                self.client.logout()
                print ("Quitting the application")
                break
            else:
                print ("Enter correct command")


def run():
    try:
        txtint = TextInterface()
        txtint.login()
        txtint.show_menu()
    except (socket.error, IOError, exception.SecurityException) as e:
        print str(e)
    sys.exit(0)


if __name__ == "__main__":
    run()
