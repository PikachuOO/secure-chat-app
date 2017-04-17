import getpass
import socket
import sys
import Helper as h
import exception_message as EM

import ChatClient as client


class CommandLineClient:
    def __init__(self,client_port):
        self.client = client.ChatClient(('', h.get_server_port()))
        print client_port
        client.udp.start_udp(self.client, '', client_port, 1)

    def sign_in(self):
        while True:
            usernm = raw_input("Enter your user name:\n")
            passwd = getpass.getpass("Enter your password:\n")
            print "Logging In"
            if self.client.login(usernm, passwd):
                print ("Successfully Logged in")
                break
            else:
                print EM.INVALID_USERNAME_PWD

    def options(self):
        print "Enter a command:\n1. list\n2. send <USER> <MESSAGE>\n3. quit\n"
        while True:
            command = raw_input()
            userinput = command.split(" ", 2)
            if userinput[0] == "list" and len(userinput)==1:
                l = self.client.list()

                if l is None:
                    print "List Failed"
                    continue

                print l
            elif userinput[0] == "send":
                if len(userinput) == 3:
                    self.client.send(userinput[1], userinput[2])
                else:
                    print EM.INCORRECT_SEND_COMMAND
            elif userinput[0] == "quit" and len(userinput)==1:
                self.client.quit()
                print EM.QUIT_APP
                break
            else:
                print EM.INCORRECT_COMMAND


def run(client_port):
    try:
        cli = CommandLineClient(client_port)
        cli.sign_in()
        cli.options()
    except (socket.error, IOError) as e:
        print str(e)
    sys.exit(0)
