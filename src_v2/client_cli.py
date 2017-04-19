import getpass
import socket
import sys
import Helper as h
import ChatClient as client
#import exception as exception


class CommandLineOptions:
    def __init__(self,client_port):
        self.client = client.ChatClient(('', h.get_server_port()))
        client.udp.start_udp(self.client, '', client_port, 1)

    def sign_in(self):
        while True:
            usernm = raw_input("Enter your user name:\n")
            passwd = getpass.getpass("Enter your password:\n")
            print "Logging In"
            if self.client.login(usernm, passwd):
                print ("Login successfull")
                break
            else:
                print ("Login Failed")

    def options(self):
        print "Enter a command:\n1. list\n2. send <USER> <MESSAGE>\n3. quit\n"
        while True:
            command = raw_input()
            userinput = command.split(" ", 2)
            if userinput[0] == "list":
                l = self.client.list()

                if l is None:  # List Failed
                    print "List Failed"
                    continue

                print l
            elif userinput[0] == "send":
                if len(userinput) == 3:
                    self.client.send(userinput[1], userinput[2])
                else:
                    print "Give user and message also"
            elif userinput[0] == "quit":
                self.client.quit()
                print ("Quitting the application")
                break
            else:
                print ("Enter correct command")


def run(client_port):
    try:
        txtint = CommandLineOptions(client_port)
        txtint.sign_in()
        txtint.options()
    except (socket.error, IOError) as e:
        print str(e)
    sys.exit(0)
