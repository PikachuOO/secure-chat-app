import socket,sys,json,getopt,threading,os


class UDPServerException(Exception):
    pass


class Client(object):

    def __init__(self, argv):
        self._message = ''
        self.client_ip = ''
        self.client_port = ''
        print 'inside int'
        if len(argv) == 0:
            print 'Hint run as: python client.py -u <username> -sip <server-name> -sp <server-port>'
            sys.exit(0)
        try:
            opts, args = getopt.getopt(argv, "u:i:p:", ["sip=", "sp="])
        except getopt.GetoptError as e:
            print 'Error in reading commandline arguments'
        print opts
        for opt, arg in opts:
            if opt == '-u':
                self.username = arg
            if opt in ('-i', '--sip'):
                self.host = arg
                print self.host

            if opt in ('-p', '--sp'):
                self.port = int(arg)
                print self.port

    def utf8len(self,s):
        return len(s.encode('utf-8'))

    def sign_in(self):
        try:
            self.send_data_to_server('SIGN-IN',self.username)
        except socket.error:
            print 'Error in signin: '
            sys.exit(0)

    def create_packet(self,packet_type,msg):
        data = {}
        data[packet_type] = msg
        json_packet = json.dumps(data)
        return json_packet

    def create_socket(self):
        try:
            self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            self.sign_in()
        except socket.error as serr:
            print 'Error in create_socket: '
            sys.exit(0)

    def send_data_to_server(self,packet_type,data):
        self.sock.sendto(self.create_packet(packet_type, data), (self.host,self.port))

    def client_to_client_messaging(self,reply):
        temp_arr = reply.split('##')
        arr=temp_arr[1:]
        for i in range(len(arr)):
            sendto_addr = arr[i].split(':')
            ip=sendto_addr[0]
            port=sendto_addr[1]
            self.sock.sendto(self._message, (ip,int(port)))

    def sign_response(self,reply):
        temp_arr=reply.split('##')
        arr=temp_arr[1:]
        self.client_ip=arr[0]
        self.client_port=arr[1]
        print 'signed @:'+self.username+' '+self.client_ip+':'+self.client_port+'>'

    def handle_response(self):
        while 1:
            try:
                d=self.sock.recvfrom(65507)
                reply=d[0]
                addr=d[1]
                ip_addr=addr[0]
                port_num=addr[1]
                if 'CREDENTIALS' in reply:
                    self.client_to_client_messaging(reply)
                elif 'sign-in success' in reply:
                    self.sign_response(reply)
                elif self.port in addr:
                    print reply
                else:
                    print reply
            except socket.error as serr:
                print 'Error in handle_response '
                sys.exit(0)

    def read_input(self):
        while 1:
            msg=raw_input('')
            if self.utf8len(msg)>65507:
                print 'Entered message is longer than supported by UDP'
            else:
                try:
                    if 'send' in msg:
                        self.get_other_client_info(msg)
                    elif 'list' == msg or 'LIST' == msg:
                        self.send_data_to_server('LIST',msg)
                    else:
                        print 'Recieved unsupported command: '
                except socket.error as serr:
                    print 'Error in read input'

    def get_other_client_info(self,msg):
        temp_msg='<From '+self.client_ip+':'+self.client_port+':'+self.username+'>:'
        if 'send' in msg:
            arr=msg.split(' ')
            temp_arr=arr[2:]
            for i in range(len(temp_arr)):
                temp_msg=temp_msg+' '+temp_arr[i]
            self._message=temp_msg
            self.send_data_to_server('USERNAME',arr[1])


def main(argv):
    client=Client(argv)
    print 'before initialization'
    client.create_socket()
    threading.Thread(target = client.read_input).start()
    threading.Thread(target = client.handle_response).start()

if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print 'Server shutting down'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)