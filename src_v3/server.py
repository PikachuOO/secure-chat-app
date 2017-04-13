import socket,sys,json,os,getopt


class UDPServerException(Exception):
    pass


class Server(object):
    def __init__(self):
        self.port = 0
        self.host = ''
        self.sock = ''
        self.user_dict = {}

    def create_packet(self,packet_type,msg):
        data = {}
        data[packet_type] = msg
        json_packet = json.dumps(data)
        return json_packet

    def get_data_fom_Json(self,json_data):
        j=json.loads(json_data)
        try:
            if len(j)>1:
                raise UDPServerException('More than one kind of packet')
            else:
                for key, value in j.items():
                    return key,value
        except UDPServerException as e:
            print e
            sys.exit()

    def list_users(self):
        users='Signed In Users: '
        for key, value in self.user_dict.items():
            users=users+value+','
        return users[:-1]

    def create_socket(self):
        #Create UDP socket
        try:
            self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        except socket.error:
            print ('Failed to create socket.')
            sys.exit()

        try:
            self.sock.bind(('',self.port))
        except socket.error:
            print('Socket bind failed.')
            sys.exit(0)
        print ('Server Initialized...')

    def update_user_dict(self,data,username):
        client_addr=data[1]
        self.user_dict.update({str(client_addr[0]) + ':' + str(client_addr[1]):username})
        print self.user_dict
        return 'sign-in success##'+str(client_addr[0])+'##'+str(client_addr[1])

    def get_client_addr(self,data):
        user_ip='CREDENTIALS'
        for key, value in self.user_dict.items():
            if value==data:
                user_ip=user_ip+'##'+key
        return user_ip

    def handle_packet(self,data):
        packet_type, username=self.get_data_fom_Json(data[0])
        try:
            if packet_type=='LIST':
                return self.list_users()
            elif packet_type=='SIGN-IN':
                return self.update_user_dict(data,username)
            elif packet_type=='USERNAME':
                return self.get_client_addr(username)
            else:
                raise UDPServerException('Recieved unsupported packet type: '+packet_type)
        except UDPServerException as e:
            return e

    def recieve_msg_from_client(self):
        while 1:
            d=self.sock.recvfrom(1024)
            data=self.handle_packet(d)
            addr=d[1]
            if not data:
                break
            reply=data
            self.sock.sendto(reply,addr)
            print 'Message[' + addr[0] + ':' + str(addr[1]) + '] - ' + data.strip()

    def close_socket(self):
        self.sock.close()

    def initialize(self,argv):
        if len(argv)==0:
            print 'Hint run as: python server.py -sp <server-port>'
            sys.exit(0)
        try:
            opts,args=getopt.getopt(argv,"s:",["sp="])
        except getopt.GetoptError:
            print 'Error in reading commandline arguments'
            print 'Hint run as: python server.py -sp <server-port>'
            sys.exit(0)
        for opt,arg in opts:
            if opt in ('-s','--sp'):
                self.port=int(arg)
            else:
                print 'Hint run as: python server.py -sp <server-port>'
                sys.exit(0)

def main(argv):
    server=Server()
    server.initialize(argv)
    server.create_socket()
    server.recieve_msg_from_client()
    server.close_socket()

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print 'Server shutting down'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
