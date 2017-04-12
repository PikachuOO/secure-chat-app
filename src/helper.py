import socket, struct, time


def get_time():
    return long(time.time())


def string_from_tuple(tp):
    final_string = ""
    for each in tp:
        length = struct.pack("!H", len(each))
        final_string += length
        final_string += each
    return final_string


def send_msg(sender_socket, dest_address, message):
    sender_socket.sendto(str(message), dest_address)


def send_recv_msg(sender_socket, receiver_udp, dest_address, message):
    receiver_udp.condition.acquire()
    sender_socket.sendto(str(message), dest_address)
    return receiver_udp.recv(15)


def tuple_from_string(string):
    final_tuple = []
    try:
        while True:
            if string == '':
                break
            header = struct.unpack("!H", string[:2])[0]
            param = string[2:2 + header]
            final_tuple.append(param)
            string = string[2 + header:]
        return tuple(final_tuple)
    except:
        print "Invalid Message"
