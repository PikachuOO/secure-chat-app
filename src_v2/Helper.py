import time

import constants as constants


def send_msg(sender_socket, dest_addr, msg):
    sender_socket.sendto(str(msg), dest_addr)


def send_recv_msg(sender_socket, recv_udp, dest_addr, msg):
    recv_udp.condition.acquire()
    sender_socket.sendto(str(msg), dest_addr)
    return recv_udp.receive(constants.SOCKET_TIMEOUT)


def get_timestamp():
    return long(time.time())
