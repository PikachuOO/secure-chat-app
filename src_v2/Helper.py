from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import os,sys,binascii,time
import constants as CN


def send_msg(sender_socket, dest_addr, msg):
    sender_socket.sendto(str(msg), dest_addr)


def send_recv_msg(sender_socket, recv_udp, dest_addr, msg):
    recv_udp.condition.acquire()
    sender_socket.sendto(str(msg), dest_addr)
    return recv_udp.receive(CN.SOCKET_TIMEOUT)


def get_timestamp():
    return long(time.time())

'''
client solves the puzzle
returns n: n such that SHA256(R, n) is zero in its first k bits
'''


def solve_puzzle(string,k):
    n=0
    while 1:
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(string)
        h.update(bytes(n))
        if is_first_k_zeros(h.finalize(), k):
            return n

        n += 1

# server verifies the challenge solution


def verify_challenge_solution(string,n,k):
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(string)
    h.update(bytes(n))
    if is_first_k_zeros(h.finalize(), k):
        return n


# checks if first k bytes are zero


def is_first_k_zeros(hashed_val,k):
    first_k_bytes = hashed_val[:k]
    for i in first_k_bytes:
        if ord(i) != 0:
            return False
    return True

# get DH public private key pair


def get_dh_pair():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# get symmetric key from DH


def get_symmetric_key(peer_public_key,private_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# create random challenge string


def get_challenge(los):
    c_str= os.urandom(CN.NONCE_LENGTH)
    while c_str in los:
        c_str = os.urandom(CN.NONCE_LENGTH)
    return c_str, ord(chr(CN.P_DIFFICULTY))
