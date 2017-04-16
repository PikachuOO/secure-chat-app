SERVER_PRIVATE_KEY = "priv.der"
SERVER_PUBLIC_KEY = "pub.der"
NONCE_LENGTH=32
P_DIFFICULTY=2


BUFFER_SIZE = 2**16

# Crypto variables
RSA_PUBLIC_EXPONENT=65537
RSA_KEY_SIZE=2**11
HASH_LENGTH=64
HASH_ITERATIONS=200000

message_type = {
    "Reject": 0,
    "Login": 1,
    "Puzzle": 2,
    "Solution": 3,
    "Server_DH": 4,
    "Password": 5,
    "Accept": 6,
    "List": 7,
    "Logout": 8,
    "Sender_Client_DH": 9,
    "Dest_Client_DH": 10,
    "Message": 11,
    "Broadcast": 12,
    "Heartbeat": 13
}

message_dictionary = {
    "Reject": "Reject",
    "Login": "Login",
    "Challenge": "Challenge",
    "Solution": "Solution",
    "Server_DH": "Server_DH",
    "Password": "Password",
    "Accept": "Accept",
    7: "List",
    8: "Logout",
    9: "Sender_Client_DH",
    10: "Dest_Client_DH",
    11: "Message",
    12: "Broadcast",
    13: "Heartbeat"
}

exception_messages={
    'UnsupportedAlgorithm':'algorithm, or combination of algorithms is not supported'
}


# File names
USER_CRED_FILE='user_cred.txt'
PT_USER_CRED_FILE='pt_user_cred.json'
