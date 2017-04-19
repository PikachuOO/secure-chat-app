SERVER_PRIVATE_KEY = "server_private_key.der"
SERVER_PUBLIC_KEY = "server_public_key.der"
NONCE_LENGTH=32
P_DIFFICULTY=2

BUFFER_SIZE = 2**16

# Crypto variables
RSA_PUBLIC_EXPONENT=65537
RSA_KEY_SIZE=2**11
HASH_LENGTH=64
HASH_ITERATIONS=200000

message_dictionary = {
    "Reject": "Reject",
    "Login": "Login",
    "Challenge": "Challenge",
    "Solution": "Solution",
    "Server_DH": "Server_DH",
    "Password": "Password",
    "Accept": "Accept",
    "List": "List",
    "UserList": "UserList",
    "RequestDetail": "RequestDetail",
    "ResponseDetail": "ResponseDetail",
    "Hello": "Hello",
    "HelloResponse": "HelloResponse",
    "PeerDHResponse": "PeerDHResponse",
    "PeerAccept": "PeerAccept",
    "InitialMessage": "InitialMessage",
    "Message": "Message",
    "HeartBeat": "HeartBeat",
    "Quit": "Quit",
    "Logout":"Logout",
    "LogoutResp": "LogoutResp"
}

exception_messages={
    'UnsupportedAlgorithm':'algorithm, or combination of algorithms is not supported'
}


# File names
USER_CRED_FILE='user_cred.txt'
PT_USER_CRED_FILE='pt_user_cred.json'
CONFIG_FILE='configuration.properties'

# Configuration file constant name
SERVER_SECTION='server'
S_PORT='s.port'
S_IP='s.ip'

# Properties keys name in properties map
SERVER_IP='s_ip'
SERVER_PORT='s_port'

