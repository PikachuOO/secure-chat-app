SERVER_CONFIG_FILE = "server-config.json"
SERVER_PUBLIC_KEY = "server_public_key.der"
SERVER_PRIVATE_KEY = "server_private_key.der"

BUFFER_SIZE = 1024

message_type = {
    "SIGN_IN": 0,
    "CHALLENGE": 1,
    "CHALLENGE_RESPONSE": 2,
    "SERVER_CLIENT_DH": 3,
    "CLIENT_SERVER_DH": 4,
    "LIST": 5,
    "LIST_RESPONSE": 6,
    "REQUEST_CLIENT": 7,
    "CLIENT_DETAIL": 8,
    "HELLO": 9,
    "DEST_SOURCE_DH": 10,
    "SOURCE_DEST_DH": 11,
    "LOGOUT": 12,
    "BROADCAST": 13,
    "ALIVE": 14

}

message_mapping = {
    0: "SIGN_IN",
    1: "CHALLENGE",
    2: "CHALLENGE_RESPONSE",
    3: "SERVER_CLIENT_DH",
    4: "CLIENT_SERVER_DH",
    5: "LIST",
    6: "LIST_RESPONSE",
    7: "REQUEST_CLIENT",
    8: "CLIENT_DETAIL",
    9: "HELLO",
    10: "DEST_SOURCE_DH",
    11: "SOURCE_DEST_DH",
    12: "LOGOUT",
    13: "BROADCAST",
    14: "ALIVE"
}