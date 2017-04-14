SERVER_PRIVATE_KEY = "priv.der"
SERVER_PUBLIC_KEY = "pub.der"


BUFFER_SIZE = 1000

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
    0: "Reject",
    "Login": "Login",
    "test": "test",
    2: "Puzzle",
    3: "Solution",
    4: "Server_DH",
    5: "Password",
    6: "Accept",
    7: "List",
    8: "Logout",
    9: "Sender_Client_DH",
    10: "Dest_Client_DH",
    11: "Message",
    12: "Broadcast",
    13: "Heartbeat"
}


