import socket
import threading
import hashlib
import time

HEADER = 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# Create Socket
socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
print("Socket successfully created")

# reserve port number
port = 8000

# Handling multiple connections (possibly)
numConnections = 0

# Bind socket to port or print error
try:
    socket.bind(('', port))
except socket.error as e:
    print(str(e))

# Socket listening
print("socket binded to %s" % port)
print("socket is waiting for connection")
socket.listen(5)

# Hash Table for Clients (i.e., vehicles)
HashTable = {}


def decrypt(encrypted_message, key):
    outText = []
    cryptText = []
    
    uppercase = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

    for eachLetter in encrypted_message:    
        if eachLetter in uppercase:
            index = uppercase.index(eachLetter)
            crypting = (index - key) % 26
            cryptText.append(crypting)
            newLetter = uppercase[crypting]
            outText.append(newLetter)
        elif eachLetter in lowercase:
            index = lowercase.index(eachLetter)
            crypting = (index - key) % 26
            cryptText.append(crypting)
            newLetter = lowercase[crypting]
            outText.append(newLetter)
        elif eachLetter is ' ':
            outText.append(' ')
    return outText

def is_int(val):
    try:
        num = int(val)
    except ValueError:
        return False
    return True

def client_registration(connection, address):

    connection.send(str.encode('Registration Name: '))
    name = connection.recv(2048)
    name = name.decode()

    # Key for registration (password) -> to be updated based on security protocol
    connection.send(str.encode('Registration Key: '))
    key = connection.recv(2048)
    key = key.decode()

    # key hash
    key = hashlib.sha256(str.encode(key)).hexdigest()

    # If not in HashTable, register
    if name not in HashTable:
        HashTable[name] = key
        connection.send(str.encode('Vehicle has been Registered.'))
        print(name, ' has been Registered.')
        print("{:<8} {:<20}".format('Name', 'Key'))

        for k, v in HashTable.items():
            label, num = k, v
            print("{:<8} {:<20}".format(label, num))
        print("______________________________________________")

    # Check password if already in HashTable (we may not need this part)
    else:
        if HashTable[name] == key:
            connection.send(str.encode('Successful (key matches).'))
            #connection.send(name, ' Successful in Connecting.')
            connected = True
            while connected:
                msg_length = connection.recv(HEADER).decode(FORMAT)
                if msg_length:
                    msg_length = int(msg_length)
                    msg = connection.recv(msg_length).decode(FORMAT)
                    if msg == DISCONNECT_MESSAGE:
                        connected = False
                    elif is_int(msg) == True:
                        print("[ DECRYPTION KEY ] .... RECEIVING")
                        time.sleep(5)
                        print("[ DECRYPTION KEY ] .... RECEIVED")
                        # print("[{0}] {1}".format(addr, msg))
                        key = int(msg)
                    print(f"[ RECEIVED MESSAGED {name}] : {str(msg)}")
                    time.sleep(5)
                    print("[ DECRYPTING MESSAGE ] ....")
                    time.sleep(5)
                    decrypted_message = ''.join(decrypt(msg, key))
                    print("[ DECRYPTED MESSAGE FROM ] {} : {}".format(name, decrypted_message))
                    connection.send("Msg received".encode(FORMAT))
            connection.close()
        else:
            connection.send(str.encode('Unsuccessful (key does not match)'))
            print(name, ' Unsuccessful in Connecting.')

    while True:
        break
    connection.close()

def start():
    # While loop (main loop)
    numConnections = 0
    while True:
        # Connect to Client
        Client, address = socket.accept()
        clientHandler = threading.Thread(target=client_registration, args=(Client,address))
        clientHandler.start()
        numConnections += 1

        print('Connection Request Number: ' + str(numConnections))

if __name__ == "__main__":
    print("Server is starting")
    start()
