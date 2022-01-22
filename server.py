import socket
import threading
import hashlib

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


def client_registration(connection):

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
            connection.send(name, ' Successful in Connecting.')
        else:
            connection.send(str.encode('Unsuccessful (key does not match'))
            print(name, ' Unsuccessful in Connecting.')

    while True:
        break
    connection.close()


# While loop (main loop)
while True:

    # Connect to Client
    Client, address = socket.accept()

    clientHandler = threading.Thread(
        target=client_registration,
        args=(Client,)
    )

    clientHandler.start()
    numConnections += 1

    print('Connection Request Number: ' + str(numConnections))

socket.close()
