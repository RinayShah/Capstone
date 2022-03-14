import socket
import threading
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import secrets

from sqlalchemy import false


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

# Hash Table for Vehicle Parameters
HashTable = {}

def client_registration(connection, address):

    # Generate Secret Key Ks
    Ks = str(secrets.token_bytes(8))[2:-1]

    connection.send(str.encode('Username: '))
    Huid = connection.recv(2048)
    Huid = Huid.decode()

    # Receive Password
    connection.send(str.encode('Password: '))
    Hpw = connection.recv(2048)
    Hpw = Hpw.decode()

    # Calculate Parameter A1
    Huid_Ks = Huid + " " + Ks
    a1 = hashlib.sha256(str.encode(Huid_Ks)).hexdigest()

    # Calculate Parameter B1
    Huid_Hpw = Huid + " " + Hpw
    temp = hashlib.sha256(str.encode(Huid_Hpw)).hexdigest()

   # b1 
    a = int(a1, base=16)
    b = int(temp, base=16)
    b1 = hex(a ^ b)


    # Store parameters a1 and b1
    if a1 not in HashTable:
        HashTable[a1] = b1
        
        connection.send(str.encode('Vehicle has been Registered.'))
        print(Huid, ' has been Registered.')
        print("{:<8}||{:<20}".format('\nA1', 'B1\n'))

        for k, v in HashTable.items():
            label, num = k, v
            print("{:<8} || {:<20}\n".format(label, num))
        print("______________________________________________")

        # Send username and password to client for future use. ENCODE BEFORE SENDING for security
        connection.send(str.encode(a1))
        print("\nA1 Sent")
        temp = connection.recv(2048)
        connection.send(str.encode(HashTable[a1]))
        print("B1 Sent")
        print("_______________________________________________")


        # Call Authentication Method
        authenticationTA(connection,b1,Ks,Huid,Hpw)

def authenticationTA(connection, B1_Auth, Ks, Huid, Hpw):
    # Second Block

    # Receive parameters from Vehicle
    Msg1 = connection.recv(2048)
    print('\nMsg1: ', Msg1.decode())
    connection.send(str.encode(" "))

    X1 = connection.recv(2048)
    print('X1: ', X1)
    connection.send(str.encode(" "))

    Tu = connection.recv(2048)
    print('Tu: ', Tu.decode())

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