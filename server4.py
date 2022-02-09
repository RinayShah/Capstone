import socket
import threading
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import ast

from sqlalchemy import false

# Keys for Trusted Authority Process
#Generate private and public keys
random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()
encrypt_str = "encrypted_message="

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

def client_registration(connection, address):

    connection.send(str.encode('Registration Name: '))
    name = connection.recv(2048)
    name = name.decode()

    # Registration Authority Process
    # Key for registration (password) -> to be updated based on security protocol
    connection.send(str.encode('Registration Key: '))
    key = connection.recv(2048)
    key = key.decode()

    # key hash Registration Authority process works with Trusted Authority process
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

    else:
        # Check password if already in HashTable 
        if HashTable[name] == key:
            connection.send(str.encode('Successful (key matches).'))
            message = connection.recv(2048)
            message = message.decode()
            print(message)

            if message == "Client: OK":
                connection.send(public_key.exportKey())
                print ("Public key sent to client.")
            connected = True
            # Encryption process is part of Trusted Authority Process
            while connected:
                connection.send(str.encode('Enter Message: '))
                encrypted_text = connection.recv(2048)
                decryptor = PKCS1_OAEP.new(private_key)
                decrypted = decryptor.decrypt(ast.literal_eval(str(encrypted_text)))
                print ("Decrypted message = " + str(decrypted.decode()))
                connection.send(str.encode("Server: OK"))
                #connected = False
        else:
            connection.send(str.encode('Unsuccessful (key does not match)'))
            print(name, ' Unsuccessful in Connecting.')

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
