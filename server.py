import socket
import threading
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import secrets
from time import time_ns
from sqlalchemy import false
import ast
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
import string

charList = string.ascii_lowercase + string.digits

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

random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

<<<<<<< HEAD
def append_space_padding(text, blocksize=8):
    while len(text) % blocksize != 0:
        text += ' '
    return text

def des_encrypt(plaintext, key):
    des = DES.new(key, DES.MODE_ECB)
    cypher = des.encrypt(str.encode(append_space_padding(plaintext)))
    return cypher

def des_decrypt(ciphertext, key):
    des = DES.new(key, DES.MODE_ECB)
    plain = des.decrypt(ciphertext).decode()
    return plain

def hash(input_bytes):
    sha3_256 = hashlib.sha3_256(input_bytes)
=======
def hash(bytes):
    sha3_256 = hashlib.sha3_256(bytes)
>>>>>>> b95a071407224e2ba2d34e7f5973a5584f5b6ba8
    return sha3_256.digest()

def bytes_xor(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))

def generateRandomBytes(num_bytes):
    return Random.new().read(num_bytes)

def handle_recv(sock, key):
    while True:
        msg = sock.recv(1024)
        print(f'\nCipher received: {msg}')
        print(f'Message received: {des_decrypt(msg, key)}')
        print('Enter a message: ')

def client_registration(connection, address):

    # Generate Secret Key Ks
    Ks = (secrets.token_bytes(8))[2:-1]

    connection.send(str.encode('Username: '))
    Huid = connection.recv(2048)

    # Receive Password
    connection.send(str.encode('Password: '))
    Hpw = connection.recv(2048)

    # Calculate Parameter A1
    Huid_Ks = Huid + Ks
    a1 = hash(Huid_Ks)

    # Calculate Parameter B1
    Huid_Hpw = hash(Huid + Hpw)

    b1 = bytes_xor(a1, Huid_Hpw)


    # Store parameters a1 and b1
    if a1 not in HashTable:
        HashTable[a1] = b1
        
        connection.send(str.encode('Vehicle has been Registered.'))
        print(Huid, ' has been Registered.')
        print("{:<8}||{:<20}".format('\nA1', 'B1\n'))
        
        for k, v in HashTable.items():
            label, num = k, v
            print("{:<8} || {:<20}\n".format(str(label), str(num)))
        print("_______________________________________________________")

        # Send username and password to client for future use. ENCODE BEFORE SENDING for security
        connection.send(a1)
        print("\nA1 Sent to Client as per Registration Process")
        temp = connection.recv(2048)
        connection.send(HashTable[a1])
        print("B1 Sent to Client as per Registration Process")
        print("_______________________________________________________")


        # Call Authentication Method
        authenticationTA_1(connection,a1,b1,Ks,Huid,Hpw)

# Trusted Authority portion of protocol when sending to Vehicle Server
def authenticationTA_1(connection, A1, b1, Ks, Huid, Hpw):
    # Second Block

    # Receive parameters from Vehicle
    print("\nReceived Parameters from Vehicle: ")
    Msg1 = connection.recv(2048)
    print('\nMsg1: ', Msg1)
    connection.send(str.encode(" "))

    X1 = connection.recv(2048)
    print('X1: ', X1)
    connection.send(str.encode(" "))

    Tu = connection.recv(2048)
    print('Tu: ', Tu)

    print("\n_______________________________________________________\n")

    Y1_star = hash(b1 + Hpw)
    Nu_Star = bytes_xor(X1, Y1_star)
    Msg1_recalculated = hash(A1 + Tu +  Hpw + Nu_Star)

    # Check to see if message sent from Vehicle matches recalculated
    if Msg1_recalculated == Msg1:
        print('\nVehicle Msg1 matches recalcualted Msg1 according to Protocol\n')
    else:
        print('\nVehicle Msg1 does not match Msg1\n')

    CID = (0).to_bytes(length=8, byteorder='big') #we may not need this if it is being passed
    SID = (0).to_bytes(length=8, byteorder='big') #we may not need this if it is being passed
    HCID = hash(Huid + CID + SID)
    
    Tc = time_ns().to_bytes(length=8, byteorder='big')  # Generate time stamp
    Msg2 = hash(HCID + Ks + Tc + Nu_Star)
    ks_hash = hash(Ks)
    X2 = bytes_xor(Nu_Star, ks_hash)

    # Print Parameters being sent to Vehicle Server
    print('Msg2', Msg2)
    print('X2', X2)
    print("Tc: ", Tc)
    print("HCID: ", HCID)


    print("\nMsg2, X2, Tc, HCID sent to Vehicle Server as per Protocol")

    print("\n_______________________________________________________\n")

    # Ks is being sent because in protocol Vehicle Server would already have Ks
    Msg3, X3, Ts, Sk = authenticationVehicleServer(Msg2, X2, Tc, HCID, Ks)

    # After Vehicle Server sends parameters back
    Ns_star = bytes_xor(Msg3, Nu_Star)
    X3_recalculated = hash(Nu_Star + Ns_star + Ts + Ks)

    # Check to see if X3 sent from Vehicle Server matches recalculated
    if X3_recalculated == X3:
        print('\nVehicle Server X3 matches recalcualted X3 according to Protocol\n')
    else:
        print('\nVehicle Server X3 does not match recalculated X3\n')

    w = bytes_xor(Ns_star, Hpw)
    X4 = hash(Nu_Star + Ns_star + Hpw)
    
    # Print parameters being sent to Vehicle
    
    
    connection.send(w)
    connection.recv(2048)
    connection.send(X4)
    connection.recv(2048)
    print("w: ", w)
    print("X4: ", X4)
    print("w, X4 sent to Vehicle as per Protocol")
    print("\n")
    
    session_key = Sk[:8]
    thread1 = threading.Thread(target=handle_recv, args=(connection, session_key))
    thread1.start()
    send_client_message(connection,session_key)


# Vehicle Server portion of Protocol
def authenticationVehicleServer(Msg2, X2, Tc, HCID, Ks): 
    ks_hash = hash(Ks)
    Nu_star = bytes_xor(X2, ks_hash)
    Msg2_recalculated = hash(HCID + Ks + Tc + Nu_star)

    # Check to see if message sent from TA matches recalculated
    if Msg2_recalculated == Msg2:
        print('\nTrusted Authority Msg2 matches recalcualted Msg2 according to Protocol\n')
    else:
        print('\nTrusted Authority Msg2 does not match reacalculated Msg2\n')

    # Generate a Random Nonce: Ns
    Ns = generateRandomBytes(8)
    Sk = hash(HCID + Ns + Nu_star)
    # Generate time stamp in byte form
    Ts = time_ns().to_bytes(length=8, byteorder='big')
    X3 = hash(Nu_star + Ns + Ts + Ks)
    Msg3 = bytes_xor(Ns, Nu_star)

    # Print parameters being sent back to Trusted Authority
    print("Msg3: ", Msg3)
    print("X3: ", X3)
    print("Ts: ", Ts)

    print("\nMsg3, X3, Ts sent to Trusted Authority as per Protocol")

    print("\n_______________________________________________________\n")

    return(Msg3, X3, Ts, Sk)



def send_client_message(connection,session_key):
    while True:
        msgToSend = input('Enter a message: ')
        cipherMsg = des_encrypt(msgToSend, session_key)
        connection.send(cipherMsg)

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