import socket
import threading
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import secrets
import datetime
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

def hash(input_bytes):
    sha3_256 = hashlib.sha3_256(input_bytes)
    return sha3_256.digest()

def bytes_xor(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))

def client_registration(connection, address):

    # Generate Secret Key Ks
    Ks = (secrets.token_bytes(8))[2:-1]

    connection.send(str.encode('Username: '))
    Huid = connection.recv(2048)
    #Huid = Huid.decode()

    # Receive Password
    connection.send(str.encode('Password: '))
    Hpw = connection.recv(2048)
    #Hpw = Hpw.decode()

    # Calculate Parameter A1
    Huid_Ks = Huid + Ks
    a1 = hash(Huid_Ks)

    # Calculate Parameter B1
    Huid_Hpw = hash(Huid + Hpw)

   # b1 
    #a = bytes()
    #b = int(temp, base=16)
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
        print("______________________________________________")

        # Send username and password to client for future use. ENCODE BEFORE SENDING for security
        connection.send(a1)
        print("\nA1 Sent")
        temp = connection.recv(2048)
        connection.send(HashTable[a1])
        print("B1 Sent")
        print("_______________________________________________")


        # Call Authentication Method
        authenticationTA(connection,a1,b1,Ks,Huid,Hpw)

def authenticationTA(connection,A1, b1, Ks, Huid, Hpw):
    # Second Block

    # Receive parameters from Vehicle
    Msg1 = connection.recv(2048)
    print('\nMsg1: ', Msg1)
    connection.send(str.encode(" "))

    X1 = connection.recv(2048)
    print('X1: ', X1)
    connection.send(str.encode(" "))

    Tu = connection.recv(2048)
    print('Tu: ', Tu)

    #b1_b = bytes(b1, 'utf-8')
    #Hpw_b = bytes(Hpw, 'utf-8')
    B1Auth_Hpw = bytes_xor(b1, Hpw)
    print(f'b1Auth_hpw: {B1Auth_Hpw}')
    Y1_Star = hash(B1Auth_Hpw)
    print(f'Y1_Star value: {Y1_Star}')
    #Y1_Star_b = bytes(Y1_Star, 'utf-8')
    Nu_Star = bytes_xor(X1, Y1_Star)
    print(f'Nu_star value: {Nu_Star}')
    Msg1_recalc = hash(A1 + Tu +  Hpw + Nu_Star)
    print(f'msg1_recalc: {Msg1_recalc}')

    if Msg1_recalc == Msg1:
        print('Vehicle index Msg1 verification succeeded')
    else:
        print('Vehicle Msg1 verification failed')
    Msg1 = hashlib.sha256(str.encode(Msg1_recalc)).hexdigest()
    CID = (0).to_bytes(length=8, byteorder='big') #we may not need this if it is being passed
    SID = (0).to_bytes(length=8, byteorder='big') #we may not need this if it is being passed
    HCID = hash(Huid + CID + SID)
    #HCID = hashlib.sha256(str.encode(Huid_CID_SID)).hexdigest()
    Tc = (datetime.datetime.now())  # Generate time stamp
    Msg2 = hash(HCID + Ks + Tc + Nu_Star)
    #Msg2 = hashlib.sha256(str.encode(HCID_Ks_Tc_Nu)).hexdigest()
    print(f'Msg2 {Msg2}')
    ks_hash = hash(Ks)
    X2 = bytes_xor(Nu_Star, ks_hash)
    print(f'X2 {X2}')

    connection.send(str.encode(Msg2))
    print("\nMsg2 send to Trusted Authority")
    connection.recv(2048)
    connection.send(X2)
    print("X2 send to Trusted Authority")
    connection.recv(2048)
    connection.send(str.encode(Tc))
    print("TC send to Trusted Authority")
    connection.send(str.encode(HCID))
    print("HCID send to Trusted Authority")

    #Push Msg2, X2, Tc and HCID to Vehicle Server

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