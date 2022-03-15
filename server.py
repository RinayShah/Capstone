import socket
import threading
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import secrets
from time import sleep, time_ns
from sqlalchemy import false
from Cryptodome.Cipher import AES

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

def send_message(connection, message):
# Protocol is the message's byte length (padded to 5 bytes) followed by the message contents
    byte_length = len(message).to_bytes(length=5, byteorder='big')
    connection.sendall(byte_length + message)

def receive_message(connection):
    # Receive 5 bytes to get message byte length
    data_received = connection.recv(5, socket.MSG_WAITALL)
    if not data_received:
        return -1
    byte_length = int.from_bytes(bytes=data_received, byteorder='big')
    # Receive byte_length bytes to get message
    data_received = connection.recv(byte_length, socket.MSG_WAITALL)
    if not data_received:
        return -1
    return data_received

def encrypt(plain_bytes, secret_key):
# mac_len is tag length (16 bytes)
    aes_object = AES.new(key=secret_key, mode=AES.MODE_GCM, mac_len=16)
    cipher_bytes, tag = aes_object.encrypt_and_digest(plain_bytes)
    # 16 bytes for tag followed by 16 bytes for nonce followed by the cipher bytes
    return tag + aes_object.nonce + cipher_bytes

# Decrypts the given dictionary and secret key using AES-GCM.
def decrypt(encrypted_bytes, secret_key):
    tag = encrypted_bytes[:16]
    nonce = encrypted_bytes[16:32]
    cipher_bytes = encrypted_bytes[32:]
    aes_object = AES.new(key=secret_key, mode=AES.MODE_GCM, nonce=nonce)
    decrypted = aes_object.decrypt_and_verify(cipher_bytes, tag)
    return decrypted

def encrypt_and_send_message(connection, message, secret_key):
    message = encrypt(message, secret_key)
    send_message(connection, message)

# Call receive_message(connection) and decrypt the message using secret_key.
def receive_message_and_decrypt(connection, secret_key):
    data_received = receive_message(connection)
    if data_received == -1:
        return -1

    return decrypt(data_received, secret_key)

def hash(input_bytes):
    sha3_256 = hashlib.sha3_256(input_bytes)
    return sha3_256.digest()

def bytes_xor(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))

def generate_random_n_bytes(n):
    return Random.new().read(n)

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
    Y1_star = hash(b1 + Hpw)
    Nu_Star = bytes_xor(X1, Y1_star)
    Msg1_recalc = hash(A1 + Tu +  Hpw + Nu_Star)

    if Msg1_recalc == Msg1:
        print('Vehicle index Msg1 verification succeeded')
    else:
        print('Vehicle Msg1 verification failed')

    CID = (0).to_bytes(length=8, byteorder='big') #we may not need this if it is being passed
    SID = (0).to_bytes(length=8, byteorder='big') #we may not need this if it is being passed
    HCID = hash(Huid + CID + SID)
    #HCID = hashlib.sha256(str.encode(Huid_CID_SID)).hexdigest()
    Tc = time_ns().to_bytes(length=8, byteorder='big')  # Generate time stamp
    Msg2 = hash(HCID + Ks + Tc + Nu_Star)
    #Msg2 = hashlib.sha256(str.encode(HCID_Ks_Tc_Nu)).hexdigest()
    print(f'Msg2 {Msg2}')
    ks_hash = hash(Ks)
    X2 = bytes_xor(Nu_Star, ks_hash)
    print(f'X2 {X2}')

    connection.send(Msg2)
    print("\nMsg2 send to Trusted Authority")
    connection.recv(2048)
    connection.send(X2)
    print("X2 send to Trusted Authority")
    connection.recv(2048)
    connection.send(Tc)
    print("TC send to Trusted Authority")
    connection.send(HCID)
    print("HCID send to Trusted Authority")


    Ns = generate_random_n_bytes(8)
    print(f'Vehicle Generated Ns {Ns.hex()}')
    Sk = hash(HCID + Ns + Nu_Star)
    print(f'Vehicle Generated Sk {Sk.hex()}')
    Ts = time_ns().to_bytes(length=8, byteorder='big')
    X3 = hash(Nu_Star + Ns + Ts + Ks)
    Msg3 = bytes_xor(Ns, Nu_Star)
    w = bytes_xor(Ns, Hpw)
    X4 = hash(Nu_Star + Ns + Hpw)

    connection.send(w)
    print("\nw sent to Trusted Authority")
    connection.recv(2048)
    connection.send(X4)
    print("X4 sent to Trusted Authority")
    connection.recv(2048)
    session_key = Sk
    send_client_message(connection, session_key)

    #Push Msg2, X2, Tc and HCID to Vehicle Server
def send_client_message(connection, session_key):
    while True:
        message = input("Enter a message to send the client: ")
        encrypt_and_send_message(connection, message.encode(), session_key)
        received = receive_message_and_decrypt(connection, session_key)
        print(f"Message from clinet {received}")

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