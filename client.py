from cProfile import run
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import hashlib
from time import sleep, time_ns
from Cryptodome import Random, Util
from Cryptodome.Cipher import AES

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

# VEHICLE
def hash(input_bytes):
    sha3_256 = hashlib.sha3_256(input_bytes)
    return sha3_256.digest()

def bytes_xor(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))

def generate_random_n_bytes(n):
    return Random.new().read(n)

def authentication(socket,Huid,Hpw,b1):
 
    # First Block following formula in figure 3
    A1_Auth = bytes_xor(b1,hash(Huid + Hpw))

    Tu = time_ns().to_bytes(length=8, byteorder='big')
    Nu = generate_random_n_bytes(8) #Generate Random Nonce

    Msg1 = hash(A1_Auth + Tu + Hpw + Nu)
    Y1 = hash(b1 + Hpw)
    X1 = bytes_xor(Nu, Y1)

    # Send Parameters to Trusted Authority section of server 
    socket.send(Msg1)
    print(f'Msg1 {Msg1}')
    print("\nMsg1 send to Trusted Authority")
    socket.recv(2048)
    socket.send(X1)
    print("X1 send to Trusted Authority")
    socket.recv(2048)
    socket.send(Tu)
    print("Tu send to Trusted Authority")


    Msg2 = socket.recv(2048)
    print('\n Received Msg2: ', Msg2)
    socket.send(str.encode(" "))

    X2 = socket.recv(2048)
    print('Received X2: ', X2)
    socket.send(str.encode(" "))

    Tc = socket.recv(2048)
    print('Received Tc: ', Tc)
    
    HCID = socket.recv(2048)
    print('Received HCID: ', HCID)
   
    w = socket.recv(2048)
    print('\n Received w: ', w)
    socket.send(str.encode(" "))

    X4 = socket.recv(2048)
    print('Received X4: ', X4)
    socket.send(str.encode(" "))

    Ns_star = bytes_xor(w, Hpw)
    print(f'Generated Ns* {Ns_star.hex()}')
    X4_recalc = hash(Nu + Ns_star + Hpw)
    if X4_recalc == X4:
        print('X4 verification succeeded')
    else:
        print('X4 verification failed')
        
    CID = (0).to_bytes(length=8, byteorder='big')
    SID = (0).to_bytes(length=8, byteorder='big')
    HCID = hash(Huid + CID + SID)
    Sk_star = hash(HCID + Ns_star + Nu)
    print(f'Generated Sk* {Sk_star.hex()}')
    session_key = Sk_star
    send_server_message(socket,session_key)

def send_server_message(socket, session_key):
    while True:
        message = input("Enter a message to send the server: ")
        encrypt_and_send_message(socket, message.encode(), session_key)
        received = receive_message_and_decrypt(socket, session_key)
        print(f"Message from server {received}")


    #Push Msg1, X1, Tu and SID

if __name__ == "__main__":
    # Create Socket
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define port number
    port = 8000

    # connect to the server on local computer
    socket.connect(('127.0.0.1', port))

    # Random Nonce
    Ru = secrets.token_bytes(8)[2:-1]

    # User input for potential Vehicle Name (Registration)
    response = socket.recv(2048)
    uID = input(response)
    uID = bytes(uID, 'utf-8')
    # Hash Username and Random Nonce and send to server as HUID
    Huid = hash(uID + Ru)
    socket.send(Huid)

    # User input for Password
    response = socket.recv(2048)
    pW = input(response)
    pW = bytes(pW, 'utf-8')
    # Hash Password and Random Nonce and send to server as HPW
    Hpw = hash(pW + Ru)
    socket.send(Hpw)


    # Receive status from Server
    response = (socket.recv(2048))
    response = response.decode()

    # Receive hashed username and password to vehicle/client for future use of vehicle
    if response == "Vehicle has been Registered.":
        # Receive parameters for authentication (Smart Card imitation)
        print("\n")
        print(response)
        a1 = socket.recv(2048)
        print('A1: ', a1)
        socket.send(str.encode(" "))
        b1 = socket.recv(2048)
        print('B1: ', b1)

        authentication(socket,Huid,Hpw,b1)
