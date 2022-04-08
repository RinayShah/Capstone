from cProfile import run
import socket
import secrets
import hashlib
from time import time_ns
from Crypto import Random
import string
import threading
import pyaes

charList = string.ascii_lowercase + string.digits

# Vehicle
def hash(bytes):
    sha3_256 = hashlib.sha3_256(bytes)
    return sha3_256.digest()

def bytes_xor(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))

def generateRandomBytes(num_bytes):
    return Random.new().read(num_bytes)

def aes_encrypt(plaintext, key):
    aes = pyaes.AESModeOfOperationCTR(key)    
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def aes_decrypt(ciphertext, key):
    aes = pyaes.AESModeOfOperationCTR(key)
    decrypted = aes.decrypt(ciphertext).decode('utf-8')
    return decrypted

def handle_recv(sock, key):
    while True:
        msg = sock.recv(1024)
        print(f'\nCipher received: {msg}')
        print(f'Message received: {aes_decrypt(msg,key)}')
        print('Enter a message: ')

def authentication(socket,Huid,Hpw,b1):
 
    # First block of figure 3 starts here:
    A1_Auth = bytes_xor(b1,hash(Huid + Hpw))

    Tu = time_ns().to_bytes(length=8, byteorder='big')
    Nu = generateRandomBytes(8) #Generate Random Nonce

    Msg1 = hash(A1_Auth + Tu + Hpw + Nu)
    Y1 = hash(b1 + Hpw)
    X1 = bytes_xor(Nu, Y1)

    # Send Parameters to Trusted Authority section of server 
    socket.send(Msg1)
    print(f'Msg1 {Msg1}')
    socket.recv(2048)
    socket.send(X1)
    print(f'X1 {X1}')
    socket.recv(2048)
    socket.send(Tu)
    print(f'Tu {Tu}')
    print("\nMsg1, X1, Tu sent to Trusted Authority as per Protocol")
    print("\n_______________________________________________________\n")

    w = socket.recv(2048)
    print('\nReceived w: ', w)
    socket.send(str.encode(" "))

    X4 = socket.recv(2048)
    print('Received X4: ', X4)
    socket.send(str.encode(" "))

    Ns_star = bytes_xor(w, Hpw)
    print(f'Generated Ns* {Ns_star.hex()}')
    X4_recalculated = hash(Nu + Ns_star + Hpw)

    if X4_recalculated == X4:
        print('Trusted Authority X4 matches recalculated X4')
    else:
        print('Trusted Authority X4 does not match recalculated X4')
        
    CID = (0).to_bytes(length=8, byteorder='big')
    SID = (0).to_bytes(length=8, byteorder='big')
    HCID = hash(Huid + CID + SID)

    Sk_star = hash(HCID + Ns_star + Nu)
    print(f'Generated Sk* {Sk_star.hex()}')
    print("\n")
    
    session_key = Sk_star
    thread1 = threading.Thread(target=handle_recv, args=(socket, session_key))
    thread1.start()
    send_server_message(socket,session_key)
    

def send_server_message(socket,session_key):
    while True:
        msgToSend = input('Enter a message: ')
        cipherMsg = aes_encrypt(msgToSend,session_key)
        socket.send(cipherMsg)


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
        print ("\nReceived Parameters from Registration Authority as per Protocol")
        a1 = socket.recv(2048)
        print('A1: ', a1)
        socket.send(str.encode(" "))
        b1 = socket.recv(2048)
        print('B1: ', b1)

        print("\n_______________________________________________________\n")

        authentication(socket,Huid,Hpw,b1)