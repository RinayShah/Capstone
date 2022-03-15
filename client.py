from cProfile import run
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import hashlib
import datetime

# VEHICLE
def hash(input_bytes):
    sha3_256 = hashlib.sha3_256(input_bytes)
    return sha3_256.digest()

def bytes_xor(one, two):
    return bytes(a ^ b for (a, b) in zip(one, two))

def authentication(socket,Huid,Hpw,b1):
 
    # First Block following formula in figure 3
    Hash_HUID_HPW = hash(Huid + Hpw)
   
    A1_Auth = bytes_xor(b1, Hash_HUID_HPW)

    Tu = str(datetime.datetime.now()) #Generate time stamp
    Tu = bytes(Tu, 'utf-8')
    Nu = (secrets.token_bytes(8))[2:-1] #Generate Random Nonce

    Msg1 = hash(A1_Auth + Tu + Hpw + Nu)
    Y1 = hash(b1 + Hpw)
    X1 = bytes_xor(Nu, Y1)

    # Send Parameters to Trusted Authority section of server 
    socket.send(Msg1)
    print("\nMsg1 send to Trusted Authority")
    socket.recv(2048)
    socket.send(X1)
    print("X1 send to Trusted Authority")
    socket.recv(2048)
    socket.send(Tu)
    print("Tu send to Trusted Authority")


    Msg2 = socket.recv(2048)
    print('\nMsg2: ', Msg2)
    socket.send(str.encode(" "))

    X2 = socket.recv(2048)
    print('X2: ', X2)
    socket.send(str.encode(" "))

    Tc = socket.recv(2048)
    print('Tc: ', Tc)
    
    HCID = socket.recv(2048)
    print('HCID: ', HCID)
   
   
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
