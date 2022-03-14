from cProfile import run
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import hashlib
import datetime;

# VEHICLE

def authentication(Huid,Hpw,b1):
 
    # First Block
    HUID_HPW = Huid + " " + Hpw
    Hash_HUID_HPW = hashlib.sha256(str.encode(HUID_HPW)).hexdigest()
   
    b1 =  int(b1, base=16)
    Hash_HUID_HPW = int(Hash_HUID_HPW, base=16)
    
    A1_Auth = b1 ^ Hash_HUID_HPW # I named A1 and B1 as A1_Auth and B1_Auth - we can change it

    A1_Auth_str = str(A1_Auth)
    b1_str = str(b1)
    Hpw_str = str(Hpw)

    Tu = str(datetime.datetime.now()) #Generate time stamp
    Nu = str(secrets.token_bytes(8))[2:-1] #Generate Random Nonce
    A1_Tu_HPW_Nu = A1_Auth_str + " " + Tu + " " + Hpw_str + " " + Nu

    Msg1 = hashlib.sha256(str.encode(A1_Tu_HPW_Nu)).hexdigest()
    Y1 = b1_str + " " + Hpw_str

    print(Tu)
    print(Nu)

    print("\n\n")
    
    Nu_int = int(Nu, base=16)
    Y1_int = int(Y1, base=16)
    X1 = Nu_int ^ Y1_int

    print("msg: ", Msg1)
    print("Y1: ", Y1)
    print("X1: ", X1)
    #Push Msg1, X1, Tu and SID

if __name__ == "__main__":
    # Create Socket
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define port number
    port = 8000

    # connect to the server on local computer
    socket.connect(('127.0.0.1', port))

    # Random Nonce
    Ru = str(secrets.token_bytes(8))[2:-1]

    # User input for potential Vehicle Name (Registration)
    response = socket.recv(2048)
    uID = input(response.decode())
    # Hash Username and Random Nonce and send to server as HUID
    uID_Ru = uID + " " + Ru
    Huid = hashlib.sha256(str.encode(uID_Ru)).hexdigest()
    socket.send(str.encode(Huid))

    # User input for Password
    response = socket.recv(2048)
    pW = input(response.decode())
    # Hash Password and Random Nonce and send to server as HPW
    pW_Ru = pW + " " + Ru
    Hpw = hashlib.sha256(str.encode(pW_Ru)).hexdigest()
    socket.send(str.encode(Hpw))

    # Receive status from Server
    response = (socket.recv(2048))
    response = response.decode()

    # Receive hashed username and password to vehicle/client for future use of vehicle
    if response == "Vehicle has been Registered.":
        # Receive parameters for authentication (Smart Card imitation)
        print("\n")
        print(response)
        a1 = socket.recv(2048)
        print('A1: ', a1.decode())
        socket.send(str.encode(" "))
        b1 = socket.recv(2048)
        print('B1: ', b1.decode())

        authentication(Huid,Hpw,b1)

