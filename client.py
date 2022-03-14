from cProfile import run
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import hashlib
import datetime

# VEHICLE

def authentication(socket,Huid,Hpw,b1):
 
    # First Block following formula in figure 3
    HUID_HPW = Huid + " " + Hpw
    Hash_HUID_HPW = hashlib.sha256(str.encode(HUID_HPW)).hexdigest()
   
    #b1 =  int(b1, base=16)
    #Hash_HUID_HPW = int(Hash_HUID_HPW, base=16)
    A1_Auth = bytes(a ^ b for (a, b) in zip(b1, Hash_HUID_HPW))  

    # Convert to string to concatenate
    A1_Auth_str = str(A1_Auth)
    b1_str = str(b1)
    Hpw_str = str(Hpw)

    Tu = str(datetime.datetime.now()) #Generate time stamp
    Nu = str(secrets.token_bytes(8))[2:-1] #Generate Random Nonce
    A1_Tu_HPW_Nu = A1_Auth_str + " " + Tu + " " + Hpw_str + " " + Nu

    Msg1 = hashlib.sha256(str.encode(A1_Tu_HPW_Nu)).hexdigest()
    Y1 = b1_str + " " + Hpw_str
    Y1 = hashlib.sha256(str.encode(Y1)).hexdigest()
    print(f'Y1 value: {Y1}')

    Y1_b = bytes(Y1, 'utf-8')
    Nu_b = bytes(Nu, 'utf-8')
    X1 = bytes(a ^ b for (a, b) in zip(Nu_b, Y1_b))

    # Send Parameters to Trusted Authority section of server 
    socket.send(str.encode(Msg1))
    print("\nMsg1 send to Trusted Authority")
    socket.recv(2048)
    socket.send(X1)
    print("X1 send to Trusted Authority")
    socket.recv(2048)
    socket.send(str.encode(Tu))
    print("Tu send to Trusted Authority")


    Msg2 = socket.recv(2048)
    print('\nMsg2: ', Msg2.decode())
    socket.send(str.encode(" "))

    X2 = socket.recv(2048)
    print('X2: ', X2)
    socket.send(str.encode(" "))

    Tc = socket.recv(2048)
    print('Tc: ', Tc.decode())
    
    HCID = socket.recv(2048)
    print('HCID: ', HCID.decode())
   
   
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

        authentication(socket,Huid,Hpw,b1)

