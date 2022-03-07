from cProfile import run
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import hashlib
#import cryptohelper

# VEHICLE

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
        # Receive Password and Username for future use
        username = socket.recv(2048)
        print(isinstance(username, bytes))
        print('Username: ', username.decode())
        socket.send(str.encode("temp"))
        password = socket.recv(2048)
        print('Password: ', password.decode())
        socket.close()

    # If key 
    elif response == 'Unsuccessful (key does not match)': 
        print("Key and Vehicle Name do not match Registered Credentials\n")
        socket.close()
        exit()

    else:
        # DO SOMETHING IF KEY MATCHES AND REGISTRATION IS COMPLETE
        print("temp")

# Close Connection
# socket.close()
