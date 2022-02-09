import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

if __name__ == "__main__":
    # Create Socket
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Define port number
    port = 8000

    # connect to the server on local computer
    socket.connect(('127.0.0.1', port))

    # User input for potential Vehicle Name (Registration Authority Process)
    response = socket.recv(2048)
    name = input(response.decode())
    socket.send(str.encode(name))

    # User input for Key -> To be modified so that it asks for key-
    # -only if already registered, otherwise system assigns key
    response = socket.recv(2048)
    key = input(response.decode())
    socket.send(str.encode(key))

    # Receive status from Server
    response = (socket.recv(2048))
    response = response.decode()
    print(response)

    #send message
    if response == "Vehicle has been Registered.":
        socket.close()
    else:
        message = "Client: OK"
        socket.send(str.encode(message))

        publickey = (socket.recv(2048))
        print(publickey)

        while True:
        #Convert string to key
            key = RSA.import_key(publickey)
            encryptor = PKCS1_OAEP.new(key)

            response = socket.recv(2048)
            encrypte_message = input(response.decode())
            encrypte_message = str.encode(encrypte_message)
            encrypted = encryptor.encrypt(encrypte_message)
            socket.send(encrypted)
            print("message sent")

            #Server's response
            server_response = (socket.recv(2048))
            server_response = server_response.decode()
            if server_response == "Server: OK":
                print ("Server decrypted message successfully")

# Close Connection
#socket.close()