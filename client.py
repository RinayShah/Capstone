import socket

# Create Socket
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define port number
port = 8000

# connect to the server on local computer
socket.connect(('127.0.0.1', port))

# User input for potential Vehicle Name (Registration)
response = socket.recv(2048)
name = input(response.decode())
socket.send(str.encode(name))

# User input for Key -> To be modified so that it asks for key
# only if already registered, otherwise system assigns key
response = socket.recv(2048)
key = input(response.decode())
socket.send(str.encode(key))

# Receive status from Server
response = (socket.recv(2048))
response = response.decode()
print(response)

# Close Connection
socket.close()

