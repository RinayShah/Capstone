import socket

# Create Socket
sock = socket.socket()

# Define port number
port = 8000

# connect to the server on local computer
sock.connect(('127.0.0.1', port))

# receive data from server
print(sock.recv(1024).decode())

# Close Connection
sock.close()

