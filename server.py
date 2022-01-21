import socket

# Create Socket
sock = socket.socket()

print ("Socket successfully created")

# reserve port number
port = 8000

# Bind socket to port and set to listening
sock.bind(('', port))
print ("socket binded to %s" %(port))
sock.listen(5)
print ("socket is listening")

# While loop (main loop)
while True:

    # Connect to Client
    c, addr = sock.accept()
    print ('Got connection from', addr )

    c.send('Thank you for connecting'.encode())

    # Close Client Connection and break from while loop
    c.close()
    break
