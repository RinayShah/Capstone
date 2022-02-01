import socket

HEADER = 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    socket.send(send_length)
    socket.send(message)
    print(socket.recv(2048).decode(FORMAT))

def encrypt(original_message, key):
    outText = []
    cryptText = []
    
    uppercase = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

    for eachLetter in original_message:    
        if eachLetter in uppercase:
            index = uppercase.index(eachLetter)
            crypting = (index + key) % 26
            cryptText.append(crypting)
            newLetter = uppercase[crypting]
            outText.append(newLetter)
        elif eachLetter in lowercase:
            index = lowercase.index(eachLetter)
            crypting = (index + key) % 26
            cryptText.append(crypting)
            newLetter = lowercase[crypting]
            outText.append(newLetter)
        elif eachLetter is ' ':
            outText.append(' ')
    return outText

if __name__ == "__main__":
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

    #send message
    if response == "Vehicle has been Registered.":
        socket.close()
    else:
        DOB = int(input("[*] Enter your date of birth in format \'YYMMDD\': "))
        key = sum(int(digit) for digit in str(DOB))
        print("[ ENCRYPTION KEY ] ...... SENDING ")
        send(str(key))
        msg = input("[ YOUR MESSAGE ] : ")
        encrypted_message = ''.join(encrypt(msg, key))
        print("[ ENCRYPTED MESSAGE ] : {}".format(encrypted_message))
        print("[ ENCRYPTED MESSAGE ] ...... SENDING")
        send(encrypted_message)

# Close Connection
socket.close()

