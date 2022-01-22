#!/usr/bin/env python3
import socket

# variables
PORT = 9999
SERVER = socket.gethostbyname('localhost') # 127.0.0.1
ADDR = (SERVER, PORT)
HEADER = 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client_socket.send(send_length)
    client_socket.send(message)
    print(client_socket.recv(2048).decode(FORMAT))

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
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(ADDR)
    print("[CONNECTING] Connecting to server {}".format(SERVER))
    DOB = int(input("[*] Enter your date of birth in format \'YYMMDD\': "))
    key = sum(int(digit) for digit in str(DOB))
    print("[ ENCRYPTION KEY ] ...... SENDING ")
    send(str(key))
    msg = input("[ YOUR MESSAGE ] : ")
    encrypted_message = ''.join(encrypt(msg, key))
    print("[ ENCRYPTED MESSAGE ] : {}".format(encrypted_message))
    print("[ ENCRYPTED MESSAGE ] ...... SENDING")
    send(encrypted_message)