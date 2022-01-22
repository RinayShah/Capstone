#!/usr/bin/env python3
import socket
import threading
import time

# variables
PORT = 9999
SERVER = socket.gethostbyname('localhost') # 127.0.0.1
ADDR = (SERVER, PORT)
HEADER = 64
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# creating socket and binding address and port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Address fami;y for ipv4 and socket streaming
server_socket.bind(ADDR)

def decrypt(encrypted_message, key):
    outText = []
    cryptText = []
    
    uppercase = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    lowercase = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

    for eachLetter in encrypted_message:    
        if eachLetter in uppercase:
            index = uppercase.index(eachLetter)
            crypting = (index - key) % 26
            cryptText.append(crypting)
            newLetter = uppercase[crypting]
            outText.append(newLetter)
        elif eachLetter in lowercase:
            index = lowercase.index(eachLetter)
            crypting = (index - key) % 26
            cryptText.append(crypting)
            newLetter = lowercase[crypting]
            outText.append(newLetter)
        elif eachLetter is ' ':
            outText.append(' ')
    return outText


def handle_client(conn, addr):
    # Handle clients connection 
    print("[NEW CONNECTION] {0} connected".format(addr))
    connected = True
    while connected:
        msg_length = conn.recv(HEADER).decode(FORMAT)
        if msg_length:
            msg_length = int(msg_length)
            msg = conn.recv(msg_length).decode(FORMAT)
            if msg == DISCONNECT_MESSAGE:
                connected = False
            elif is_int(msg) == True:
                print("[ DECRYPTION KEY ] .... RECEIVING")
                time.sleep(5)
                print("[ DECRYPTION KEY ] .... RECEIVED")
                # print("[{0}] {1}".format(addr, msg))
                key = int(msg)
            print(f"[ RECEIVED MESSAGED {addr}] : {str(msg)}")
            time.sleep(5)
            print("[ DECRYPTING MESSAGE ] ....")
            time.sleep(5)
            decrypted_message = ''.join(decrypt(msg, key))
            print("[ DECRYPTED MESSAGE FROM ] {} : {}".format(addr, decrypted_message))
            conn.send("Msg received".encode(FORMAT))
    conn.close()

def is_int(val):
    try:
        num = int(val)
    except ValueError:
        return False
    return True

def start():
    # Starts socket for connection 
    server_socket.listen()
    print("[LISTENTING] Server is listening on {}".format(SERVER))
    time.sleep(3)
    while True:
        conn, addr = server_socket.accept() # returns connection information 
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print("[ACTIVE CONNECTION] {0}".format(threading.activeCount() -1))

if __name__ == "__main__":
    print("Server is starting")
    start()