import socket as so
import threading
from Configuration import *

HOST = 'localhost'
PORT = 13991

server = so.socket(so.AF_INET, so.SOCK_STREAM)
server.bind((HOST, PORT))

server.listen()


def listen_to_client(s: so.socket):
    while True:
        req = s.recv(BUFFER_SIZE).decode(ENCODING)
        print(req)
        req += req
        s.send(req.encode(ENCODING))


while True:
    socket, address = server.accept()
    print(f'print accepted client with address {address}')
    threading.Thread(target=listen_to_client, args=(socket,)).start()
