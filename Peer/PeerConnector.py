import socket as so
from Configuration import *


class PeerConnector:

    def __init__(self, identifier, port):
        self.id = identifier
        self.port = port

        self.socket = None
        self.socket: so.socket

    def connect(self):
        self.socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        self.socket.connect((MANAGER_HOST, MANAGER_PORT))
        self.socket.recv(BUFFER_SIZE).decode(ENCODING)

    def send_connection_message(self):
        s = f'CONNECT AS {self.id} ON PORT {self.port}'
        self.socket.send(s.encode(ENCODING))

    def receive_message(self):
        self.socket.recv()

    def get_id(self):
        self.connect()
        self.send_connection_message()
        self.socket.




