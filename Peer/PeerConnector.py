import socket as so
import re
from Configuration import *
from Address import Address

request_message = 'CONNECT AS {identifier} ON PORT {port}'
success_response = 'CONNECT TO (\\d+) WITH PORT (\\d+)'


class PeerConnector:

    def __init__(self, address: Address):
        self.address = address
        self.socket = so.socket(so.AF_INET, so.SOCK_STREAM)

    def connect(self):
        self.socket.connect((MANAGER_HOST, MANAGER_PORT))

    def send_connection_request(self):
        request = request_message.encode(str(self.address.id), str(self.address.port))
        self.socket.send(request.encode(ENCODING))
        return self.socket.recv(BUFFER_SIZE).decode(ENCODING)

    def handle(self):
        response = self.send_connection_request()
        x = re.match(response, success_response)
        if x is not None:
            parent_id = int(x.group(1))
            parent_port = int(x.group(2))
            parent_host = MANAGER_HOST
            return Address(parent_host, parent_port, parent_id)
        else:
            raise Exception("failed")

    def get_id(self):
        self.connect()
        return self.handle()
