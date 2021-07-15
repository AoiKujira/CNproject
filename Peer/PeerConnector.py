import socket as so
import re
from Configuration import *
from Address import Address

request_message = '{identifier} {port}'
success_response = 'CONNECT TO (\\d+) WITH PORT (\\d+)'


class PeerConnector:

    def __init__(self):
        self.socket = so.socket(so.AF_INET, so.SOCK_STREAM)

    def send_connection_request(self, address: Address) -> str:
        request = request_message.encode(str(address.id), str(address.port))
        self.socket.send(request.encode(ENCODING))
        return self.socket.recv(BUFFER_SIZE).decode(ENCODING)

    def handle(self, address: Address) -> Address:
        response = self.send_connection_request(address)
        x = re.match(response, success_response)
        if x is not None:
            parent_id = int(x.group(1))
            parent_port = int(x.group(2))
            parent_host = MANAGER_HOST
            return Address(parent_host, parent_port, parent_id)
        else:
            raise Exception("failed")

    def get_id(self, address: Address) -> Address:
        self.socket.connect((MANAGER_HOST, MANAGER_PORT))
        try:
            return self.handle(address)
        finally:
            self.socket.close()
