from Util import *
from Address import Address
from Configuration import *
from PeerConnector import PeerConnector
import time
import socket as so


class Peer:

    def __init__(self):
        self.address, self.parent_address = self.connect_to_network()

    def connect_to_network(self) -> (Address, Address):
        while True:
            try:
                return self.try_once()
            except Exception as e:
                print(e)
            time.sleep(0.5)

    @staticmethod
    def try_once() -> (Address, Address):
        port = get_random_port()
        identifier = get_random_id()
        address = Address(MANAGER_HOST, port, identifier)
        peer_connector = PeerConnector()
        return address, peer_connector.get_id(address)

    def handle(self):
        server = so.socket(so.AF_INET, so.SOCK_STREAM)
        server.bind((self.address.host, self.address.port))


if __name__ == '__main__':
    peer = Peer()
