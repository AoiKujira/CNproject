from Util import *
from Address import Address
from Configuration import *
from PeerConnector import PeerConnector
import time


class Peer:

    @staticmethod
    def try_once() -> Address:
        port = get_random_port()
        identifier = get_random_id()
        address = Address(MANAGER_HOST, port, identifier)
        peer_connector = PeerConnector()
        return peer_connector.get_id(address)

    def connect_to_network(self) -> Address:
        while True:
            try:
                return self.try_once()
            except Exception as e:
                print(e)
            time.sleep(0.5)

    def __init__(self):
        self.parent_address = None
        self.address = self.connect_to_network()
        print(self.address)


if __name__ == '__main__':
    peer = Peer()
