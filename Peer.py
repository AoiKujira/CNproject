from Util import *
from Address import Address
from Configuration import *
from PeerConnector import PeerConnector
from Packet import Packet
import time
import socket as so
import threading
from PacketType import PacketType
from Child import Child
from Messenger import *


class Peer:

    def __init__(self):
        self.address, self.parent_address = self.connect_to_network()
        self.parent_socket = None
        self.connect_to_parent()

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

    def listen(self):
        server = so.socket(so.AF_INET, so.SOCK_STREAM)
        server.bind((self.address.host, self.address.port))
        server.listen()

        while True:
            client, address = server.accept()
            child = Child(client)
            threading.Thread(target=self.listen_to_child, args=(child,)).run()

    def connect_to_parent(self):
        self.parent_socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        self.parent_socket.connect((self.parent_address.host, self.parent_address.port))

    def advertise_to_parent(self):
        pass

    def listen_to_child(self, child: Child):
        while True:
            s = child.socket.recv(BUFFER_SIZE).decode(ENCODING)
            packet = decode_packet(s)
            self.handle_message(packet)
        pass

    def handle_message(self, packet: Packet):
        if packet.type == PacketType.MESSAGE:
            pass
        elif packet.type == PacketType.ROUTING_REQUEST:
            pass
        elif packet.type == PacketType.ROUTING_RESPONSE:
            pass
        elif packet.type == PacketType.PARENT_ADVERTISE:
            pass
        elif packet.type == PacketType.ADVERTISE:
            pass
        elif packet.type == PacketType.DESTINATION_NOT_FOUND_MESSAGE:
            pass
        elif packet.type == PacketType.CONNECTION_REQUEST:
            pass
        else:
            raise Exception("NOT SUPPORTED PACKET TYPE")

    def send_message_to_socket(self, socket: so.socket, packet: Packet) -> None:
        s = encode_packet(packet)
        socket.send(s.encode(ENCODING))
        pass


if __name__ == '__main__':
    peer = Peer()
