from Util import *
from Address import Address
from Configuration import *
from PeerConnector import PeerConnector
import time
import socket as so
import threading
from PacketType import PacketType
from Node import Node
from Node import Child
from Node import Parent
from Util import decode_packet


class Peer:

    def __init__(self):
        self.address, parent_address = self.connect_to_network()
        self.parent = Parent(so.socket(so.AF_INET, so.SOCK_STREAM), parent_address)
        self.connect_to_parent()
        self.children = []

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
            self.children.append(child)
            threading.Thread(target=self.listen_to_child, args=(child,)).start()

    def connect_to_parent(self):
        self.parent.socket.connect((self.parent.address.host, self.parent.address.port))

    def advertise_to_parent(self):
        pass

    def listen_to_child(self, child: Child):
        while True:
            s = child.socket.recv(BUFFER_SIZE).decode(ENCODING)
            packet = decode_packet(s)
            self.handle_message(child, packet)
        pass

    def handle_message(self, child: Child, packet: Packet):
        if packet.type == PacketType.MESSAGE:
            pass
        elif packet.type == PacketType.ROUTING_REQUEST:
            self.handle_routing_request_packet(packet)  # todo: remove
        elif packet.type == PacketType.ROUTING_RESPONSE:
            pass
        elif packet.type == PacketType.PARENT_ADVERTISE:
            self.handle_parent_advertise_packet(child, packet)
        elif packet.type == PacketType.ADVERTISE:
            pass
        elif packet.type == PacketType.DESTINATION_NOT_FOUND_MESSAGE:
            pass
        elif packet.type == PacketType.CONNECTION_REQUEST:
            pass
        else:
            raise Exception("NOT SUPPORTED PACKET TYPE")

    def handle_parent_advertise_packet(self, child: Child, packet: Packet):
        subtree_child_id = parse_advertise_data(packet.data)
        child.add_sub_node_if_not_exists(subtree_child_id)
        if self.parent.address.id != NO_PARENT_ID:
            send_message_to_socket(
                self.parent.socket,
                make_parent_advertise_packet(
                    self.address.id,
                    self.parent.address.id,
                    subtree_child_id
                )
            )

    def handle_routing_request_packet(self, packet: Packet):
        if packet.destination_id == self.address.id:
            self.handle_routing_message_to_self(packet)
            return

        node = self.get_routing_request_destination_node(packet)
        send_message_to_socket(node.socket, packet)

    def get_routing_request_destination_node(self, packet: Packet) -> Node:
        for ch in self.children:
            if packet.destination_id in ch.sub_tree_child_ids:
                return ch

        return self.parent

    def handle_routing_message_to_self(self, packet: Packet):
        response_packet = make_routing_response_packet(self.address.id, packet.source_id)
        node = self.get_routing_request_destination_node(packet)
        send_message_to_socket(node.socket, response_packet)


if __name__ == '__main__':
    peer = Peer()
