from typing import Any, Optional, Union

from Util import *
from Address import Address
from Configuration import *
from PeerConnector import PeerConnector
import time
import socket as so
import threading
from PacketType import PacketType
from Node import *
from Util import decode_packet


class Peer:

    def __init__(self):
        self.address, parent_address = self.connect_to_network()
        self.parent = Parent(NodeType.PARENT, so.socket(so.AF_INET, so.SOCK_STREAM), parent_address)
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
            child = Child(NodeType.CHILD, client)
            self.children.append(child)
            threading.Thread(target=self.listen_to_node, args=(child,)).start()

    def connect_to_parent(self):
        self.parent.socket.connect((self.parent.address.host, self.parent.address.port))
        threading.Thread(target=self.listen_to_node, args=(self.parent,)).start()

    def listen_to_node(self, node: Node):
        while True:
            s = node.socket.recv(BUFFER_SIZE).decode(ENCODING)
            packet = decode_packet(s)
            self.handle_message(node, packet)
        pass

    def handle_message(self, node: Node, packet: Packet):
        if packet.type == PacketType.MESSAGE:
            pass
        elif packet.type == PacketType.ROUTING_REQUEST:
            self.handle_routing_request_packet(packet)
        elif packet.type == PacketType.ROUTING_RESPONSE:
            self.handle_routing_response_packet(node, packet)
        elif packet.type == PacketType.PARENT_ADVERTISE:
            self.handle_parent_advertise_packet(node, packet)
        elif packet.type == PacketType.ADVERTISE:
            pass
        elif packet.type == PacketType.DESTINATION_NOT_FOUND_MESSAGE:
            self.handle_destination_not_found_message(packet)
        elif packet.type == PacketType.CONNECTION_REQUEST:
            pass
        else:
            raise Exception("NOT SUPPORTED PACKET TYPE")

    def handle_parent_advertise_packet(self, node: Node, packet: Packet):
        assert isinstance(node, Child)
        subtree_child_id = parse_advertise_data(packet.data)
        node.add_sub_node_if_not_exists(subtree_child_id)
        if self.parent.address.id != NO_PARENT_ID:
            send_message_to_socket(
                self.parent.socket,
                make_parent_advertise_packet(
                    self.address.id,
                    self.parent.address.id,
                    subtree_child_id
                )
            )

    def handle_routing_request_packet(self, node: Node, packet: Packet):
        if packet.destination_id == self.address.id:
            self.handle_routing_request_to_self(packet)
            return

        forward_node = self.get_routing_request_destination_node(packet)
        if forward_node is None:
            self.send_destination_not_found_message(node, packet)
            return

        send_message_to_socket(forward_node.socket, packet)

    def send_destination_not_found_message(self, node: Node, packet: Packet):
        p = make_destination_not_found_message_packet(self.address.id, packet.source_id, packet.destination_id)
        send_message_to_socket(node.socket, p)

    def get_routing_request_destination_node(self, packet: Packet) -> Union[Optional[Parent], Any]:
        for ch in self.children:
            if packet.destination_id in ch.sub_tree_child_ids:
                return ch

        if self.parent.address.id != NO_PARENT_ID:
            return self.parent

        return None

    def handle_routing_request_to_self(self, packet: Packet):
        response_packet = make_routing_response_packet(self.address.id, packet.source_id)
        node = self.get_routing_request_destination_node(packet)
        send_message_to_socket(node.socket, response_packet)

    def handle_routing_response_packet(self, node: Node, packet: Packet):
        if packet.destination_id == self.address.id:
            self.handle_routing_response_to_self(packet)
            return

        forward_node = self.get_routing_request_destination_node(packet)

        if node.type == NodeType.PARENT:
            packet.data += '->{}'.format(self.address.id)
        elif node.type == NodeType.CHILD:
            packet.data += '<-{}'.format(self.address.id)
        else:
            raise Exception("invalid node type encountered")

        send_message_to_socket(forward_node.socket, packet)

    def handle_routing_response_to_self(self, packet: Packet):
        print(packet.data)

    def handle_destination_not_found_message(self, packet: Packet):
        forward_node = self.get_routing_request_destination_node(packet)
        send_message_to_socket(forward_node.socket, packet)


if __name__ == '__main__':
    peer = Peer()
