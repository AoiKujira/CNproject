import re
import threading
from typing import Any, Optional, Union

from Configuration import *
from Node import *
from PeerConnector import PeerConnector
from Util import *

connect_command = 'CONNECT AS (\\d+|-\\d+) ON PORT (\\d+|-\\d+)'


class Peer:

    def __init__(self):
        self.address = None
        self.parent_address = None
        self.parent = None
        self.children = []
        self.server = None
        threading.Thread(target=self.terminal).run()

    def terminal(self):
        while True:
            command = input("$Enter command:")
            x = re.match(connect_command, command)
            if x is not None:
                try:
                    identifier = int(x.group(1))
                    port = int(x.group(2))
                    self.connect_to_network(port, identifier)
                    self.start_listening()
                    self.send_connection_request_to_parent()
                except Exception as e:
                    print(e)
                    exit(0)
                continue
            x = re.match(connect_command, command)
            if x is not None:
                pass

    def connect_to_network(self, port: int, identifier: int):
        address = Address(MANAGER_HOST, port, identifier)
        peer_connector = PeerConnector()
        self.parent_address = peer_connector.negotiate_address_with_manager(address)
        self.address = address

    def start_listening(self):
        self.server = so.socket(so.AF_INET, so.SOCK_STREAM)
        self.server.bind((self.address.host, self.address.port))
        threading.Thread(target=self.listen).start()

    def listen(self):
        while True:
            socket, address = self.server.accept()
            self.parent = Parent(NodeType.PARENT, socket, self.parent_address)
            self.advertise_to_parent()
            threading.Thread(target=self.listen_to_node, args=(self.parent,)).start()

    def send_connection_request_to_parent(self):
        if self.parent_address.id == NO_PARENT_ID:
            return
        socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        socket.connect((self.parent_address.host, self.parent_address.port))
        packet = make_connection_request_packet(self.address.id, self.parent_address.id, self.address.port)
        send_packet_to_node(self.parent, packet)
        socket.close()

    def advertise_to_parent(self):
        packet = make_parent_advertise_packet(self.address.id, self.parent.id, self.address.id)
        send_packet_to_node(self.parent, packet)

    def listen_to_node(self, node: Node):
        while True:
            s = node.socket.recv(BUFFER_SIZE).decode(ENCODING)
            packet = decode_packet(s)
            self.handle_message(node, packet)

    def handle_message(self, node: Node, packet: Packet):
        if packet.type == PacketType.MESSAGE:
            pass
        elif packet.type == PacketType.ROUTING_REQUEST:
            self.handle_routing_request_packet(node, packet)
        elif packet.type == PacketType.ROUTING_RESPONSE:
            self.handle_routing_response_packet(node, packet)
        elif packet.type == PacketType.PARENT_ADVERTISE:
            self.handle_parent_advertise_packet(node, packet)
        elif packet.type == PacketType.ADVERTISE:
            pass
        elif packet.type == PacketType.DESTINATION_NOT_FOUND_MESSAGE:
            self.handle_destination_not_found_message(packet)
        elif packet.type == PacketType.CONNECTION_REQUEST:
            self.handle_connection_request_packet(packet)
        else:
            raise Exception("NOT SUPPORTED PACKET TYPE")

    def handle_parent_advertise_packet(self, node: Node, packet: Packet):
        assert isinstance(node, Child)
        subtree_child_id = parse_advertise_data(packet.data)
        node.add_sub_node_if_not_exists(subtree_child_id)
        if self.parent.address.id != NO_PARENT_ID:
            packet = make_parent_advertise_packet(self.address.id, self.parent.address.id, subtree_child_id)
            send_packet_to_node(self.parent, packet)

    def handle_routing_request_packet(self, node: Node, packet: Packet):
        if packet.destination_id == self.address.id:
            self.handle_routing_request_to_self(packet)
            return

        forward_node = self.get_routing_request_destination_node(packet)
        if forward_node is None:
            self.send_destination_not_found_message(node, packet)
            return

        send_packet_to_node(forward_node, packet)

    def send_destination_not_found_message(self, node: Node, packet: Packet):
        p = make_destination_not_found_message_packet(self.address.id, packet.source_id, packet.destination_id)
        send_packet_to_node(node, p)

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
        send_packet_to_node(node, response_packet)

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

        send_packet_to_node(forward_node, packet)

    def handle_routing_response_to_self(self, packet: Packet):
        print(packet.data)

    def handle_destination_not_found_message(self, packet: Packet):
        forward_node = self.get_routing_request_destination_node(packet)
        send_packet_to_node(forward_node, packet)

    def handle_connection_request_packet(self, packet: Packet):
        child_host = MANAGER_HOST
        child_port = int(packet.data)
        socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        socket.bind((self.address.host, self.address.port))
        socket.connect((child_host, child_port))
        child = Child(NodeType.CHILD, socket)
        self.children.append(child)
        threading.Thread(target=self.listen_to_node, args=(child,))


if __name__ == '__main__':
    peer = Peer()
