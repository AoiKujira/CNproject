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
        self.parent_socket = None
        threading.Thread(target=self.terminal).run()

    def terminal(self):
        while True:
            command = input("$Enter command:")
            x = re.match(connect_command, command)
            if x is not None:
                try:
                    self.address, self.parent_address = self.connect_to_network(int(x[2]), int(x[1]))
                    self.connect_to_parent()
                except Exception as e:
                    print(e)
                    exit(0)
                threading.Thread(target=self.listen).start()
                continue
            x = re.match(connect_command, command)
            if x is not None:
                pass

    def send_connection_request_to_parent(self):
        if self.parent_address.id == NO_PARENT_ID:
            return
        socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        socket.connect((self.parent_address.host, self.parent_address.port))
        packet = make_connection_request_packet(self.address.id, self.parent_address.id, self.address.port)
        # send_packet_to_node(self.parent, packet)
        socket.close()

    def connect_to_network(self, port, identifier):
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
        if self.parent_address.port == -1:
            return
        self.parent_socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        self.parent_socket.connect((self.parent_address.host, self.parent_address.port))

    def advertise_to_parent(self):
        self.parent.socket.connect((self.parent.address.host, self.parent.address.port))
        threading.Thread(target=self.listen_to_node, args=(self.parent,)).start()

    def listen_to_node(self, node: Node):
        while True:
            s = node.socket.recv(BUFFER_SIZE).decode(ENCODING)
            packet = decode_packet(s)
            self.handle_message(node, packet)

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
