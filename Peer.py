import re
import re
import threading
from typing import Union

from Configuration import *
from Node import *
from PeerConnector import PeerConnector
from Util import *

connect_command = 'CONNECT AS (\\d+|-\\d+) ON PORT (\\d+|-\\d+)'
show_known_command = 'SHOW KNOWN CLIENTS'
route_command = 'ROUTE (\\d+|-\\d+)'
advertise_command = 'Advertise (\\d+|-\\d+)'
start_chat_command = 'START CHAT ([\\w\\d._-]+): [.]*'


class Peer:

    def __init__(self):
        self.known_addresses = []
        self.address = None
        self.parent_address = None
        self.parent_socket = None
        self.children = []
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
                    self.connect_to_parent()
                except Exception as e:
                    print(e)
                    exit(0)
                threading.Thread(target=self.listen).start()
                continue

            x = re.match(show_known_command, command)
            if x is not None:
                for known_address in self.known_addresses:
                    print(known_address.id)
                continue

            x = re.match(route_command, command)
            if x is not None:
                pass

            x = re.match(advertise_command, command)
            if x is not None:
                pass

            x = re.match(start_chat_command, command)
            if x is not None:
                self.chat_name = x[1]
                identifiers = self.format_start_chat_identidires(command.split()[3:])
                # REQUESTS FOR STARTING CHAT WITH CHAT_NAMEA: IDA, ID1, ID2, ID3...

                pass

            x = re.match(advertise_command, command)
            if x is not None:
                pass

    def format_start_chat_identidires(self, ids):
        ret = []
        for i in ids:
            if i[-1] == ',':
                i = i[:-2]
            i = int(i)
            if i in self.get_known_ids() and i not in ret and i != self.address.id:
                ret.append(i)
        return ret

    def get_known_ids(self):
        ret = []
        for i in self.known_addresses:
            ret.append(i.id)
        return ret

    def connect_to_parent(self):
        if self.parent_address.id == NO_PARENT_ID:
            return
        self.send_connection_request_to_parent()

    def send_connection_request_to_parent(self):
        packet = make_connection_request_packet(self.address.id, self.parent_address.id, self.address.port)
        send_packet_to_addresses(self.parent_address, packet)

    def connect_to_network(self, port: int, identifier: int):
        address = Address(MANAGER_HOST, port, identifier)
        peer_connector = PeerConnector()
        self.parent_address = peer_connector.get_id(address)
        self.address = address

    def listen(self):
        server = so.socket(so.AF_INET, type=so.SOCK_STREAM)
        server.bind((self.address.host, self.address.port))
        server.listen()
        while True:
            socket, address = server.accept()
            print(f'connected to {address}')
            self.handle_socket(socket)

    def handle_socket(self, socket: so.socket):
        message = socket.recv(BUFFER_SIZE).decode(ENCODING)
        print(f'message: {message}')
        packet = decode_packet(message)
        self.handle_message(packet)
        socket.close()

    def handle_message(self, packet: Packet):
        if packet.type == PacketType.MESSAGE:
            pass
        elif packet.type == PacketType.ROUTING_REQUEST:
            self.handle_routing_request_packet(packet)
        elif packet.type == PacketType.ROUTING_RESPONSE:
            self.handle_routing_response_packet(packet)
        elif packet.type == PacketType.PARENT_ADVERTISE:
            self.handle_parent_advertise_packet(packet)
        elif packet.type == PacketType.ADVERTISE:
            self.handle_advertise_packet(packet)
        elif packet.type == PacketType.DESTINATION_NOT_FOUND_MESSAGE:
            self.handle_destination_not_found_message(packet)
        elif packet.type == PacketType.CONNECTION_REQUEST:
            self.handle_connection_request_packet(packet)
        else:
            raise Exception("NOT SUPPORTED PACKET TYPE")

    def handle_advertise_packet(self, packet: Packet):
        if packet.destination_id == self.address.id:
            self.handle_advertise_to_self(packet)
            return
        addresses = self.get_routing_request_destination_for_packet(packet)
        send_packet_to_addresses(addresses, packet)

    def handle_advertise_to_self(self, packet: Packet):
        print('received advertise to self packet')
        print(encode_packet(packet))
        print()

    def handle_parent_advertise_packet(self, packet: Packet):
        subtree_child_id = parse_advertise_data(packet.data)
        child = self.find_child_with_id(packet.source_id)
        child.add_sub_node_if_not_exists(subtree_child_id)
        if self.parent_address.id != NO_PARENT_ID:
            send_packet_to_addresses(
                self.parent_address,
                make_parent_advertise_packet(
                    self.address.id,
                    self.parent_address.id,
                    subtree_child_id
                )
            )

    def find_child_with_id(self, identifier: int) -> Child:
        candidates = list(filter(lambda child: child.address.id == identifier, self.children))
        return candidates[0]

    def handle_routing_request_packet(self, packet: Packet):
        if packet.destination_id == self.address.id:
            self.handle_routing_request_to_self(packet)
            return

        addresses = self.get_routing_request_destination_for_packet(packet)
        if addresses is None:
            self.send_destination_not_found_message(packet)
            return
        send_packet_to_addresses(addresses, packet)

    def send_destination_not_found_message(self, packet: Packet):
        p = make_destination_not_found_message_packet(self.address.id, packet.source_id, packet.destination_id)
        addresses = self.get_routing_request_destination_for_packet(p)
        assert addresses is not None
        send_packet_to_addresses(addresses, packet)

    def get_routing_request_destination_for_packet(self, packet: Packet) -> Union[List[Address], None]:
        neighbor_node_id = packet.source_id
        if packet.destination_id == -1:
            addresses = [child.address for child in self.children if child.address.id != neighbor_node_id]
            if self.parent_address.id != neighbor_node_id:
                addresses.append(self.parent_address)
            return addresses

        for child in self.children:
            if packet.destination_id in child.sub_tree_child_ids:
                return list(child.address)

        if self.parent_address.id != NO_PARENT_ID:
            return list(self.parent_address)

        return None

    def handle_routing_request_to_self(self, packet: Packet):
        response_packet = make_routing_response_packet(self.address.id, packet.source_id)
        addresses = self.get_routing_request_destination_for_packet(packet)
        send_packet_to_addresses(addresses, response_packet)

    def handle_routing_response_packet(self, packet: Packet):
        if packet.destination_id == self.address.id:
            self.handle_routing_response_to_self(packet)
            return

        m = re.search('(-\\d+|\\d+).*', packet.data)
        assert m is not None
        last_id = m.group(1)

        if last_id == self.parent_address.id:
            packet.data = f'{self.address.id}<-{packet.data}'
        else:
            packet.data = f'{self.address.id}->{packet.data}'

        addresses = self.get_routing_request_destination_for_packet(packet)
        send_packet_to_addresses(addresses, packet)

    def handle_routing_response_to_self(self, packet: Packet):
        print(packet.data)

    def handle_destination_not_found_message(self, packet: Packet):
        addresses = self.get_routing_request_destination_for_packet(packet)
        send_packet_to_addresses(addresses, packet)

    def handle_connection_request_packet(self, packet: Packet):
        child_host = MANAGER_HOST
        child_port = int(packet.data)
        child_id = packet.source_id
        child_address = Address(child_host, child_port, child_id)
        child = Child(child_address)
        self.children.append(child)
        self.advertise_to_parent(child)

    def advertise_to_parent(self, child: Child):
        packet = make_parent_advertise_packet(self.address.id, self.parent_address.id, child.address.id)
        if self.parent_address.id != NO_PARENT_ID:
            send_packet_to_addresses(self.parent_address, packet)


if __name__ == '__main__':
    peer = Peer()
