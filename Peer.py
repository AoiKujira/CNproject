import re
import socket as so
import threading
from typing import Union, List

from Configuration import *
from Configuration import ENCODING
from Node import *
from PeerConnector import PeerConnector
from Util import *
from Util import encode_packet

from FwRule import *
from FwDirection import *
from FwAction import *

connect_command = 'CONNECT AS (\\d+|-\\d+) ON PORT (\\d+|-\\d+)'
show_known_command = 'SHOW KNOWN CLIENTS'
route_command = 'ROUTE (\\d+|-\\d+)'
advertise_command = 'Advertise (\\d+|-\\d+)'
start_chat_command = 'START CHAT ([\\w\\d._-]+): ((\\d+|-\\d+)(, *(\\d+|-\\d+))*)'
request_chat_command = 'REQUESTS FOR STARTING CHAT WITH ([\\w\\d._-]+): (\\d+|-\\d+)((, *(\\d+|-\\d+))+)'
join_message = '(\\d+|-\\d+): ([\\w\\d._-]+)'
exit_chat_command = 'EXIT CHAT'
someone_exit_chat_message = 'EXIT CHAT (\\d+|-\\d+)'
fw_command = 'FILTER (\\w+) (\\d+|[*]) (\\d+|[*]) (\\d+) (\\w+)'
fw_chat_command = 'FW CHAT (\\w+)'
chat_message = 'CHAT:.*'
salam_command = 'Salam Salam Sad Ta Salam (\\d+|-\\d+)'
recived_salam_message = '(\\d+|-\\d+): Salam Salam Sad Ta Salam'
recived_javab_salam_message = '(\\d+|-\\d+): Hezaro Sisad Ta Salam'


class Peer:

    def __init__(self):
        self.known_ids = []
        self.address = None
        self.parent_address = None
        self.children = []
        self.is_connected = False
        self.chat_name = None
        self.got_request = False
        self.chat_members = {}
        self.chat_invite_members = []
        self.terminal_command = None
        self.fw_rules = []
        self.block_chat = False
        threading.Thread(target=self.terminal).run()

    def terminal(self):
        while True:
            if self.chat_name is not None:
                self.terminal_command = input('$Enter message:')
                x = re.match(exit_chat_command, self.terminal_command)
                if x is not None:
                    print(f'sendin exit message to {self.chat_invite_members}')
                    for i in self.chat_invite_members:
                        packet = self.make_message_packet(i, f'CHAT:\nEXIT CHAT {self.address.id}')
                        self.send_message(packet)
                    self.chat_invite_members = []
                    self.chat_members = {}
                    self.chat_name = None
                    continue

                for i in self.chat_members.keys():
                    packet = self.make_message_packet(i, f'CHAT:\n{self.chat_name}: {self.terminal_command}')
                    self.send_message(packet)
            else:
                self.terminal_command = input("$Enter command:")
                if self.got_request:
                    for i in self.chat_invite_members:
                        if i not in self.known_ids:
                            self.known_ids.append(i)

                    if self.terminal_command == 'y' or self.terminal_command == 'Y':
                        self.chat_name = input('$Choose a name for yourself:')
                        data = f'CHAT:\n{self.address.id}: {self.chat_name}'
                        # print(f'im telling {self.chat_invite_members}')
                        for identifier in self.chat_invite_members:
                            if identifier != self.address.id:
                                packet = self.make_message_packet(identifier, data)
                                self.send_message(packet)
                    else:
                        self.chat_members = {}
                        self.chat_invite_members = []
                        self.chat_name = None

                    self.got_request = False
                    self.request_message = ''
                    continue

                x = re.match(connect_command, self.terminal_command)
                if x is not None:
                    if self.is_connected:
                        print('Denied\nAlready connected!')
                        continue
                    try:
                        identifier = int(x.group(1))
                        port = int(x.group(2))
                        self.connect_to_network(port, identifier)
                        self.connect_to_parent()
                        self.is_connected = True
                    except Exception as e:
                        print(e)
                        exit(0)
                    threading.Thread(target=self.listen).start()
                    continue

                x = re.match(show_known_command, self.terminal_command)
                if x is not None:
                    for known_id in self.known_ids:
                        print(known_id)
                    continue

                x = re.match(route_command, self.terminal_command)
                if x is not None:
                    # if self.check_destination(int(x[1])):
                    packet = Packet(packet_type=PacketType.ROUTING_REQUEST,
                                    source_id=self.address.id,
                                    destination_id=int(x[1]),
                                    data=None,
                                    last_node_id=self.address.id)
                    if self.check_fw_rules(packet):
                        self.handle_routing_request_packet(packet)
                    else:
                        print("Firewall dropped a packet from", packet.source_id, " to", packet.destination_id,
                              " type:", packet.type)
                    # else:
                    #     print('Unknown id')
                    continue

                x = re.match(advertise_command, self.terminal_command)
                if x is not None:
                    if self.check_destination(int(x[1])):
                        packet = Packet(packet_type=PacketType.ADVERTISE,
                                        source_id=self.address.id,
                                        destination_id=int(x[1]),
                                        data=str(self.address.id),
                                        last_node_id=self.address.id)
                        if self.check_fw_rules(packet):
                            self.handle_advertise_packet(packet)
                        else:
                            print("Firewall dropped a packet from", packet.source_id, " to", packet.destination_id,
                                  " type:", packet.type)
                    else:
                        print('Unknown id')
                    continue

                x = re.match(fw_command, self.terminal_command)
                if x is not None:
                    direction, src, dest, p_type, action = x[1], x[2], x[3], int(x[4]), x[5]
                    if src == '*':
                        src = -1
                    if dest == '*':
                        dest = -1
                    src, dest = int(src), int(dest)
                    if self.validate_fw_command(direction, p_type, action):
                        rule = FwRule(FwDirection(direction), src, dest, PacketType(p_type))
                        if self.is_logically_valid_fw_rule(rule):
                            if self.apply_fw_rule(rule, FwAction(action)):
                                print("The rule added")
                            else:
                                print("The rule already exists")
                        else:
                            print("Your rule's logic sucks idiot!")
                    continue

                x = re.match(fw_chat_command, self.terminal_command)
                if x is not None:
                    action = x[1]
                    if action == FwAction.DROP.value:
                        if not self.block_chat:
                            self.block_chat = True
                            print("The rule added")
                        else:
                            print("The rule already exists")
                    elif action == FwAction.ACCEPT.value:
                        if self.block_chat:
                            self.block_chat = False
                            print("The rule added")
                        else:
                            print("The rule already exists")
                    else:
                        print("Valid actions: ACCEPT / DROP")
                    continue

                x = re.match(start_chat_command, self.terminal_command)
                if x is not None:
                    if not self.block_chat:
                        self.chat_name = x[1]
                        self.chat_invite_members = self.get_start_chat_identifiers(x[2].split())
                        data = f'CHAT:\nREQUESTS FOR STARTING CHAT WITH {self.chat_name}: {self.address.id}'
                        for i in self.chat_invite_members:
                            data += f', {i}'

                        for identifier in self.chat_invite_members:
                            packet = make_message_packet(self.address.id, identifier, data)
                            self.send_message(packet)
                    else:
                        print("Chat is disabled. Make sure the firewall allows you to chat")
                    continue

                x = re.match(salam_command, self.terminal_command)
                if x is not None:
                    if self.check_destination(int(x[1])):
                        packet = make_salam_packet(self.address.id, int(x[1]))
                        self.send_message(packet)
                    continue

                print('command not found!')

    @staticmethod
    def validate_fw_command(direction: str, p_type: int, action: str):
        if direction in [direc.value for direc in FwDirection]:
            if p_type != PacketType.FIREWALL_DROP.value and p_type in [pt.value for pt in PacketType]:
                if action in [ac.value for ac in FwAction]:
                    return True
                else:
                    print("Valid actions: ACCEPT / DROP")
            else:
                print("Valid actions: 10 / 11 / 20 / 21 / 31 / 41")
        else:
            print("Valid directions: INPUT / OUTPUT / FORWARD")
        return False

    def apply_fw_rule(self, new_rule: FwRule, action: FwAction):
        if new_rule in self.fw_rules:
            if action == FwAction.ACCEPT:
                self.fw_rules.remove(new_rule)
                return True
        else:
            if action == FwAction.DROP:
                self.fw_rules.append(new_rule)
                return True
            else:
                if new_rule.src == -1:
                    for rule in self.fw_rules:
                        if new_rule.is_eq_stronger(src_wise=True, rule=rule):
                            self.fw_rules.remove(rule)
                            return True
                if new_rule.dest == -1:
                    for rule in self.fw_rules:
                        if new_rule.is_eq_stronger(src_wise=False, rule=rule):
                            self.fw_rules.remove(rule)
                            return True
        return False

    def is_logically_valid_fw_rule(self, rule: FwRule):
        if (rule.dir == FwDirection.INPUT or rule.dir == FwDirection.FORWARD) and rule.src == self.address.id:
            return False
        if (rule.dir == FwDirection.OUTPUT or rule.dir == FwDirection.FORWARD) and rule.dest == self.address.id:
            return False
        return True

    def check_fw_rules(self, packet: Packet):
        for item in self.fw_rules:
            if not item.is_acceptable(self.address.id, packet):
                return False
        return True

    def check_destination(self, destination):
        if destination != -1 and destination not in self.known_ids:
            print(f'Unknown destination {destination}')
            return False
        return True

    def get_start_chat_identifiers(self, ids):
        ret = []
        for i in ids:
            if i == ',':
                continue
            if i[-1] == ',':
                i = i[:-1]
            i = int(i)
            if i in self.known_ids and i not in ret and i != self.address.id:
                ret.append(i)
        return ret

    def get_request_chat_identifiers(self, ids):
        ret = []
        for i in ids:
            if i == ',':
                continue
            if i[-1] == ',':
                i = i[:-1]
            i = int(i)
            if i != self.address.id:
                ret.append(i)
        return ret

    def connect_to_parent(self):
        if self.parent_address.id == NO_PARENT_ID:
            return
        self.send_connection_request_to_parent()
        self.known_ids.append(self.parent_address.id)

    def send_connection_request_to_parent(self):
        packet = self.make_connection_request_packet(self.parent_address.id, self.address.port)
        self.send_packet_to_address(self.parent_address, packet)

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
            print(f'\nconnected to {address}')
            self.handle_socket(socket)

    def handle_socket(self, socket: so.socket):
        message = socket.recv(BUFFER_SIZE).decode(ENCODING)
        print(f'got packet: {{\n{message}\n}}')
        packet = decode_packet(message)
        if self.check_fw_rules(packet):
            self.handle_message(packet)
        else:
            print("Firewall dropped a packet from", packet.source_id, " to", packet.destination_id,
                  " type:", packet.type)
            packet = Packet(packet_type=PacketType.FIREWALL_DROP,
                            source_id=self.address.id,
                            destination_id=packet.source_id,
                            data='Firewall dropped your packet at node ' + str(self.address.id),
                            last_node_id=self.address.id)
            self.handle_message(packet)
        socket.close()

    def handle_message(self, packet: Packet):
        if packet.type == PacketType.MESSAGE:
            self.handle_message_packet(packet)
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
        elif packet.type == PacketType.FIREWALL_DROP:
            self.handle_firewall_packet(packet)
        else:
            raise Exception("NOT SUPPORTED PACKET TYPE")

    def handle_firewall_packet(self, packet: Packet):
        if self.address.id == packet.destination_id:
            print(packet.data)
            return

        addresses = self.get_routing_request_destination_for_packet(packet)
        assert addresses is not None
        self.send_packet_to_addresses(addresses, packet)

    def handle_message_packet(self, packet: Packet):
        if self.is_packet_for_us(packet):
            self.handle_message_packet_to_self(packet)

        if self.should_forward_packet(packet):
            addresses = self.get_routing_request_destination_for_packet(packet)
            assert addresses is not None
            self.send_packet_to_addresses(addresses, packet)

    def handle_message_packet_to_self(self, packet: Packet):
        if packet.source_id not in self.known_ids:
            self.known_ids.append(packet.source_id)

        if re.match(chat_message, packet.data):
            data = encode_message_packet(packet.data)
            x = re.match(request_chat_command, data)
            if x is not None:
                if self.chat_name is None:
                    self.request_message = data
                    self.got_request = True
                    x = re.match(request_chat_command, self.request_message)
                    self.chat_invite_members = self.get_request_chat_identifiers((x[2] + x[3]).split())
                    self.chat_members[int(x[2])] = x[1]
                    print(f'{x[1]} with id {x[2]} has asked you to join a chat. Would you like to join?[Y/N]')
                return

            x = re.match(join_message, data)
            if x is not None:
                print(f'{x[2]}({x[1]}) was joined to the chat.')
                if int(x[1]) not in self.chat_members.keys():
                    self.chat_members[int(x[1])] = x[2]
                return

            x = re.match(someone_exit_chat_message, data)
            if x is not None:
                print(f'{self.chat_members[int(x[1])]}({x[1]}) left the chat.')
                assert int(x[1]) in self.chat_members.keys()
                del self.chat_members[int(x[1])]
                return

            print(f'${data}')
            return

        x = re.match(recived_salam_message, packet.data)
        if x is not None:
            print(f'${packet.data}')
            if self.check_destination(int(x[1])):
                packet = make_javab_salam_packet(self.address.id, int(x[1]))
                self.send_message(packet)
            return

        x = re.match(recived_javab_salam_message, packet.data)
        if x is not None:
            print(f'${packet.data}')
            return

    def handle_advertise_packet(self, packet: Packet):
        if self.is_packet_for_us(packet):
            self.handle_advertise_to_self(packet)

        if self.should_forward_packet(packet):
            addresses = self.get_routing_request_destination_for_packet(packet)
            assert addresses is not None
            packet.source_id = self.address.id
            self.send_packet_to_addresses(addresses, packet)

    def handle_advertise_to_self(self, packet: Packet):
        if packet.source_id not in self.known_ids:
            self.known_ids.append(packet.source_id)
        print('received advertise to self packet')
        print(encode_packet(packet))
        print()

    def handle_parent_advertise_packet(self, packet: Packet):
        subtree_child_id = parse_advertise_data(packet.data)
        self.known_ids.append(subtree_child_id)
        child = self.find_child_with_id(packet.source_id)
        child.add_sub_node_if_not_exists(subtree_child_id)
        if self.parent_address.id != NO_PARENT_ID:
            self.send_packet_to_address(
                self.parent_address,
                self.make_parent_advertise_packet(
                    self.parent_address.id,
                    subtree_child_id
                )
            )

    def find_child_with_id(self, identifier: int) -> Child:
        return next(filter(lambda child: child.address.id == identifier, self.children))

    def find_neighbor_id_with_port(self, port: int):
        if self.parent_address.port == port:
            return self.parent_address.id
        return next(filter(lambda child: child.address.port == port, self.children))

    def handle_routing_request_packet(self, packet: Packet):
        if self.is_packet_for_us(packet):
            self.handle_routing_request_to_self(packet)

        if self.should_forward_packet(packet):
            addresses = self.get_routing_request_destination_for_packet(packet)
            if addresses is None:
                self.send_destination_not_found_message(packet)
                return
            self.send_packet_to_addresses(addresses, packet)

    def send_destination_not_found_message(self, packet: Packet):
        p = self.make_destination_not_found_message_packet(packet.source_id, packet.destination_id)
        addresses = self.get_routing_request_destination_for_packet(p)
        assert addresses is not None
        self.send_packet_to_addresses(addresses, p)

    def get_routing_request_destination_for_packet(self, packet: Packet) -> Union[List[Address], None]:
        print(" finding destination to ", packet.destination_id)
        assert packet.last_node_id is not None
        if packet.destination_id == ALL_IDS:
            addresses = [child.address for child in self.children if child.address.id != packet.last_node_id]
            if self.parent_address.id != NO_PARENT_ID and self.parent_address.id != packet.last_node_id:
                addresses.append(self.parent_address)
            print("to", [address.id for address in addresses])
            return addresses

        for child in self.children:
            if packet.destination_id in child.sub_tree_child_ids:
                print("to", child.address.id)
                return [child.address]

        if self.parent_address.id != NO_PARENT_ID:
            print("to", self.parent_address.id)
            return [self.parent_address]

        return None

    def handle_routing_request_to_self(self, packet: Packet):
        if packet.source_id not in self.known_ids:
            self.known_ids.append(packet.source_id)
        response_packet = self.make_routing_response_packet(packet.source_id)
        addresses = self.get_routing_request_destination_for_packet(response_packet)
        self.send_packet_to_addresses(addresses, response_packet)

    def handle_routing_response_packet(self, packet: Packet):
        if self.is_packet_for_us(packet):
            self.handle_routing_response_to_self(packet)

        if self.should_forward_packet(packet):
            self.append_current_node_to_routing_response_message(packet)
            addresses = self.get_routing_request_destination_for_packet(packet)
            self.send_packet_to_addresses(addresses, packet)

    def handle_routing_response_to_self(self, packet: Packet):
        if packet.source_id not in self.known_ids:
            self.known_ids.append(packet.source_id)
        self.append_current_node_to_routing_response_message(packet)
        print(packet.data)

    def append_current_node_to_routing_response_message(self, packet: Packet):
        m = re.search('(-\\d+|\\d+).*', packet.data)
        assert m is not None
        last_id = int(m.group(1))

        if last_id == self.parent_address.id:
            packet.data = f'{self.address.id}<-{packet.data}'
        else:
            packet.data = f'{self.address.id}->{packet.data}'

    def handle_destination_not_found_message(self, packet: Packet):
        if self.is_packet_for_us(packet):
            self.handle_destination_not_found_message_to_self(packet)

        if self.should_forward_packet(packet):
            addresses = self.get_routing_request_destination_for_packet(packet)
            self.send_packet_to_addresses(addresses, packet)

    def handle_destination_not_found_message_to_self(self, packet: Packet):
        print(packet.data)
        print()

    def handle_connection_request_packet(self, packet: Packet):
        child_host = MANAGER_HOST
        child_port = int(packet.data)
        child_id = packet.source_id
        self.known_ids.append(child_id)
        child_address = Address(child_host, child_port, child_id)
        child = Child(child_address)
        self.children.append(child)
        self.advertise_to_parent(child)

    def advertise_to_parent(self, child: Child):
        packet = self.make_parent_advertise_packet(self.parent_address.id, child.address.id)
        if self.parent_address.id != NO_PARENT_ID:
            self.send_packet_to_address(self.parent_address, packet)

    def send_packet_to_addresses(self, addresses: List[Address], packet: Packet):
        for address in addresses:
            self.send_packet_to_address(address, packet)

    def send_packet_to_address(self, address: Address, packet: Packet):
        socket = so.socket(so.AF_INET, type=so.SOCK_STREAM)
        packet.last_node_id = self.address.id
        print(f'sending packet: {{\n{encode_packet(packet)}\n}} to {address.id} on port {address.port}')
        socket.connect((address.host, address.port))
        m = encode_packet(packet)
        socket.send(m.encode(ENCODING))
        socket.close()

    def send_message(self, packet: Packet):
        addresses = self.get_routing_request_destination_for_packet(packet)
        if addresses is None:
            self.send_destination_not_found_message(packet)
            return
        self.send_packet_to_addresses(addresses, packet)

    def is_packet_for_us(self, packet: Packet):
        return packet.destination_id == self.address.id or \
               (packet.source_id != self.address.id and packet.destination_id == ALL_IDS)

    def should_forward_packet(self, packet: Packet):
        return packet.destination_id != self.address.id

    def make_message_packet(self, destination_id: int, data: str):
        return Packet(packet_type=PacketType.MESSAGE,
                      source_id=self.address.id,
                      destination_id=destination_id,
                      data=data,
                      last_node_id=self.address.id)

    def make_connection_request_packet(self, destination_id: int, port: int):
        return Packet(packet_type=PacketType.CONNECTION_REQUEST, source_id=self.address.id,
                      destination_id=destination_id, data=str(port), last_node_id=self.address.id)

    def make_parent_advertise_packet(self, parent_id: int, subtree_child_id) -> Packet:
        return Packet(packet_type=PacketType.PARENT_ADVERTISE, source_id=self.address.id, destination_id=parent_id,
                      data=str(subtree_child_id),
                      last_node_id=self.address.id)

    def make_routing_response_packet(self, destination_id: int) -> Packet:
        return Packet(packet_type=PacketType.ROUTING_RESPONSE, source_id=self.address.id, destination_id=destination_id,
                      data=str(self.address.id),
                      last_node_id=self.address.id)

    def make_destination_not_found_message_packet(self, destination_id: int, searched_id: int) -> Packet:
        return Packet(packet_type=PacketType.DESTINATION_NOT_FOUND_MESSAGE, source_id=self.address.id,
                      destination_id=destination_id, data='DESTINATION {} NOT FOUND'.format(searched_id),
                      last_node_id=self.address.id)


if __name__ == '__main__':
    peer = Peer()
