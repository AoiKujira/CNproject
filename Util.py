import random
import socket as so
import Configuration
import Packet
import socket as so
from Configuration import ENCODING
from Packet import Packet
from PacketType import PacketType
from Address import Address


def get_random_port() -> int:
    Configuration.PORT_BASE += 1
    return Configuration.PORT_BASE


def get_random_id() -> int:
    Configuration.ID_BASE += 1
    return Configuration.ID_BASE


def decode_packet(message: str):
    try:
        message = message.split(maxsplit=3)
        return Packet(int(message[0]), int(message[1]), int(message[2]), str(message[3]))
    except Exception as e:
        print(e)


def encode_packet(packet: Packet):
    message = str(packet.message_type) + '\n' \
              + str(packet.source_id) + '\n' \
              + str(packet.destination_id) + "\n" \
              + str(packet.data)
    return message


def send_packet_to_address(address: Address, packet: Packet):
    socket = so.socket(so.AF_INET, type=so.SOCK_DGRAM)  # use udp socket for request response style
    socket.connect((address.host, address.port))
    m = encode_packet(packet)
    socket.send(m.encode(ENCODING))
    socket.close()


def make_connection_request_packet(source_id: int, destination_id: int, port: int):
    return Packet(packet_type=PacketType.CONNECTION_REQUEST, source_id=source_id, destination_id=destination_id,
                  data=str(port))


def parse_advertise_data(data: str):
    return int(data)


def make_parent_advertise_packet(source_id: int, parent_id: int, subtree_child_id) -> Packet:
    return Packet(packet_type=PacketType.PARENT_ADVERTISE, source_id=source_id, destination_id=parent_id,
                  data=str(subtree_child_id))


def make_routing_response_packet(source_id: int, destination_id: int) -> Packet:
    return Packet(packet_type=PacketType.ROUTING_RESPONSE, source_id=source_id, destination_id=destination_id,
                  data=str(source_id))


def make_destination_not_found_message_packet(source_id: int, destination_id: int, searched_id: int) -> Packet:
    return Packet(packet_type=PacketType.DESTINATION_NOT_FOUND_MESSAGE, source_id=source_id,
                  destination_id=destination_id, data='DESTINATION {} NOT FOUND'.format(searched_id))
