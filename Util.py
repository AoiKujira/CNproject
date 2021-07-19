from re import S
import Configuration
import Packet
from Packet import Packet
from PacketType import PacketType


def get_random_port() -> int:
    Configuration.PORT_BASE += 1
    return Configuration.PORT_BASE


def get_random_id() -> int:
    Configuration.ID_BASE += 1
    return Configuration.ID_BASE


def decode_packet(message: str):
    try:
        message = message.split(maxsplit=3)
        return Packet(packet_type=PacketType(int(message[0])), source_id=int(message[1]),
                      destination_id=int(message[2]),
                      data=str(message[3]))
    except Exception as e:
        print(e)


def encode_packet(packet: Packet):
    message = str(packet.type.value) + '\n' \
              + str(packet.source_id) + '\n' \
              + str(packet.destination_id) + "\n" \
              + str(packet.data)
    return message

def encode_message_packet(data: str):
    data = data.split('\n', maxsplit=1)
    return data[1]

def make_salam_packet(source_id: int, destination_id: int):
    return make_message_packet(source_id, destination_id, f'{source_id}: Salam Salam Sad Ta Salam')

def make_javab_salam_packet(source_id: int, destination_id: int):
    return make_message_packet(source_id, destination_id, f'{source_id}: Hezaro Sisad Ta Salam')

def make_message_packet(source_id: int, destination_id: int, data:str):
    return Packet(packet_type=PacketType.MESSAGE,
                  source_id=source_id,
                  destination_id=destination_id,
                  data=data)

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
