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
        message = message.split(maxsplit=4)
        print('messs:' , message[0], message[1], message[2], message[3])
        p = Packet(packet_type=PacketType(int(message[0])), source_id=int(message[1]),
                   destination_id=int(message[2]),
                   data=str(message[4]),
                   last_node_id=int(message[3]))
        return p
    except Exception as e:
        print(e)


def encode_packet(packet: Packet):
    message = str(packet.type.value) + '\n' \
              + str(packet.source_id) + '\n' \
              + str(packet.destination_id) + "\n" \
              + str(packet.last_node_id) + "\n" \
              + str(packet.data) + "\n"
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
                  data=data,
                  last_node_id=source_id)


def parse_advertise_data(data: str):
    return int(data)
