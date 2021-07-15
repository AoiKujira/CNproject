import random
import Configuration
import Packet


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