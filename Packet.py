from PacketType import PacketType


class Packet:

    def __init__(self, *, packet_type: PacketType, source_id: int, destination_id: int, data: str):
        self.type = packet_type
        self.source_id = source_id
        self.destination_id = destination_id
        self.data = data
