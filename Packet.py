from PacketType import PacketType


class Packet:

    def __init__(self, *, packet_type: PacketType, source_id: int, destination_id: int, data: str, last_node_id):
        self.type = packet_type
        self.source_id = source_id
        self.destination_id = destination_id
        self.data = data
        self.last_node_id = last_node_id
