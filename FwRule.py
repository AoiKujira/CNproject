from Packet import *
from PacketType import *
from FwDirection import *


class FwRule:
    def __init__(self, direction: FwDirection, src: int, dest: int, p_type: PacketType):
        self.dir = direction
        self.src = src
        self.dest = dest
        self.type = p_type

    def is_acceptable(self, node: int, packet: Packet):
        if packet.type == self.type:
            if self.dir == FwDirection.INPUT:
                if packet.destination_id == node:
                    return False
                return True
            elif self.dir == FwDirection.OUTPUT:
                if packet.source_id == node:
                    return False
                return True
            elif self.dir == FwDirection.FORWARD:
                if self.src == packet.source_id and self.dest == packet.destination_id:
                    return False
                if (self.dest == -1 and self.src == packet.source_id) or (self.src == -1 and self.dest == packet.destination_id):
                    return False
                return True
        return True

    def __eq__(self, other):
        return self.dir == other.dir and self.src == other.src and self.dest == other.dest and self.type == other.type

    def is_eq_stronger(self, src_wise: bool, rule):
        base_con = self.dir == rule.dir and self.type == rule.type
        if base_con:
            if src_wise:
                return self.src == -1 and self.dest == rule.dest
            else:
                return self.dest == -1 and self.src == rule.src
        return False

