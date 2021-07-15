from Address import Address
import socket as so


class Child:

    def __init__(self, socket: so.socket):
        self.socket = socket
        self.child_ids = []

    def add_sub_node(self, child_id):
        self.child_ids.append(child_id)
