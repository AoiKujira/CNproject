import socket as so
from Address import Address


class Node:

    def __init__(self, socket: so.socket):
        self.socket = socket


class Child(Node):

    def __init__(self, socket: so.socket):
        super(Child, self).__init__(socket)
        self.sub_tree_child_ids = set()

    def add_sub_node_if_not_exists(self, subtree_child_id: int):
        if subtree_child_id not in self.sub_tree_child_ids:
            self.sub_tree_child_ids.add(subtree_child_id)


class Parent(Node):

    def __init__(self, socket: so.socket, address: Address):
        super(Parent, self).__init__(socket)
        self.address = address
