from enum import Enum
import socket as so
from Address import Address


class NodeType(Enum):
    PARENT = 0,
    CHILD = 1,


class Node:

    def __init__(self, node_type: NodeType, socket: so.socket):
        self.type = node_type
        self.socket = socket


class Child(Node):

    def __init__(self, node_type: NodeType, socket: so.socket):
        super(Child, self).__init__(node_type, socket)
        self.sub_tree_child_ids = set()

    def add_sub_node_if_not_exists(self, subtree_child_id: int):
        if subtree_child_id not in self.sub_tree_child_ids:
            self.sub_tree_child_ids.add(subtree_child_id)


class Parent(Node):

    def __init__(self, node_type: NodeType, socket: so.socket, address: Address):
        super(Parent, self).__init__(node_type, socket)
        self.address = address


