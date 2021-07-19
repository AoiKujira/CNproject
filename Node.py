from Address import Address


class Child:

    def __init__(self, address: Address):
        self.address = address
        self.sub_tree_child_ids = set()
        self.sub_tree_child_ids.add(address.id)

    def add_sub_node_if_not_exists(self, subtree_child_id: int):
        if subtree_child_id not in self.sub_tree_child_ids:
            self.sub_tree_child_ids.add(subtree_child_id)
