import random
import Configuration


def get_random_port() -> int:
    Configuration.PORT_BASE += 1
    return Configuration.PORT_BASE


def get_random_id() -> int:
    Configuration.ID_BASE += 1
    return Configuration.ID_BASE
