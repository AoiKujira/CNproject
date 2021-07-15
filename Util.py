import random
from Configuration import *


def get_random_port() -> int:
    return random.randint(PORT_BASE, PORTS_LIMIT)


def get_random_id() -> int:
    return random.randint(ID_BASE, ID_LIMIT)
