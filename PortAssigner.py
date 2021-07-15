import random
from Configuration import PORT_BASE
from Configuration import PORTS_LIMIT


def get_random_port() -> int:
    return random.randint(PORT_BASE, PORTS_LIMIT)
