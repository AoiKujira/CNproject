import socket
from Configuration import *

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((MANAGER_HOST, MANAGER_PORT))
server.listen()
tree = []
nodes = {}  # (id, port)


def find_parent():
    l = len(tree)
    if not l:
        return -1, -1
    return tree[(l - 1) // 2]


print('server up')
while True:
    print('waiting for client...')
    client, address = server.accept()
    print('connected with', address)
    respond = client.recv(BUFFER_SIZE).decode('ascii')
    # respond:"$IDnew REQUESTS FOR CONNECTING TO NETWORK ON PORT $Port"
    respond = respond.split()
    print('respond:', respond)

    print(respond[0])
    print(respond[1])

    while respond[0] in nodes.keys() or respond[1] in nodes.values():
        client.send('ID and/or port is taken, try again'.encode("ascii"))
        respond = client.recv(1024).decode('ascii').split()
    par = find_parent()
    client.send(f'CONNECT TO {par[0]} WITH PORT {par[1]}'.encode("ascii"))
    tree.append((respond[0], respond[1]))
    nodes[respond[0]] = respond[1]
