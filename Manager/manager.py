import socket
import threading

HOST = '127.0.0.1'
MANAGER_PORT = 13391

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, MANAGER_PORT))
server.listen()
tree = []
nodes = {} #(id, port)

def find_par():
    l = len(tree)
    if not l:
        return -1, -1
    return tree[(l-1)//2]

print('server up')
while True:
    print('waiting for client...')
    client, address = server.accept()
    print('connected with', address)
    respond = client.recv(1024).decode('ascii')
    # respond:"$IDnew REQUESTS FOR CONNECTING TO NETWORK ON PORT $Port"
    respond = respond.split()

    while (respond[0], respond[-1]) in nodes or \
            respond[0] in nodes.keys() or \
            respond[-1] in nodes.values() :
        client.send('ID and/or port is taken, try again'.encode("ascii"))
        respond = client.recv(1024).decode('ascii').split()
    par = find_par()
    client.send(f'CONNECT TO {par[0]} WITH PORT {par[1]}'.encode("ascii"))
    tree.append((respond[0], respond[-1]))
    nodes[respond[0]] = respond[-1]
