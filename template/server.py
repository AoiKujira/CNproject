import socket
import threading

HOST = '100.113.62.61'
PORT = 13991

# class Account:
#     def __init__(self, client):
#         pass

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
clients = []
usernames = []
groups = []
groupnames = []
channels = []
channelnames = []

def send_message(client, name, message):
    error_message = ''
    if not client in clients:
        print('client not found! fear death.')
    client_index = clients.index(client)
    client_name = usernames[client_index]

    if name in usernames:
        index = usernames.index(name)
        clients[index].send((client_name + ' :' + message).encode('ascii'))
    elif name in groupnames:
        index = groupnames.index(name)
        if not client_name in groups[index]:
            return 'You are not a member of this group!'
        for username in groups[index]:
            username_index = usernames.index(username)
            clients[username_index].send((name + '_' + client_name + ' :' + message).encode('ascii'))
    elif name in channelnames:
        index = channelnames.index(name)
        if client_name != channels[index][0]:
            return 'You are not soltan of this group!'
        for username in channels[index]:
            username_index = usernames.index(username)
            clients[username_index].send((name + ' :' + message).encode('ascii'))
    else:
        error_message = 'ID not found!'
    
    return error_message

def join_command(client, id_type, name):
    error_message = ''
    if not client in clients:
        print('client not found! fear death.')
    client_index = clients.index(client)
    client_name = usernames[client_index]

    if id_type == 'group':
        if name in groupnames:
            index = groupnames.index(name)
            if client_name in groups[index]:
                return 'already in group!'
            else:
                groups[index].append(client_name)
    elif id_type == 'channel':
        if name in channelnames:
            index = channelnames.index(name)
            if client_name in channels[index]:
                return 'already in channel!'
            else:
                channels[index].append(client_name)
    else:
        return 'group/channel ID not found!'
    return error_message

def create_command(client, id_type, name):
    if name in username or name in groupnames or name in channelnames:
        return 'ID already taken'
    error_message = ''
    if not client in clients:
        print('client not found! fear death.')
    client_index = clients.index(client)
    client_name = usernames[client_index]

    if id_type == 'group':
        groups.append([])
        groupnames.append(name)
    elif id_type == 'channel':
        channels.append([])
        channelnames.append(name)
    else:
        return 'invalid command'
    join_command(client, id_type, name)
    return error_message

def handle(client):
    while True:
        try:
            inp = client.recv(1024).decode('ascii')
            message = inp.split()
            error_message = ''
            print(' '.join(message))
            if len(message) >= 3 and message[0] == 'create':
                error_message = create_command(client, message[1], message[2])
            elif len(message) >= 3 and message[0] == 'join':
                error_message = join_command(client, message[1], message[2])
            elif len(message) >= 5 and message[0]+' '+message[1]+' '+message[2] == 'send message to':
                error_message = send_message(client, message[3], inp[len(message[3])+15+2:])
            else:
                error_message = 'error, command not found.'
            
            if error_message != '':
                # print(error_message)
                client.send(error_message.encode('ascii'))
            else:
                client.send('succesful'.encode('ascii'))
        except:
            print('handle failed')
            client.close()
            index = clients.index(client)
            clients.remove(client)
            name = usernames.pop(index)
            for group in groups:
                if name in group:
                    group.remove(name)
            for channel in channels:
                if name in channel:
                    channel.remove(name)
            return

print('server up')
while True:
    print('waiting for client...')
    client, address = server.accept()
    print('connected with', address)
    client.send('username'.encode("ascii"))
    username = client.recv(1024).decode('ascii')
    while username in usernames:
        client.send('username is taken'.encode("ascii"))
        username = client.recv(1024).decode('ascii')
    client.send('welcome'.encode("ascii"))
    clients.append(client)
    usernames.append(username)
    thread = threading.Thread(target = handle, args=(client,))
    thread.start()
