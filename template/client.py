import socket
import threading

host = '100.113.62.61'
port = 13991

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))


username = input('Enter username:\n')

def recive():
    flag = False
    while True:
        try:
            message = client.recv(1024).decode('ascii')
            if not flag and message == 'username':
                client.send(username.encode('ascii'))
                message = client.recv(1024).decode('ascii')
                if message == 'welcome':
                    print(message)
                    flag = True
            else:
                print(message)
                # print('enter command:')
        except:
            client.close()
            print('recive failed!')
            return

def write():
    while True:
        message = input('Enter command:\n')
        client.send(message.encode('ascii'))

recive_thread = threading.Thread(target=recive)
recive_thread.start()
write_thread = threading.Thread(target=write)
write_thread.start()