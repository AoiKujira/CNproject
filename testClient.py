import socket as so
import threading

host = 'localhost'
port = 13991

client = so.socket(so.AF_INET, so.SOCK_STREAM)
client.bind((host, 13999))
client.connect((host, port))


def receive():
    while True:
        try:
            message = client.recv(1024).decode('ascii')
            print(message)
            # print('enter command:')
        except Exception as e:
            client.close()
            print(e)
            print('recive failed!')
            return


def write():
    while True:
        message = input('Enter command:\n')
        client.send(message.encode('ascii'))


threading.Thread(target=receive).start()
threading.Thread(target=write).start()
