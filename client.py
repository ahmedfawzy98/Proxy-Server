import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 1234))
# while True:
msg, address = s.recvfrom(1024)
print(msg)
# s.connect(('127.0.0.1', 1234))
s.send(bytes('Thank you for your connection server','utf-8'))
# s.sendall(bytes('Welcome from the client','utf-8'))
# print('Message sent')
