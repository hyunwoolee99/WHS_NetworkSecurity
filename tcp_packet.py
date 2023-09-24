import socket

target_ip = "52.79.145.40"
target_port = 80
message = "GET / HTTP/1.1\r\nHost: whitehatschool.kr\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))

s.sendall(message.encode('utf-8'))
data = s.recv(4096)
s.close()
