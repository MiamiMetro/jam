# udp_client.py
import socket

server = ("127.0.0.1", 9999)   # match your C++ server bind port

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)  # avoid blocking forever

# send
msg = b"hello from python"
sock.sendto(msg, server)
print(f"Sent: {msg}")

# receive
try:
    data, addr = sock.recvfrom(1024)
    print(f"Got reply from {addr}: {data}")
except socket.timeout:
    print("No reply (timeout)")
