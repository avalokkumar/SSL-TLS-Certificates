import ssl
import socket

# Create a basic client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Wrap the socket with SSL/TLS
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations('/Users/alok.vishwakarma1/personal/workspace/SSL-TLS-Certificates/Intro_to_SSL&TLS/SSL_TLS_Encryption/server.crt')  # Load server certificate

with context.wrap_socket(client_socket, server_hostname='localhost') as secure_socket:
    secure_socket.connect(('localhost', 8443))
    
    # Send and receive data securely
    secure_socket.send(b"Hello, server!")
    data = secure_socket.recv(1024)
    print(f"Received from server: {data.decode()}")
