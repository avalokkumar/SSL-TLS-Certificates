import ssl
import socket

# Create a basic server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the server to localhost on port 8443
server_socket.bind(('localhost', 8443))
server_socket.listen(5)

# Wrap the socket with SSL/TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='server.crt', keyfile='server.key')

with context.wrap_socket(server_socket, server_side=True) as secure_socket:
    print("Server is listening on port 8443...")
    conn, addr = secure_socket.accept()
    print(f"Connection from {addr} established!")
    
    # Receive and send data securely
    data = conn.recv(1024)
    print(f"Received: {data.decode()}")
    conn.send(b"Hello, client! Secure connection established.")
    conn.close()