### **How to Run the Example**

1. **Generate SSL Certificates**: First, you need to generate a self-signed SSL certificate for testing purposes. You can do this using the `openssl` command:

   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
   ```

   This command will generate a `server.crt` (certificate) and `server.key` (private key) file.

2. **Run the Server**: Start the server by running the `server.py` script.

   ```bash
   python server.py
   ```

3. **Run the Client**: In a separate terminal, run the `client.py` script.

   ```bash
   python client.py
   ```

### **Explanation**

- **Server Code**:
  - The server creates a basic TCP socket and then wraps it with SSL/TLS using the `ssl.SSLContext` object.
  - The server loads its certificate and private key using `context.load_cert_chain`.
  - The server listens for incoming connections on port 8443 and securely communicates with the client.

- **Client Code**:
  - The client creates a basic TCP socket and then wraps it with SSL/TLS using `ssl.create_default_context`.
  - The client loads the server's certificate using `context.load_verify_locations` to verify the server's identity.
  - The client connects to the server and exchanges data securely.

### **Output**

- When the client connects to the server and sends a message, you should see output like this:
  - **Server**:
    ```
    Server is listening on port 8443...
    Connection from ('127.0.0.1', 12345) established!
    Received: Hello, server!
    ```
  - **Client**:
    ```
    Received from server: Hello, client! Secure connection established.
    ```