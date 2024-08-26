## Cryptography Fundamentals

### **1. Basic Cryptography Concepts**

#### **1.1 What is Cryptography?**

Cryptography is the science of securing information by transforming it into a format that can only be read by someone who has the correct key. The goal is to protect data from unauthorized access or tampering.

### **1.2 Encryption and Decryption**

#### **Encryption:**
- **What It Is:** Encryption is the process of converting plain text (readable data) into cipher text (unreadable data) using a key. The purpose of encryption is to ensure that even if someone intercepts the data, they cannot understand it without the key.
- **Example:**
  - **Plain Text:** "Hello, World!"
  - **Encryption Process:** Suppose we use a simple encryption technique called Caesar Cipher, where each letter is shifted by 3 places in the alphabet.
  - **Cipher Text:** "Khoor, Zruog!"
  
> Here, "Hello, World!" has been transformed into "Khoor, Zruog!" using a key (in this case, shifting letters by 3).

#### **Decryption:**
- **What It Is:** Decryption is the reverse process of encryption. It involves converting the cipher text back into plain text using the same key (or a corresponding key). Decryption allows the intended recipient to understand the encrypted message.
- **Example:**
  - **Cipher Text:** "Khoor, Zruog!"
  - **Decryption Process:** Using the same key (shifting letters back by 3).
  - **Plain Text:** "Hello, World!"

  Here, "Khoor, Zruog!" has been decrypted back to the original message "Hello, World!".

### **1.3 Keys in Cryptography**

#### **What is a Key?**
- **What It Is:** A key is a piece of information (a string of characters) that is used in the encryption and decryption processes. The key is what makes the encrypted data secure, as it controls how the plain text is transformed into cipher text and vice versa.
  
#### **Types of Keys:**

1.3.1 **Symmetric Key:**
   - **What It Is:** In symmetric key cryptography, the same key is used for both encryption and decryption.
   - **Example:**
     - If you and your friend both know the secret key "12345", you can encrypt and decrypt messages using that key. Anyone without the key "12345" cannot read your messages.

   - **Pros:** Symmetric key encryption is fast and efficient.
   - **Cons:** The key must be shared securely between the sender and receiver. If someone intercepts the key, they can decrypt the messages.

1.3.2 **Asymmetric Key:**
   - **What It Is:** In asymmetric key cryptography, there are two keys: a public key and a private key. The public key is used for encryption, and the private key is used for decryption.
   - **Example:**
     - Suppose you want to send a secret message to your friend. You encrypt the message using your friend's public key, which everyone can see. However, only your friend has the private key needed to decrypt the message.
     - **Public Key (for encryption):** "FriendPublicKey"
     - **Private Key (for decryption):** "FriendPrivateKey"
     
     Your message "Hello!" is encrypted with the public key into a cipher text, which can only be decrypted by your friend using the private key.

   - **Pros:** Asymmetric key cryptography is more secure for key distribution because the private key never needs to be shared.
   
   - **Cons:** It is slower and computationally more intensive than symmetric key encryption.
   
### **1.4 Real-World Example**

Imagine you want to send a secret message to a friend:
- **Without Encryption:** If you just write the message on a postcard, anyone who sees it can read it.
- **With Symmetric Encryption:** You put the message in a locked box and give your friend the only key that can open it. Both of you use the same key.
- **With Asymmetric Encryption:** You put the message in a box that locks automatically when closed (public key). Only your friend has the special key that can open it (private key).

### **5. Why is Cryptography Important?**

Cryptography is essential in many areas, including secure online communication (like sending emails or making purchases), protecting personal data, and ensuring that information remains confidential and unaltered. Without cryptography, sensitive information could be easily intercepted and read by unauthorized parties. By using encryption, organizations can protect their data and maintain the trust of their customers and users.


---

### **2. Symmetric vs. Asymmetric Encryption**

#### **2.1 Symmetric Encryption**

**Definition:**
Symmetric encryption uses a single key to both encrypt and decrypt data. This key must be shared between the sender and the receiver to ensure secure communication.

**Formula:**
- **Encryption:** \( C = E(K, P) \)
  - \( C \): Cipher text (encrypted data)
  - \( E \): Encryption algorithm
  - \( K \): Key
  - \( P \): Plain text (original data)
  
- **Decryption:** \( P = D(K, C) \)
  - \( D \): Decryption algorithm

**Process:**
1. The sender uses the key \( K \) to encrypt the plain text \( P \) into cipher text \( C \).
2. The receiver uses the same key \( K \) to decrypt the cipher text \( C \) back into plain text \( P \).

**Example:**
- **Encryption Algorithm:** Advanced Encryption Standard (AES)
- **Key:** "mysecretkey"

```python
from Crypto.Cipher import AES
import base64

# Symmetric Encryption Example with AES
def pad(text):
    # Padding the text to ensure it's a multiple of 16 bytes
    return text + (16 - len(text) % 16) * ' '

# Symmetric Key
key = 'mysecretkey12345'

# Plain text to be encrypted
plain_text = "Hello, Symmetric Encryption!"

# Encryption
cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
cipher_text = base64.b64encode(cipher.encrypt(pad(plain_text).encode('utf-8'))).decode('utf-8')

print(f"Encrypted: {cipher_text}")

# Decryption
decrypted_text = cipher.decrypt(base64.b64decode(cipher_text)).decode('utf-8').strip()
print(f"Decrypted: {decrypted_text}")
```

**Pros:**
- Fast and efficient.
- Suitable for encrypting large amounts of data.
- Simple to implement.
- Used for secure communication and data storage.

**Cons:**
- Requires secure key distribution. If the key is intercepted, the encryption is compromised.
- Not suitable for key exchange or digital signatures.
- Key management can be challenging.
- Vulnerable to key compromise.

#### **2.2 Asymmetric Encryption**

**Definition:**
Asymmetric encryption uses a pair of keys: a public key for encryption and a private key for decryption. The public key can be shared openly, but the private key must be kept secure.

**Formula:**
- **Encryption:** \( C = E(K_{pub}, P) \)
  - \( K_{pub} \): Public key

- **Decryption:** \( P = D(K_{priv}, C) \)
  - \( K_{priv} \): Private key

**Process:**
1. The sender uses the receiver's public key \( K_{pub} \) to encrypt the plain text \( P \) into cipher text \( C \).
2. The receiver uses their private key \( K_{priv} \) to decrypt the cipher text \( C \) back into plain text \( P \).

> Note: Private keys should never be shared or exposed.

**Example:**
- **Encryption Algorithm:** RSA

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA keys
key = RSA.generate(2048)
public_key = key.publickey()

# Plain text to be encrypted
plain_text = "Hello, Asymmetric Encryption!"

# Encrypt using public key
cipher = PKCS1_OAEP.new(public_key)
cipher_text = base64.b64encode(cipher.encrypt(plain_text.encode('utf-8'))).decode('utf-8')

print(f"Encrypted: {cipher_text}")

# Decrypt using private key
cipher = PKCS1_OAEP.new(key)
decrypted_text = cipher.decrypt(base64.b64decode(cipher_text)).decode('utf-8')
print(f"Decrypted: {decrypted_text}")
```

**Pros:**
- No need to share the private key, making key distribution more secure.
- Public key can be freely distributed without compromising security.
- Enables secure key exchange and digital signatures.

**Cons:**
- Slower and more resource-intensive than symmetric encryption.
- Less efficient for large amounts of data.

### **3. Comparison: Symmetric vs. Asymmetric Encryption**

| **Aspect**                     | **Symmetric Encryption**                                         | **Asymmetric Encryption**                                         |
|--------------------------------|------------------------------------------------------------------|-------------------------------------------------------------------|
| **Key Usage**                  | Same key for encryption and decryption.                          | Different keys: public key for encryption, private key for decryption. |
| **Speed**                      | Faster and more efficient.                                       | Slower and more resource-intensive.                               |
| **Security**                   | Requires secure key sharing.                                     | More secure key distribution as private key is never shared.      |
| **Use Cases**                  | Encrypting large amounts of data, like files or disks.           | Secure key exchange, digital signatures, and encrypting small amounts of data. |
| **Complexity**                 | Simpler to implement.                                            | More complex due to key pair generation and management.           |

### **4. Real-World Use Cases**

- **Symmetric Encryption:**
  - **File Encryption:** Encrypting files on a disk using AES.
  - **VPNs:** Protecting data transmitted over a Virtual Private Network (VPN).

- **Asymmetric Encryption:**
  - **SSL/TLS:** Protecting data in transit over the internet, such as HTTPS websites.
  - **Digital Signatures:** Verifying the authenticity of a message or document.

### **5. Hybrid Encryption**

In practice, many systems use a combination of both symmetric and asymmetric encryption. This approach leverages the strengths of both:
- **Asymmetric encryption** is used to securely exchange a symmetric key.
- **Symmetric encryption** is then used for the actual data transfer, providing speed and efficiency.

**Example:** 
In SSL/TLS:
- The server and client use asymmetric encryption to exchange a symmetric session key.
- The session key is then used for faster symmetric encryption of the actual data.
- This hybrid approach combines the security of asymmetric encryption with the efficiency of symmetric encryption.
- It is widely used in secure communication protocols like SSL/TLS.


---

### **3. Public Key Infrastructure (PKI)**

#### Details available at below Link:

**[Public Key Infrastructure (PKI)](https://github.com/avalokkumar/developer-notes/blob/main/PKI.md)**

---

### **4. Hashing and its Role in SSL/TLS**

#### **4.1 What is Hashing?**

**Hashing** is a process that takes an input (or "message") and returns a fixed-size string of bytes. The output is typically a "digest" that uniquely represents the input data. Hashing functions are used extensively in computer science and cryptography for various purposes like data integrity, digital signatures, and password storage.

**Key Characteristics of Hashing:**
- **Deterministic:** The same input will always produce the same hash output.
- **Fixed Output Size:** Regardless of the size of the input, the output (hash) is always the same length.
- **Pre-Image Resistance:** Given a hash value, it should be computationally difficult to reverse the process to find the original input.
- **Collision Resistance:** It should be difficult to find two different inputs that produce the same hash output.
- **Fast Computation:** Hash functions should be fast to compute, even for large amounts of data.
- **Non-Reversible:** Hash functions are one-way functions, meaning you cannot reverse the process to obtain the original input.

**Common Hash Functions:**
- **SHA-256 (Secure Hash Algorithm 256-bit)**
- - This is a widely used hash function that produces a 256-bit (32-byte) hash value.
- **SHA-512 (Secure Hash Algorithm 512-bit)**
- - A variant of SHA-2 that produces a 512-bit (64-byte) hash value.
- **MD5 (Message Digest Algorithm 5)**
- - An older hash function that produces a 128-bit (16-byte) hash value.
- **SHA-1 (Secure Hash Algorithm 1)**
- - Another widely used hash function, but now considered weak due to vulnerabilities.
- **SHA-3 (Secure Hash Algorithm 3)**
- - A newer hash function that is part of the SHA-3 family of cryptographic hash functions.
- **Whirlpool**
- - A cryptographic hash function that produces a 512-bit hash value.
- **RIPEMD-160**
- - A hash function that produces a 160-bit hash value.


#### Different Hash Functions:

| **Hash Function** | **Algorithm**              | **Formula/Description**                                                                                     | **Pros**                                                             | **Cons**                                                     |
|-------------------|----------------------------|-------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|--------------------------------------------------------------|
| **MD5**           | Message Digest Algorithm 5 | Produces a 128-bit hash value. Example: `MD5("Hello") -> 8b1a9953c4611296a827abf8c47804d7`                    | Fast computation, widely used                                         | Vulnerable to collision attacks, considered insecure         |
| **SHA-1**         | Secure Hash Algorithm 1    | Produces a 160-bit hash value. Example: `SHA-1("Hello") -> f7c3bc1d808e04732adf679965ccc34ca7ae3441`          | Better security than MD5, widely used in legacy systems               | Vulnerable to collision attacks, deprecated for secure use    |
| **SHA-256**       | Secure Hash Algorithm 256  | Produces a 256-bit hash value. Example: `SHA-256("Hello") -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` | High security, widely adopted in SSL/TLS, Bitcoin, etc.              | Slower than MD5 and SHA-1                                     |
| **SHA-3**         | Secure Hash Algorithm 3    | Produces a variable-length output (224, 256, 384, 512 bits). Example: `SHA-3-256("Hello") -> 3338bbe7c68dc1ed2389b5ffb53c5b03bd1ef10c226022db2dbd1a48402c996e` | Post-SHA-2 security improvements, resistance to certain attacks      | Slower than SHA-2                                            |
| **RIPEMD-160**    | RACE Integrity Primitives   | Produces a 160-bit hash value. Example: `RIPEMD-160("Hello") -> 108f07b8382412612c048d07d13f814118445acd`      | Balanced speed and security, less common, unique design               | Less adopted, considered less secure than SHA-256            |
| **BLAKE2**        | BLAKE2 Cryptographic Hash   | Produces a variable-length output (up to 512 bits). Example: `BLAKE2b-256("Hello") -> 256-bit hash value`     | Faster than MD5, SHA-1, and SHA-256, high security, customizable     | Newer algorithm, less widespread adoption                    |
| **HMAC**          | Hash-based Message Auth.   | Combines a secret key with a hash function for added security. Example: `HMAC-SHA256(key, message)`           | Provides data integrity and authentication, resistant to length-extension attacks | Requires key management                                      |


#### **4.2 Role of Hashing in SSL/TLS**

In SSL/TLS, hashing plays several critical roles in ensuring secure communication between a client and a server. These roles include:

1. **Data Integrity:**
   - **Purpose:** Ensures that the data transmitted between the client and server is not altered during transit.
   - **How It Works:** During the SSL/TLS handshake, both the client and server agree on a hash function (part of the cipher suite). Every message that is sent is accompanied by a hash value (called a Message Authentication Code, or MAC) of that message. The recipient can recompute the hash and compare it with the received hash value. If they match, the message has not been altered.
   
   - **Example:**
     - Imagine you send a message "Hello, World!" from the client to the server.
     - Before sending, the client computes the hash (e.g., using SHA-256) of the message.
     - The server, upon receiving the message, computes the hash again and compares it with the one sent by the client. If they match, the message is intact.

2. **Digital Signatures:**
   - **Purpose:** Provides authentication and non-repudiation.
   - **How It Works:** A digital signature is essentially a hash of the data that is encrypted with a private key. In SSL/TLS, digital signatures are used to verify the identity of the communicating parties. When the server sends its SSL/TLS certificate, it includes a digital signature that the client can verify using the server's public key.
   
   - **Example:**
     - The server's certificate contains a hash of the certificate's contents. This hash is signed using the server's private key.
     - The client uses the server's public key to decrypt the hash and compare it to a freshly computed hash of the certificate's contents. If they match, the certificate is authentic.

3. **Session Key Generation:**
   - **Purpose:** Helps in creating session keys for encryption.
   - **How It Works:** During the SSL/TLS handshake, hashing is used as part of the process to generate the session keys. These keys are then used for symmetric encryption during the session.
   
   - **Example:**
     - Both the client and server generate the same session key using a combination of the pre-master secret, client and server random values, and a hash function (often HMAC-SHA256).

#### **4.3 Hashing Example in Python**

Let’s look at a simple example of hashing a message using Python's `hashlib` library.

```python
import hashlib

# Hashing with SHA-256
message = "Hello, this is a message to be hashed."
hash_object = hashlib.sha256(message.encode())
hex_dig = hash_object.hexdigest()

print(f"Original Message: {message}")
print(f"SHA-256 Hash: {hex_dig}")
```

**Output:**
```
Original Message: Hello, this is a message to be hashed.
SHA-256 Hash: 36b976c5f7d9d6d89f4e46f1c6cceaba7693b83f785cf27d42153b8ed1569050
```

In this example:
- **Original Message:** "Hello, this is a message to be hashed."
- **SHA-256 Hash:** The resulting hash is a 64-character hexadecimal string that represents the input message.

#### **4. Real-World Example: Using Hashing in Digital Signatures**

When you visit an HTTPS website, the server provides a certificate signed by a Certificate Authority (CA). Here’s a simplified process involving hashing:

1. **Server Certificate Creation:**
   - The server's certificate contains information like the server's public key, domain name, and more.
   - The certificate's content is hashed using a hash function like SHA-256.
   - This hash is then encrypted with the CA's private key to create a digital signature.

2. **Client Verification:**
   - When your browser connects to the server, it receives the certificate and the digital signature.
   - The browser hashes the certificate's contents and compares it to the decrypted signature (using the CA's public key).
   - If they match, the certificate is verified, and the browser can trust that the server is legitimate.

#### **4.5 Importance of Hashing in SSL/TLS**

Hashing is crucial in SSL/TLS for:
- **Ensuring Data Integrity:** By ensuring that any modification of data during transit can be detected.
- **Supporting Authentication:** By enabling digital signatures that verify the authenticity of the communicating parties.
- **Securing Session Keys:** By helping in the derivation of session keys used for encrypting communication.

---


### **Digital Signatures**

Digital signatures are a fundamental component of SSL/TLS, playing a vital role in ensuring that the data exchanged between a client and a server is authentic, has not been tampered with, and can be trusted. Let’s break down the core concepts and components of digital signatures in SSL/TLS

#### **Core Concepts**

1. **Public Key Cryptography:**

   - **Concept:** Public key cryptography is the foundation of digital signatures. It involves two cryptographic keys: 
     - **Public Key:** This key is shared openly and is used to verify a digital signature.
     - **Private Key:** This key is kept secret and is used to create a digital signature.
   - **Example:** 
     - Imagine Alice wants to send a secure message to Bob. Alice uses her private key to sign the message. Bob can then use Alice's public key to verify that the message was indeed signed by Alice and has not been altered.

```python
     from cryptography.hazmat.primitives.asymmetric import rsa, padding
     from cryptography.hazmat.primitives import hashes

     # Generate a private key
     private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

     # Derive the public key from the private key
     public_key = private_key.public_key()

     # Message to be signed
     message = b"Hello, Bob! This is Alice."

     # Create a digital signature using the private key
     signature = private_key.sign(
         message,
         padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
         ),
         hashes.SHA256()
     )

     # Verify the signature using the public key
     public_key.verify(
         signature,
         message,
         padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
         ),
         hashes.SHA256()
     )
```

   - **Explanation:** In this example, Alice generates a digital signature using her private key. Bob, who has access to Alice's public key, verifies that the message is authentic and unaltered.

2. **Hash Functions:**

   - A hash function takes an input (or message) and returns a fixed-size string of bytes. The output is unique for a given input, meaning even a small change in the input will produce a drastically different hash. In digital signatures, the hash of the message is what gets signed, not the entire message.

   - **Example:**
     - Before signing a document, Alice creates a hash of the document. She then encrypts this hash with her private key to create the digital signature. When Bob receives the document and the signature, he creates a hash of the document and uses Alice’s public key to decrypt the signature. If the hashes match, the document is verified.

        ```python
            from cryptography.hazmat.primitives import hashes

            # Hash the message
            digest = hashes.Hash(hashes.SHA256())
            digest.update(b"Hello, Bob! This is Alice.")
            message_hash = digest.finalize()

            print("Message Hash:", message_hash)
        ```
   - **Explanation:** This code produces a unique hash of the message, which can be used in the digital signature process.

#### **Components of a Digital Signature**

1. **Hash Value:**
   - **Definition:** A hash value is a unique digital fingerprint of the data. It's generated using a hash function like SHA-256.
   - **Example:** When Alice wants to sign a message, she first hashes the message to create a fixed-size hash value.
   - **Real-World Example:** Think of a hash value like a fingerprint of a document. Just as each person has a unique fingerprint, each document has a unique hash. If even one letter in the document changes, the fingerprint (hash) will be entirely different.

2. **Signature:**
   - **Definition:** The signature is the encrypted hash value, created using the sender's private key. It proves the authenticity and integrity of the message.
   - **Example:** Alice encrypts the hash value with her private key to create a digital signature. Bob, on receiving the message, can use Alice’s public key to decrypt the signature and compare the hash with the one he generates from the message.
     
     ```python
     # Example showing how the hash is used to create the signature
     signature = private_key.sign(
         message_hash,
         padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
         ),
         hashes.SHA256()
     )
     ```
   - **Real-World Example:** Consider signing a contract with a unique ink that only you possess. If anyone tries to replicate your signature without the ink (private key), it won’t match when checked with the special light (public key).


#### **Real-World Scenario:**

Imagine you're on an e-commerce website, entering your credit card details to make a purchase. The website uses SSL/TLS to secure the connection. When you submit your details, they are hashed and signed using the server’s private key. This signature is then sent along with your data. Your browser, which has the server’s public key, verifies the signature. If the signature is valid, the browser knows that the data came from the legitimate server and hasn't been tampered with.

This process ensures that the sensitive information you send over the internet is secure, authentic, and can be trusted, making SSL/TLS a cornerstone of online security.

---

### Process of Digital Signature Creation and Verification

1. **Hash Generation:** The sender calculates the hash of the data to be signed. This hash value uniquely represents the data. It is generated using a cryptographic hash function like SHA-256.
2. **Signature Creation:** The sender encrypts the hash value using their private key to create the digital signature. This signature is unique to the sender and the data. It proves that the sender has signed the data. The encryption process involves padding and hashing algorithms.
3. **Signature Transmission:** The sender transmits the data and the digital signature to the recipient. The recipient can use the sender's public key to verify the signature. The public key is part of the sender's digital certificate. The certificate is issued by a trusted Certificate Authority (CA). The CA vouches for the authenticity of the public key. The recipient can trust the public key because it is part of a trusted chain of certificates. This process is known as the Public Key Infrastructure (PKI).
4. **Signature Verification:** The recipient calculates the hash of the received data and decrypts the digital signature using the sender's public key.
5. **Comparison:** The recipient compares the calculated hash with the decrypted hash. If they match, the signature is valid. This means the data has not been altered and is authentic. If the hashes do not match, the signature is invalid, indicating that the data has been tampered with. The recipient can reject the data. This process ensures data integrity and authenticity.

### Key Features and Benefits

* **Authentication:** Verifies the identity of the sender. The recipient can trust that the data comes from the claimed source.
* **Integrity:** Ensures that the data has not been modified during transmission. Any alteration would result in an invalid signature.
* **Non-Repudiation:** Prevents the sender from denying having sent the data. The digital signature provides proof of the sender's identity.
* **Confidentiality:** While not directly providing confidentiality, digital signatures can be used in conjunction with encryption algorithms to achieve end-to-end encryption. This ensures that only the intended recipient can read the data.

### Common Algorithms Used in SSL/TLS

* **RSA:** A widely used public-key cryptography algorithm. It is used for digital signatures and key exchange.
* **DSA:** The Digital Signature Algorithm, another popular choice. It is commonly used in government applications.
* **ECDSA:** Elliptic Curve Digital Signature Algorithm, often used for mobile devices and embedded systems due to its efficiency. It provides the same level of security as RSA but with smaller key sizes.

### Security Considerations

* **Key Management:** Proper management of private keys is essential to prevent unauthorized access and misuse.
* **Algorithm Strength:** Choosing strong cryptographic algorithms is crucial for ensuring the security of digital signatures.
* **Certificate Authority (CA):** A trusted third party that issues digital certificates, which contain public keys and other information about the certificate holder.
