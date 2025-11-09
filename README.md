# Encrypted Messenger

A secure peer-to-peer encrypted messaging application written in C++23 for Linux.

## Features

- **End-to-end encryption**: Messages are encrypted using ChaCha20-Poly1305 AEAD
- **Key derivation**: SHA-256 hash of shared password for cryptographic key
- **Secure key input**: Password masking in console
- **Asynchronous messaging**: Real-time bidirectional communication
- **Simple setup**: One person hosts (server), another connects (client)

## Cryptographic Design

1. **Key Derivation**: SHA-256 hash of the shared password generates a 256-bit key
2. **Encryption**: ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
   - ChaCha20 stream cipher for confidentiality
   - Poly1305 MAC for authentication and integrity
   - Random nonce for each message
   - Protection against tampering and replay attacks

## Prerequisites

Install required dependencies:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential cmake libsodium-dev pkg-config

# Fedora/RHEL
sudo dnf install gcc-c++ cmake libsodium-devel pkgconfig

# Arch Linux
sudo pacman -S base-devel cmake libsodium
```

## Building

```bash
mkdir build
cd build
cmake ..
make
```

This will create the `messenger` executable in the build directory.

## Usage

### Step 1: Server Setup

On the first computer (server), run:

```bash
./messenger server
```

1. Enter your shared encryption key (e.g., "abc") - **it will be masked**
2. The application will display available IP addresses
3. Wait for the client to connect
4. Once connected, the key will be verified
5. Start messaging!

### Step 2: Client Connection

On the second computer (client), run:

```bash
./messenger client
```

1. Enter the server's IP address (shown by the server)
2. Enter the same encryption key - **it will be masked**
3. The application will connect and verify the key
4. Start messaging!

### Messaging

- Type your message and press Enter to send
- Messages from the other person appear asynchronously with `[Them]:` prefix
- Your messages show with `[You]:` prefix
- Type `quit` to exit

## Example Session

**Server:**
```
=== Encrypted Messenger - Server Mode ===
Enter encryption key: ****
Key set successfully.

=== Your IP Addresses ===
  eth0: 192.168.1.100
=========================

Waiting for client connection on port 9999...
Client connected from: 192.168.1.101
Waiting for client to verify key...
Key verified successfully!

=== Secure messaging started ===
Type your messages and press Enter to send.
Type 'quit' to exit.

[You]: Hello!
[Them]: Hi there! The encryption is working!
[You]: Perfect!
```

**Client:**
```
=== Encrypted Messenger - Client Mode ===
Enter server IP address: 192.168.1.100
Enter encryption key: ****
Connecting to server...
Connected to server!
Verifying encryption key...
Key verified successfully!

=== Secure messaging started ===
Type your messages and press Enter to send.
Type 'quit' to exit.

[Them]: Hello!
[You]: Hi there! The encryption is working!
[Them]: Perfect!
```

## Security Notes

1. **Shared Key**: Both parties must know the same password beforehand
2. **Secure Channel**: Exchange the password through a secure channel (not over the internet)
3. **Strong Passwords**: Use strong, unique passwords for better security
4. **Network Security**: Messages are encrypted, but use on trusted networks
5. **Memory Safety**: Keys are securely erased from memory when done
6. **Port**: Default port is 9999 (configurable in source code)

## Technical Details

- **Language**: C++23
- **Crypto Library**: libsodium
- **Encryption**: ChaCha20-Poly1305-IETF AEAD
- **Key Derivation**: SHA-256
- **Key Size**: 256 bits
- **Nonce Size**: 96 bits (automatically generated per message)
- **MAC Size**: 128 bits (authentication tag)
- **Network**: TCP sockets (IPv4)
- **Threading**: POSIX threads for async I/O

## How It Works

1. Server and client both derive a 256-bit encryption key from the shared password using SHA-256
2. Client connects to server over TCP
3. Handshake verification ensures both sides have the correct key
4. Each message is encrypted with ChaCha20-Poly1305:
   - A random 96-bit nonce is generated
   - Message is encrypted with ChaCha20
   - Poly1305 MAC is computed for authentication
   - Nonce + ciphertext + MAC are sent
5. Receiver decrypts and verifies the MAC
6. Messages are sent/received asynchronously using threads

## Limitations

- Supports only two participants (peer-to-peer)
- No persistent message history
- Requires direct network connectivity (no NAT traversal)
- IPv4 only
- Single session (no reconnection handling)

## License

This is a simple educational implementation. Use at your own risk for personal communication.

## Troubleshooting

**Connection refused**:
- Check firewall settings
- Ensure server is running and listening
- Verify IP address is correct

**Key verification failed**:
- Both parties must use exactly the same password
- Keys are case-sensitive

**Build errors**:
- Ensure libsodium-dev is installed
- Check that C++23 compiler is available (GCC 11+ or Clang 14+)
