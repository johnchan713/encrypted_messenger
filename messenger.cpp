#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <atomic>
#include <vector>
#include <array>
#include <memory>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sodium.h>

constexpr int PORT = 9999;
constexpr size_t NONCE_SIZE = crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
constexpr size_t MAC_SIZE = crypto_aead_chacha20poly1305_IETF_ABYTES;
constexpr size_t KEY_SIZE = crypto_aead_chacha20poly1305_IETF_KEYBYTES;

class SecureMessenger {
private:
    std::array<unsigned char, KEY_SIZE> encryption_key{};
    std::atomic<bool> running{true};
    int socket_fd{-1};

    // Derive encryption key from password using SHA-256
    void derive_key(const std::string& password) {
        unsigned char hash[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(hash,
                          reinterpret_cast<const unsigned char*>(password.data()),
                          password.size());

        // Use first 32 bytes of SHA-256 hash as ChaCha20-Poly1305 key
        std::memcpy(encryption_key.data(), hash, KEY_SIZE);

        // Clear the hash from memory
        sodium_memzero(hash, sizeof(hash));
    }

    // Encrypt message using ChaCha20-Poly1305 AEAD
    std::vector<unsigned char> encrypt_message(const std::string& plaintext) {
        // Generate random nonce
        std::array<unsigned char, NONCE_SIZE> nonce;
        randombytes_buf(nonce.data(), NONCE_SIZE);

        // Allocate buffer for ciphertext (includes MAC tag)
        std::vector<unsigned char> ciphertext(plaintext.size() + MAC_SIZE);
        unsigned long long ciphertext_len;

        // Encrypt with ChaCha20-Poly1305
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
            nullptr, 0,  // No additional authenticated data
            nullptr,     // No secret nonce
            nonce.data(),
            encryption_key.data()
        );

        ciphertext.resize(ciphertext_len);

        // Prepend nonce to ciphertext (nonce doesn't need to be secret)
        std::vector<unsigned char> result;
        result.reserve(NONCE_SIZE + ciphertext_len);
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());

        return result;
    }

    // Decrypt message using ChaCha20-Poly1305 AEAD
    std::string decrypt_message(const std::vector<unsigned char>& encrypted_data) {
        if (encrypted_data.size() < NONCE_SIZE + MAC_SIZE) {
            throw std::runtime_error("Invalid encrypted message size");
        }

        // Extract nonce and ciphertext
        std::array<unsigned char, NONCE_SIZE> nonce;
        std::memcpy(nonce.data(), encrypted_data.data(), NONCE_SIZE);

        const unsigned char* ciphertext = encrypted_data.data() + NONCE_SIZE;
        size_t ciphertext_len = encrypted_data.size() - NONCE_SIZE;

        // Allocate buffer for plaintext
        std::vector<unsigned char> plaintext(ciphertext_len);
        unsigned long long plaintext_len;

        // Decrypt with ChaCha20-Poly1305
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                plaintext.data(), &plaintext_len,
                nullptr,  // No secret nonce
                ciphertext, ciphertext_len,
                nullptr, 0,  // No additional authenticated data
                nonce.data(),
                encryption_key.data()) != 0) {
            throw std::runtime_error("Decryption failed - invalid key or corrupted message");
        }

        return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
    }

    // Send encrypted message over socket
    void send_message(const std::string& message) {
        auto encrypted = encrypt_message(message);

        // Send message length first (4 bytes)
        uint32_t msg_len = htonl(encrypted.size());
        if (send(socket_fd, &msg_len, sizeof(msg_len), 0) != sizeof(msg_len)) {
            throw std::runtime_error("Failed to send message length");
        }

        // Send encrypted message
        size_t total_sent = 0;
        while (total_sent < encrypted.size()) {
            ssize_t sent = send(socket_fd, encrypted.data() + total_sent,
                               encrypted.size() - total_sent, 0);
            if (sent <= 0) {
                throw std::runtime_error("Failed to send message");
            }
            total_sent += sent;
        }
    }

    // Receive encrypted message from socket
    std::string receive_message() {
        // Receive message length first
        uint32_t msg_len;
        if (recv(socket_fd, &msg_len, sizeof(msg_len), MSG_WAITALL) != sizeof(msg_len)) {
            throw std::runtime_error("Connection closed");
        }
        msg_len = ntohl(msg_len);

        if (msg_len == 0 || msg_len > 1024 * 1024) {  // Max 1MB message
            throw std::runtime_error("Invalid message length");
        }

        // Receive encrypted message
        std::vector<unsigned char> encrypted(msg_len);
        size_t total_received = 0;
        while (total_received < msg_len) {
            ssize_t received = recv(socket_fd, encrypted.data() + total_received,
                                   msg_len - total_received, 0);
            if (received <= 0) {
                throw std::runtime_error("Connection closed");
            }
            total_received += received;
        }

        return decrypt_message(encrypted);
    }

    // Thread for receiving messages
    void receive_loop() {
        while (running) {
            try {
                std::string message = receive_message();
                std::cout << "\n[Them]: " << message << std::endl;
                std::cout << "[You]: " << std::flush;
            } catch (const std::exception& e) {
                if (running) {
                    std::cerr << "\nError receiving message: " << e.what() << std::endl;
                    running = false;
                }
                break;
            }
        }
    }

    // Get masked password input
    std::string get_masked_password(const std::string& prompt) {
        std::cout << prompt << std::flush;

        // Disable echo
        termios oldt;
        tcgetattr(STDIN_FILENO, &oldt);
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        std::string password;
        std::getline(std::cin, password);

        // Restore echo
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << std::endl;

        return password;
    }

    // Display local IP addresses
    void display_ip_addresses() {
        ifaddrs* ifaddr;
        if (getifaddrs(&ifaddr) == -1) {
            std::cerr << "Failed to get IP addresses" << std::endl;
            return;
        }

        std::cout << "\n=== Your IP Addresses ===" << std::endl;
        for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;

            int family = ifa->ifa_addr->sa_family;
            if (family == AF_INET) {
                char host[NI_MAXHOST];
                getnameinfo(ifa->ifa_addr, sizeof(sockaddr_in),
                           host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);

                std::string ip(host);
                // Skip loopback
                if (ip != "127.0.0.1") {
                    std::cout << "  " << ifa->ifa_name << ": " << host << std::endl;
                }
            }
        }
        std::cout << "=========================" << std::endl;
        freeifaddrs(ifaddr);
    }

public:
    SecureMessenger() {
        // Initialize libsodium
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    ~SecureMessenger() {
        running = false;
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        // Clear encryption key from memory
        sodium_memzero(encryption_key.data(), encryption_key.size());
    }

    // Run as server
    void run_server() {
        std::cout << "=== Encrypted Messenger - Server Mode ===" << std::endl;

        // Get encryption key
        std::string password = get_masked_password("Enter encryption key: ");
        derive_key(password);
        sodium_memzero(password.data(), password.size());  // Clear password from memory

        std::cout << "Key set successfully." << std::endl;

        // Display IP addresses
        display_ip_addresses();

        // Create socket
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Set socket options
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // Bind socket
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);

        if (bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            close(server_fd);
            throw std::runtime_error("Failed to bind socket to port " + std::to_string(PORT));
        }

        // Listen for connections
        if (listen(server_fd, 1) < 0) {
            close(server_fd);
            throw std::runtime_error("Failed to listen on socket");
        }

        std::cout << "\nWaiting for client connection on port " << PORT << "..." << std::endl;

        // Accept connection
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        socket_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        close(server_fd);  // Don't need server socket anymore

        if (socket_fd < 0) {
            throw std::runtime_error("Failed to accept connection");
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        std::cout << "Client connected from: " << client_ip << std::endl;

        // Key verification handshake
        std::cout << "Waiting for client to verify key..." << std::endl;

        try {
            std::string handshake = receive_message();
            if (handshake == "HANDSHAKE_OK") {
                send_message("HANDSHAKE_OK");
                std::cout << "Key verified successfully!" << std::endl;
            } else {
                throw std::runtime_error("Invalid handshake");
            }
        } catch (const std::exception& e) {
            std::cerr << "Key verification failed: " << e.what() << std::endl;
            return;
        }

        start_messaging();
    }

    // Run as client
    void run_client() {
        std::cout << "=== Encrypted Messenger - Client Mode ===" << std::endl;

        // Get server IP
        std::string server_ip;
        std::cout << "Enter server IP address: ";
        std::getline(std::cin, server_ip);

        // Get encryption key
        std::string password = get_masked_password("Enter encryption key: ");
        derive_key(password);
        sodium_memzero(password.data(), password.size());  // Clear password from memory

        std::cout << "Connecting to server..." << std::endl;

        // Create socket
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Connect to server
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);

        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid IP address");
        }

        if (connect(socket_fd, reinterpret_cast<sockaddr*>(&server_addr),
                   sizeof(server_addr)) < 0) {
            throw std::runtime_error("Failed to connect to server");
        }

        std::cout << "Connected to server!" << std::endl;
        std::cout << "Verifying encryption key..." << std::endl;

        // Key verification handshake
        try {
            send_message("HANDSHAKE_OK");
            std::string response = receive_message();
            if (response == "HANDSHAKE_OK") {
                std::cout << "Key verified successfully!" << std::endl;
            } else {
                throw std::runtime_error("Invalid handshake response");
            }
        } catch (const std::exception& e) {
            std::cerr << "Key verification failed: " << e.what() << std::endl;
            std::cerr << "Make sure both sides are using the same key." << std::endl;
            return;
        }

        start_messaging();
    }

private:
    void start_messaging() {
        std::cout << "\n=== Secure messaging started ===" << std::endl;
        std::cout << "Type your messages and press Enter to send." << std::endl;
        std::cout << "Type 'quit' to exit.\n" << std::endl;

        // Start receive thread
        std::thread receive_thread(&SecureMessenger::receive_loop, this);

        // Send loop (main thread)
        std::string input;
        while (running) {
            std::cout << "[You]: " << std::flush;
            std::getline(std::cin, input);

            if (input == "quit") {
                running = false;
                break;
            }

            if (input.empty()) continue;

            try {
                send_message(input);
            } catch (const std::exception& e) {
                std::cerr << "Error sending message: " << e.what() << std::endl;
                running = false;
                break;
            }
        }

        // Cleanup
        running = false;
        if (socket_fd >= 0) {
            shutdown(socket_fd, SHUT_RDWR);
        }

        if (receive_thread.joinable()) {
            receive_thread.join();
        }

        std::cout << "\nMessaging session ended." << std::endl;
    }
};

int main(int argc, char* argv[]) {
    try {
        SecureMessenger messenger;

        if (argc > 1 && std::string(argv[1]) == "server") {
            messenger.run_server();
        } else if (argc > 1 && std::string(argv[1]) == "client") {
            messenger.run_client();
        } else {
            std::cout << "Usage:" << std::endl;
            std::cout << "  Server mode: " << argv[0] << " server" << std::endl;
            std::cout << "  Client mode: " << argv[0] << " client" << std::endl;
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
