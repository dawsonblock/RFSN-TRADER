/*
 * ============================================================================
 * PROJECT: HEAB + SBM Financial Execution Stack v7.0
 * MODULE: dtls_relay_poll.cpp
 * PURPOSE: Single-Client DTLS 1.2 PSK Relay to Polymarket (MacOS/Linux Portable)
 * AUTH: PSK (Identity: "client1", Key: 32 bytes of 'A')
 * UPSTREAM: Persistent TLS to clob.polymarket.com
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <poll.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

// Configuration
#define LISTEN_PORT 13370
std::string UPSTREAM_HOST = "clob.polymarket.com";
std::string UPSTREAM_PORT = "443";
#define PSK_IDENTITY "client1"
// 32 bytes of 'A' (hex 41)
#define PSK_KEY_HEX "4141414141414141414141414141414141414141414141414141414141414141"

// Globals
int udp_fd = -1;
int tcp_fd = -1;
SSL_CTX* dtls_ctx = nullptr;
SSL_CTX* tls_ctx = nullptr;
SSL* dtls_ssl = nullptr;
SSL* tls_ssl = nullptr;
bool connected = false;
bool handshaking = false;

// Helper: Hex string to bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes.push_back((uint8_t)strtol(byteString.c_str(), nullptr, 16));
    }
    return bytes;
}

// PSK Callback for server
unsigned int psk_server_cb(SSL* ssl, const char* identity, unsigned char* psk, unsigned int max_psk_len) {
    (void)ssl;
    std::cout << "[PSK] Identity received: " << identity << "\n";

    if (strcmp(identity, PSK_IDENTITY) != 0) {
        std::cerr << "[PSK] Unknown identity\n";
        return 0;
    }

    std::vector<uint8_t> key = hex_to_bytes(PSK_KEY_HEX);
    if (key.size() > max_psk_len) {
        std::cerr << "[PSK] Key too long\n";
        return 0;
    }

    memcpy(psk, key.data(), key.size());
    return key.size();
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Upstream Connection Logic
bool connect_upstream() {
    if (tls_ssl) {
        SSL_shutdown(tls_ssl);
        SSL_free(tls_ssl);
        tls_ssl = nullptr;
    }
    if (tcp_fd >= 0) {
        close(tcp_fd);
        tcp_fd = -1;
    }

    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(UPSTREAM_HOST.c_str(), UPSTREAM_PORT.c_str(), &hints, &res) != 0) {
        std::cerr << "[UPSTREAM] DNS Resolution Failed\n";
        return false;
    }

    tcp_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (tcp_fd < 0) {
        freeaddrinfo(res);
        return false;
    }

    if (connect(tcp_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect upstream");
        close(tcp_fd);
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);
    set_nonblocking(tcp_fd);

    tls_ssl = SSL_new(tls_ctx);
    SSL_set_fd(tls_ssl, tcp_fd);
    SSL_set_connect_state(tls_ssl);

    if (SSL_connect(tls_ssl) <= 0) {
        // Simple blocking connect
    }
    
    std::cout << "[UPSTREAM] Connected to " << UPSTREAM_HOST << "\n";
    return true;
}

// Reset DTLS session for next client
void reset_dtls_session() {
    if (dtls_ssl) {
        SSL_shutdown(dtls_ssl);
        SSL_free(dtls_ssl);
    }
    
    dtls_ssl = SSL_new(dtls_ctx);
    
    // Re-bind BIO
    BIO* bio = BIO_new_dgram(udp_fd, BIO_NOCLOSE);
    SSL_set_bio(dtls_ssl, bio, bio);
    
    connected = false;
    handshaking = false;
}

// Initialization
void init_openssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // DTLS Context
    dtls_ctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_set_psk_server_callback(dtls_ctx, psk_server_cb);
    
    // Enable PSK Ciphers explicitly and lower security level for compatibility
    SSL_CTX_set_security_level(dtls_ctx, 1); 
    SSL_CTX_set_cipher_list(dtls_ctx, "PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA");
    
    // Cookie generation and verification
    SSL_CTX_set_cookie_generate_cb(dtls_ctx, [](SSL* ssl, unsigned char* cookie, unsigned int* cookie_len) -> int {
        (void)ssl;
        RAND_bytes(cookie, DTLS1_COOKIE_LENGTH);
        *cookie_len = DTLS1_COOKIE_LENGTH;
        return 1;
    });
    SSL_CTX_set_cookie_verify_cb(dtls_ctx, [](SSL* ssl, const unsigned char* cookie, unsigned int cookie_len) -> int {
        (void)ssl; (void)cookie; (void)cookie_len;
        return 1;
    });

    // Upstream TLS Context
    tls_ctx = SSL_CTX_new(TLS_client_method());
}

int main(int argc, char** argv) {
    if (argc >= 4) {
        if (argc >= 5) {
             UPSTREAM_HOST = argv[3];
             UPSTREAM_PORT = argv[4];
        }
    }

    init_openssl();

    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);
    
    int reuse = 1;
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    if (bind(udp_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    set_nonblocking(udp_fd);

    std::cout << "[RELAY] Listening on UDP " << LISTEN_PORT << " (DTLS)\n";

    // Establish upstream
    if (!connect_upstream()) return 1;

    // Main Loop
    struct pollfd fds[2];
    
    // Initial DTLS Setup
    BIO_ADDR* peer_addr = BIO_ADDR_new();
    
    // Create first session
    dtls_ssl = SSL_new(dtls_ctx);
    BIO* bio = BIO_new_dgram(udp_fd, BIO_NOCLOSE);
    SSL_set_bio(dtls_ssl, bio, bio);

    while (true) {
        fds[0].fd = udp_fd;
        fds[0].events = POLLIN;
        fds[1].fd = tcp_fd;
        fds[1].events = POLLIN;

        int ret = poll(fds, 2, 1000); // 1s timeout
        if (ret < 0) break;

        // Upstream Maintenance
        if ((fds[1].revents & (POLLHUP|POLLERR)) || (tcp_fd == -1)) {
            std::cerr << "[UPSTREAM] Disconnected. Reconnecting...\n";
            connect_upstream();
        }

        // --- UDP (Downstream) Handling ---
        if (fds[0].revents & POLLIN) {
            if (!connected) {
                if (!handshaking) {
                    // LISTEN Phase
                    int res = DTLSv1_listen(dtls_ssl, peer_addr);
                    if (res > 0) {
                        std::cout << "[DTLS] Client Hello Verified.\n";
                        handshaking = true;
                        
                        // Attempt to advance handshake immediately
                        int acc = SSL_accept(dtls_ssl);
                        if (acc <= 0) {
                            int err = SSL_get_error(dtls_ssl, acc);
                            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                                ERR_print_errors_fp(stderr);
                                reset_dtls_session();
                            }
                        } else {
                            connected = true;
                            handshaking = false;
                            std::cout << "[DTLS] Handshake Complete Immediately.\n";
                        }
                    } else if (res < 0) {
                        ERR_clear_error();
                    }
                } else {
                    // HANDSHAKING Phase
                    int acc = SSL_accept(dtls_ssl);
                    if (acc > 0) {
                        connected = true;
                        handshaking = false;
                        std::cout << "[DTLS] Handshake Complete.\n";
                    } else {
                        int err = SSL_get_error(dtls_ssl, acc);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                             std::cerr << "[DTLS] Handshake Error. Resetting.\n";
                             ERR_print_errors_fp(stderr);
                             reset_dtls_session();
                        }
                    }
                }
            } else {
                // DATA Phase
                char buf[8192];
                int len = SSL_read(dtls_ssl, buf, sizeof(buf));
                if (len > 0) {
                    std::cout << "[DTLS] Received " << len << " bytes. Forwarding...\n";
                    if (tls_ssl) SSL_write(tls_ssl, buf, len);
                } else {
                    int err = SSL_get_error(dtls_ssl, len);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                        std::cerr << "[DTLS] Read Error/Close. Resetting.\n";
                        reset_dtls_session();
                    }
                }
            }
        }

        // --- Upstream (TCP) Handling ---
        if (connected && (fds[1].revents & POLLIN)) {
             char buf[8192];
             int len = SSL_read(tls_ssl, buf, sizeof(buf));
             if (len > 0) {
                 if (connected) SSL_write(dtls_ssl, buf, len);
             } else {
                 connect_upstream();
             }
        }
    }

    BIO_ADDR_free(peer_addr);
    return 0;
}
