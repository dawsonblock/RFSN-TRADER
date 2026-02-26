/*
 * ============================================================================
 * PROJECT: HEAB + SBM Financial Execution Stack v7.0
 * MODULE: udp_tls_relay.cpp
 * PURPOSE: Coherent, authenticated UDP -> TLS Relay
 * PROTOCOL: [SEQ(4)][TS(8)][KEY_ID(1)][HMAC(32)][PAYLOAD(N)]
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <cstdlib>
#include <ctime>

// MacOS / Linux Endianness Portability
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
#include <endian.h>
#endif

// Configuration
#define RELAY_UDP_PORT 13370
#define POLYMARKET_HOST "clob.polymarket.com"
#define POLYMARKET_PORT "443"
#define REPLAY_WINDOW_NS 2000000000ULL // 2 seconds

// Protocol Definition
// Header: [SEQ(4)] [TS(8)] [KEY_ID(1)] [MAC(32)]
static constexpr size_t RELAY_HEADER_SIZE = 45;
static constexpr size_t MAC_OFFSET = 13; // 4 + 8 + 1
static constexpr size_t MAC_SIZE = 32;

// Key Store (In production, load from vault/env)
// map<key_id, psk>
static std::unordered_map<uint8_t, std::string> KEY_STORE;

std::atomic<bool> running{true};
SSL* active_ssl = nullptr;
int active_tcp_fd = -1;

// Helper: Get monotonic epoch time in nanoseconds
uint64_t epoch_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void load_keys() {
    // Default key for ID 1
    const char* psk_hex = std::getenv("RELAY_PSK_HEX");
    if (psk_hex && std::strlen(psk_hex) == 64) {
        std::string psk_bytes;
        for (size_t i = 0; i < 32; i++) {
            char byte_str[3] = {psk_hex[i*2], psk_hex[i*2+1], '\0'};
            psk_bytes.push_back((char)std::strtol(byte_str, nullptr, 16));
        }
        KEY_STORE[1] = psk_bytes;
        std::cout << "[INIT] Loaded Key ID 1 from environment.\n";
    } else {
        std::cerr << "[WARN] No RELAY_PSK_HEX found. Using hardcoded test key for ID 1.\n";
        KEY_STORE[1] = std::string(32, 'A'); // Dummy key
    }
}

SSL_CTX* init_ssl_context() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "[FATAL] SSL_CTX_new failed.\n";
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void connect_to_polymarket(SSL_CTX* ctx) {
    if (active_ssl) {
        SSL_shutdown(active_ssl);
        SSL_free(active_ssl);
        active_ssl = nullptr;
    }
    if (active_tcp_fd >= 0) {
        close(active_tcp_fd);
        active_tcp_fd = -1;
    }

    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(POLYMARKET_HOST, POLYMARKET_PORT, &hints, &res) != 0) {
        std::cerr << "[ERR] getaddrinfo failed. Retrying...\n";
        return;
    }

    active_tcp_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (active_tcp_fd < 0) {
        std::cerr << "[ERR] socket failed.\n";
        freeaddrinfo(res);
        return;
    }

    int flag = 1;
    setsockopt(active_tcp_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));

    if (connect(active_tcp_fd, res->ai_addr, res->ai_addrlen) < 0) {
        std::cerr << "[ERR] connect failed.\n";
        close(active_tcp_fd);
        active_tcp_fd = -1;
        freeaddrinfo(res);
        return;
    }
    freeaddrinfo(res);

    active_ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(active_ssl, POLYMARKET_HOST);
    SSL_set_fd(active_ssl, active_tcp_fd);

    if (SSL_connect(active_ssl) <= 0) {
        std::cerr << "[ERR] SSL_connect failed.\n";
        SSL_free(active_ssl);
        active_ssl = nullptr;
        close(active_tcp_fd);
        active_tcp_fd = -1;
        return;
    }

    std::cout << "[TLS] Connection Established to " << POLYMARKET_HOST << "\n";
}

void keep_alive_loop(SSL_CTX* ctx) {
    const std::string ping_req = "GET /time HTTP/1.1\r\nHost: " POLYMARKET_HOST "\r\nConnection: keep-alive\r\n\r\n";
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        if (!active_ssl) {
            connect_to_polymarket(ctx);
            continue;
        }

        int written = SSL_write(active_ssl, ping_req.c_str(), ping_req.length());
        if (written <= 0) {
            std::cerr << "[TLS] Keep-alive write failed. Reconnecting...\n";
            connect_to_polymarket(ctx);
        }
    }
}

bool verify_packet(uint8_t* buffer, int len, int& payload_offset, int& payload_len) {
    if (len < (int)RELAY_HEADER_SIZE) return false;

    // 1. Parsing
    uint32_t seq_net;
    uint64_t ts_net;
    uint8_t key_id;
    
    std::memcpy(&seq_net, buffer, 4);
    std::memcpy(&ts_net, buffer + 4, 8);
    key_id = buffer[12];

    uint32_t seq = ntohl(seq_net);
    uint64_t ts = be64toh(ts_net);
    (void)seq; // unused but parsed

    // 2. Timestamp check (Replay)
    uint64_t now = epoch_ns();
    int64_t diff = (int64_t)(now - ts); // can be negative if clocks drift slightly forward
    if (std::abs(diff) > (int64_t)REPLAY_WINDOW_NS) {
        std::cerr << "[REJECT] Timestamp skew > 2s. Diff: " << diff << "ns\n";
        return false;
    }

    // 3. Key Lookup
    if (KEY_STORE.find(key_id) == KEY_STORE.end()) {
        std::cerr << "[REJECT] Unknown Key ID: " << (int)key_id << "\n";
        return false;
    }
    const std::string& key = KEY_STORE[key_id];

    // 4. HMAC Verify
    // The MAC in the packet is at offset 13 (4+8+1)
    uint8_t* received_mac = buffer + MAC_OFFSET;
    
    // Data covered by MAC: [SEQ][TS][KEY_ID]... [PAYLOAD]
    // Basically everything EXCEPT the MAC bytes themselves.
    // To preserve zero-copyish behavior, we hash the prefix (0-13) and suffix (45-end).
    
    uint8_t calculated_mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len;
    
    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, key.data(), key.size(), EVP_sha256(), nullptr);
    
    // Header parts before MAC
    HMAC_Update(hmac_ctx, buffer, MAC_OFFSET);
    
    // Payload parts after MAC
    payload_offset = RELAY_HEADER_SIZE;
    payload_len = len - RELAY_HEADER_SIZE;
    if (payload_len > 0) {
        HMAC_Update(hmac_ctx, buffer + payload_offset, payload_len);
    }
    
    HMAC_Final(hmac_ctx, calculated_mac, &mac_len);
    HMAC_CTX_free(hmac_ctx);

    if (CRYPTO_memcmp(received_mac, calculated_mac, 32) != 0) {
        std::cerr << "[REJECT] HMAC Mismatch\n";
        return false;
    }

    return true;
}

void udp_server_loop() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // Non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in servaddr{}, cliaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(RELAY_UDP_PORT); // 13370

    if (bind(sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        exit(1);
    }

    std::cout << "[UDP] Listening on port " << RELAY_UDP_PORT << "\n";

    uint8_t buffer[4096];
    socklen_t len;

    while (running) {
        len = sizeof(cliaddr);
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&cliaddr, &len);
        
        if (n > 0) {
            int p_offset, p_len;
            if (verify_packet(buffer, n, p_offset, p_len)) {
                 if (active_ssl && p_len > 0) {
                     int written = SSL_write(active_ssl, buffer + p_offset, p_len);
                     if (written > 0) {
                         std::cout << "[FWD] " << p_len << " bytes to TLS\n";
                     } else {
                         std::cerr << "[ERR] SSL_write failed\n";
                     }
                 } else {
                     std::cerr << "[DROP] No active TLS connection\n";
                 }
            }
        } else {
            // Busy loop yield
             std::this_thread::yield(); 
        }
    }
    close(sockfd);
}

int main() {
    load_keys();
    SSL_CTX* ctx = init_ssl_context();
    connect_to_polymarket(ctx);

    std::thread hb(keep_alive_loop, ctx);
    udp_server_loop();
    hb.join();
    SSL_CTX_free(ctx);
    return 0;
}
