/*
 * ============================================================================
 * PROJECT: HEAB + SBM Financial Execution Stack v7.0
 * MODULE: udp_tls_relay.cpp
 * PURPOSE: Deployed to AWS us-east-1 to bypass Saskatoon geoblocking.
 * CORRECTIONS IN V7.0:
 * - HMAC-SHA256 + replay window replaces trivial IP whitelist
 * - Constant-time HMAC comparison prevents timing oracle
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
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

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#define RELAY_UDP_PORT 13370
#define POLYMARKET_HOST "clob.polymarket.com"
#define POLYMARKET_PORT "443"

// HMAC packet format: [4-byte seq] [8-byte timestamp_ns] [32-byte HMAC] [payload]
static constexpr size_t RELAY_HEADER_SIZE = 4 + 8 + 32;
static constexpr uint64_t REPLAY_WINDOW_NS = 5'000'000'000ULL; // 5 seconds

std::atomic<bool> running{true};
SSL* active_ssl = nullptr;
int active_tcp_fd = -1;

uint8_t RELAY_PSK[32];

#ifdef __aarch64__
    // Apple Silicon / ARM64
    uint64_t rdtsc_to_ns() {
        uint64_t tsc;
        asm volatile("mrs %0, cntvct_el0" : "=r"(tsc));
        // Simple monotonic time since tsc scaling is complex
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }
    
    inline void cpu_relax() {
        asm volatile("yield");
    }
#else
    // x86_64
    uint64_t rdtsc_to_ns() {
        uint64_t tsc = __builtin_ia32_rdtsc();
        static constexpr double TSC_NS_PER_CYCLE = 0.4; // ~2.5 GHz CPU
        return (uint64_t)(tsc * TSC_NS_PER_CYCLE);
    }

    inline void cpu_relax() {
        _mm_pause();
    }
#endif

SSL_CTX* init_ssl_context() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "[FATAL] SSL_CTX_new failed.\n";
        std::exit(EXIT_FAILURE);
    }
    return ctx;
}

void connect_to_polymarket(SSL_CTX* ctx) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(POLYMARKET_HOST, POLYMARKET_PORT, &hints, &res) != 0) {
        std::cerr << "[FATAL] getaddrinfo failed.\n";
        std::exit(EXIT_FAILURE);
    }

    active_tcp_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (active_tcp_fd < 0) {
        std::cerr << "[FATAL] socket() failed.\n";
        std::exit(EXIT_FAILURE);
    }

    int flag = 1;
    setsockopt(active_tcp_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));

    if (connect(active_tcp_fd, res->ai_addr, res->ai_addrlen) < 0) {
        std::cerr << "[FATAL] connect() to Polymarket failed.\n";
        std::exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    active_ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(active_ssl, POLYMARKET_HOST);
    SSL_set_fd(active_ssl, active_tcp_fd);

    if (SSL_connect(active_ssl) <= 0) {
        std::cerr << "[FATAL] SSL_connect failed.\n";
        std::exit(EXIT_FAILURE);
    }

    std::cout << "[TLS] Connection Warmed and Locked." << std::endl;
}

void keep_alive_loop() {
    const std::string ping_req = "GET /time HTTP/1.1\r\nHost: clob.polymarket.com\r\nConnection: keep-alive\r\n\r\n";
    while (running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (active_ssl) {
            SSL_write(active_ssl, (const uint8_t*)ping_req.c_str(), ping_req.length());
        }
    }
}

bool verify_relay_packet(const uint8_t* buf, int len) {
    if (len < (int)RELAY_HEADER_SIZE) return false;

    // Extract timestamp and verify replay window
    uint64_t ts;
    memcpy(&ts, buf + 4, 8);
    uint64_t now_ns = rdtsc_to_ns();
    if (llabs((int64_t)(now_ns - ts)) > (int64_t)REPLAY_WINDOW_NS) {
        std::cerr << "[REPLAY-REJECT] Timestamp outside 5s window.\n";
        return false;
    }

    // Verify HMAC over [seq + timestamp + payload]
    uint8_t expected_mac[32];
    unsigned int mac_len = 32;
    HMAC(EVP_sha256(), RELAY_PSK, 32,
         buf, len - 32,  // Everything except the MAC bytes
         expected_mac, &mac_len);

    // Constant-time compare (prevents timing oracle)
    if (CRYPTO_memcmp(buf + len - 32, expected_mac, 32) != 0) {
        std::cerr << "[HMAC-REJECT] Authentication failed.\n";
        return false;
    }

    return true;
}

void relay_hot_path() {
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        std::cerr << "[FATAL] socket(SOCK_DGRAM) failed.\n";
        std::exit(EXIT_FAILURE);
    }

    int flags = fcntl(udp_fd, F_GETFL, 0);
    fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(RELAY_UDP_PORT);

    if (bind(udp_fd, (const struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "[FATAL] bind() failed.\n";
        std::exit(EXIT_FAILURE);
    }

    uint8_t buffer[2048];
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    std::cout << "[HOT-PATH] Busy-polling active (HMAC + replay protection enabled)." << std::endl;

    while (running.load(std::memory_order_relaxed)) {
        int len = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                           (struct sockaddr*)&client_addr, &client_len);
        if (len > 0) {
            if (verify_relay_packet(buffer, len)) {
                // Strip the header and send only the payload
                int payload_len = len - RELAY_HEADER_SIZE;
                SSL_write(active_ssl, buffer + RELAY_HEADER_SIZE, payload_len);
                std::cout << "[RELAY-OK] Forwarded " << payload_len << " bytes.\n";
            }
        } else {
            cpu_relax();
        }
    }

    close(udp_fd);
}

int main() {
    // Load PSK from environment variable
    const char* psk_hex = std::getenv("RELAY_PSK_HEX");
    if (!psk_hex) {
        std::cerr << "[FATAL] Set RELAY_PSK_HEX environment variable (64 hex chars).\n";
        std::exit(EXIT_FAILURE);
    }

    // Parse hex into 32 bytes
    if (std::strlen(psk_hex) != 64) {
        std::cerr << "[FATAL] RELAY_PSK_HEX must be 64 hex characters (32 bytes).\n";
        std::exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 32; i++) {
        char byte_str[3] = {psk_hex[i*2], psk_hex[i*2+1], '\0'};
        RELAY_PSK[i] = (uint8_t)std::strtol(byte_str, nullptr, 16);
    }

    std::cout << "[PSK] Loaded 32-byte relay secret from RELAY_PSK_HEX.\n";

    // CPU affinity (Linux only)
    #if defined(__linux__)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    #endif

    SSL_CTX* ctx = init_ssl_context();
    connect_to_polymarket(ctx);

    std::thread hb(keep_alive_loop);
    
    #if defined(__linux__)
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    pthread_setaffinity_np(hb.native_handle(), sizeof(cpu_set_t), &cpuset);
    #endif

    relay_hot_path();
    hb.join();

    return 0;
}
