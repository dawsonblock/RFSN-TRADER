/*
 * ============================================================================
 * PROJECT: HEAB + SBM Financial Execution Stack v7.0
 * MODULE: udp_sender.cpp
 * PURPOSE: Secure UDP Sender Client (Test/Localhost)
 *          Generates valid packets for the udp_tls_relay
 * PROTOCOL: [SEQ(4)][TS(8)][KEY_ID(1)][HMAC(32)][PAYLOAD(N)]
 * ============================================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
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
#define RELAY_HOST "127.0.0.1"
#define RELAY_PORT 13370
#define KEY_ID 1

uint64_t epoch_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

std::vector<uint8_t> build_packet(uint32_t seq, const std::string& payload, const std::string& key) {
    std::vector<uint8_t> buffer;
    
    // 1. Header: SEQ (4)
    uint32_t seq_net = htonl(seq);
    buffer.resize(4);
    std::memcpy(buffer.data(), &seq_net, 4);
    
    // 2. Header: TS (8)
    uint64_t ts = epoch_ns();
    uint64_t ts_net = htobe64(ts);
    buffer.resize(12);
    std::memcpy(buffer.data() + 4, &ts_net, 8);
    
    // 3. Header: KEY_ID (1)
    buffer.push_back(KEY_ID);
    
    // 4. Header: MAC Placeholder (32)
    size_t mac_offset = buffer.size();
    buffer.resize(mac_offset + 32, 0);
    
    // 5. Payload
    buffer.insert(buffer.end(), payload.begin(), payload.end());
    
    // 6. Calculate MAC
    unsigned int mac_len;
    uint8_t calculated_mac[EVP_MAX_MD_SIZE];
    
    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    HMAC_Init_ex(hmac_ctx, key.data(), key.size(), EVP_sha256(), nullptr);
    
    // Hash Header (0 -> mac_offset) // [SEQ][TS][KEY_ID]
    HMAC_Update(hmac_ctx, buffer.data(), mac_offset);
    
    // Hash Payload (mac_offset+32 -> end)
    HMAC_Update(hmac_ctx, buffer.data() + mac_offset + 32, payload.length());
    
    HMAC_Final(hmac_ctx, calculated_mac, &mac_len);
    HMAC_CTX_free(hmac_ctx);
    
    // 7. Write MAC into placeholder
    std::memcpy(buffer.data() + mac_offset, calculated_mac, 32);
    
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./udp_sender <message>\n";
        return 1;
    }
    
    std::string message = argv[1];
    std::string key(32, 'A'); // Hardcoded test key (matches relay default)
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(RELAY_PORT);
    inet_pton(AF_INET, RELAY_HOST, &servaddr.sin_addr);

    static uint32_t seq = 0;
    std::vector<uint8_t> packet = build_packet(seq++, message, key);
    
    sendto(sockfd, packet.data(), packet.size(), 0, (const struct sockaddr*)&servaddr, sizeof(servaddr));
    
    std::cout << "[SENT] " << message.length() << " bytes payload (Total: " << packet.size() << ")\n";
    close(sockfd);
    return 0;
}
