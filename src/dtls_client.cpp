#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Global context
SSL_CTX *ctx = nullptr;
SSL *ssl = nullptr;

// UDP Connection info for Callback
struct PskCreds {
    std::string identity;
    std::string key_hex;
};

unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len) {
    (void)hint;
    
    // Retrieve credentials stored in SSL object (passed via caller)
    // We can't easily pass closure data to this callback without using SSL_set_app_data or global.
    // Let's use SSL_get_app_data.
    PskCreds *creds = (PskCreds*)SSL_get_app_data(ssl);

    if (!creds) {
        fprintf(stderr, "Error: Missing PSK credentials in callback\n");
        return 0;
    }

    // Set Identity
    if (creds->identity.length() >= max_identity_len) {
        fprintf(stderr, "Error: PSK Identity too long\n");
        return 0;
    }
    strncpy(identity, creds->identity.c_str(), max_identity_len);
    identity[max_identity_len - 1] = '\0';

    // Set Key (Hex decode)
    std::string hex = creds->key_hex;
    if (hex.substr(0, 2) == "0x") hex = hex.substr(2);
    
    size_t key_len = hex.length() / 2;
    if (key_len > max_psk_len) {
        fprintf(stderr, "Error: PSK Key too long\n");
        return 0;
    }

    for (size_t i = 0; i < key_len; i++) {
        std::string byteString = hex.substr(i * 2, 2);
        psk[i] = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
    }
    
    return (unsigned int)key_len;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0] << " <host> <port> <identity> <psk_key_hex> <message>" << std::endl;
        return 1;
    }

    std::string host = argv[1];
    int port = std::stoi(argv[2]);
    std::string identity = argv[3];
    std::string key_hex = argv[4];
    std::string message = argv[5];

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create Context
    // DTLS_client_method() negotiates highest available version.
    ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 2;
    }

    // Set Cipher List - MUST Include PSK
    if (!SSL_CTX_set_cipher_list(ctx, "PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA")) {
        ERR_print_errors_fp(stderr);
        return 2;
    }

    // Set PSK Callback
    SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);

    // Create UDP Socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 3;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        return 3;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 3;
    }

    // Create BIO from socket
    BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return 3;
    }
    
    // Set Timeout for Handshake
    struct timeval timeout;
    timeout.tv_sec = 2; // 2 seconds timeout
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // Create SSL
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);
    
    // Store credentials
    PskCreds creds = {identity, key_hex};
    SSL_set_app_data(ssl, &creds);

    // Handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed. (Check if server is running and PSK matches)\n");
        ERR_print_errors_fp(stderr);
        return 4;
    }

    std::cout << "[DTLS] Handshake Complete. Cipher: " << SSL_get_cipher(ssl) << std::endl;

    // Send Message
    int len = SSL_write(ssl, message.c_str(), message.length());
    if (len <= 0) {
        fprintf(stderr, "SSL_write failed\n");
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "[DTLS] Sent " << len << " bytes: " << message << std::endl;
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    
    return 0;
}
