#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define DTLS_PORT 13370
#define PSK_IDENTITY "client1"
// 32 bytes of 'A' (0x41)
#define PSK_KEY "4141414141414141414141414141414141414141414141414141414141414141"
#define UPSTREAM_HOST "clob.polymarket.com"
#define UPSTREAM_PORT "443"

// Helper to convert hex string to binary
int hex_to_bin(const char* hex, unsigned char* bin, int bin_len) {
    int len = strlen(hex);
    if (len % 2 != 0 || len / 2 > bin_len) return -1;
    for (int i = 0; i < len / 2; i++) {
        sscanf(hex + 2*i, "%2hhx", &bin[i]);
    }
    return len / 2;
}

// PSK Callback for OpenSSL
unsigned int psk_server_callback(SSL *ssl, const char *identity,
                                 unsigned char *psk, unsigned int max_psk_len) {
    if (strcmp(identity, PSK_IDENTITY) != 0) {
        std::cerr << "[-] Unknown PSK identity: " << identity << std::endl;
        return 0;
    }
    
    // Convert hex key to binary
    int psk_len = hex_to_bin(PSK_KEY, psk, max_psk_len);
    if (psk_len < 0) {
        std::cerr << "[-] Error parsing PSK key" << std::endl;
        return 0;
    }
    
    std::cout << "[+] Accepted PSK identity: " << identity << std::endl;
    return psk_len;
}

// Cookie generation for DTLS (for DoS protection)
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    /* Initialize a random secret if not already done */
    static unsigned char cookie_secret[16];
    static int initialized = 0;
    if (!initialized) {
        if (!RAND_bytes(cookie_secret, 16)) {
             return 0;
        }
        initialized = 1;
    }

    /* Read peer information */
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    /* Create buffer with peer info + secret */
    length = 0;
    switch (peer.ss.ss_family) {
    case AF_INET:
        length += sizeof(struct in_addr);
        length += sizeof(peer.s4.sin_port);
        break;
    case AF_INET6:
        length += sizeof(struct in6_addr);
        length += sizeof(peer.s6.sin6_port);
        break;
    default:
        OPENSSL_assert(0);
        break;
    }
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL) {
        return 0;
    }

    switch (peer.ss.ss_family) {
    case AF_INET:
        memcpy(buffer, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
        memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(buffer, &peer.s6.sin6_port, sizeof(peer.s6.sin6_port));
        memcpy(buffer + sizeof(peer.s6.sin6_port), &peer.s6.sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        OPENSSL_assert(0);
        break;
    }

    /* Calculate HMAC of buffer using the secret */
    HMAC(EVP_sha1(), (const void*) cookie_secret, 16,
         (const unsigned char*) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in6 s6;
        struct sockaddr_in s4;
    } peer;

    // Use same secret logic, this assumes single process/thread for simplicity
    static unsigned char cookie_secret[16]; // Should be same as generate
    // In a real app, manage this secret properly. For now we assume generate is called first locally.
    // Actually, we can reuse the generate function logic or make the secret global.
    // For simplicity, let's just accept the cookie if it matches what we would generate now.
    
    unsigned char my_cookie[EVP_MAX_MD_SIZE];
    unsigned int my_cookie_len;
    
    if (generate_cookie(ssl, my_cookie, &my_cookie_len) == 0) return 0;
    
    if (cookie_len == my_cookie_len && memcmp(cookie, my_cookie, my_cookie_len) == 0) {
        return 1;
    }
    return 0;
}

int create_upstream_connection(SSL_CTX *ctx, SSL **ssl_out, int *fd_out) {
    struct addrinfo hints = {}, *addrs;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(UPSTREAM_HOST, UPSTREAM_PORT, &hints, &addrs) != 0) {
        return -1;
    }

    int fd = -1;
    struct addrinfo *p;
    for (p = addrs; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1) continue;

        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(addrs);

    if (fd == -1) return -1;

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, UPSTREAM_HOST);

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    *ssl_out = ssl;
    *fd_out = fd;
    return 0;
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // --- DTLS Server Context ---
    SSL_CTX *dtls_ctx = SSL_CTX_new(DTLS_server_method());
    if (!dtls_ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_psk_server_callback(dtls_ctx, psk_server_callback);
    SSL_CTX_set_cookie_generate_cb(dtls_ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(dtls_ctx, verify_cookie);
    SSL_CTX_set_options(dtls_ctx, SSL_OP_COOKIE_EXCHANGE);

    // --- TLS Client Context (Upstream) ---
    SSL_CTX *tls_ctx = SSL_CTX_new(TLS_client_method());
    if (!tls_ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // --- UDP Socket setup ---
    int udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        perror("socket");
        return 1;
    }

    // Dual stack (IPv4 mapped) or just IPv6 depending on OS default. 
    // Usually setting IPV6_V6ONLY to 0 enables dual stack.
    int no = 0;
    setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
    
    // Reuse addr/port
    int on = 1;
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));

    struct sockaddr_in6 server_addr = {};
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any; // Listen on all interfaces
    server_addr.sin6_port = htons(DTLS_PORT);

    if (bind(udp_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    std::cout << "[*] UDP DTLS Relay listening on port " << DTLS_PORT << std::endl;

    // --- Main Loop: Handle ONE client logic for simplicity ---
    while (true) {
        BIO_ADDR *client_addr = BIO_ADDR_new();
        SSL *dtls_ssl = SSL_new(dtls_ctx);
        
        BIO *bio = BIO_new_dgram(udp_fd, BIO_NOCLOSE);
        SSL_set_bio(dtls_ssl, bio, bio);

        std::cout << "[*] Waiting for DTLS ClientHello..." << std::endl;
        
        // Loop DTLSv1_listen to handle cookie exchange
        while (DTLSv1_listen(dtls_ssl, client_addr) <= 0) {
            // Handle errors or just continue listening
        }

        std::cout << "[+] ClientHello verified. Starting handshake." << std::endl;
        
        // Retrieve peer info to connect for the session
        // We will fork to handle the session
        pid_t pid = fork();
        
        if (pid == 0) {
            // Child process
            close(udp_fd); // Close listener copy since we don't need it
            
            // Create a new socket for the connection
            int conn_fd = socket(AF_INET6, SOCK_DGRAM, 0);
            
            // Allow address reuse to bind to the SAME port if possible, 
            // but we can't have two sockets bound to same port/addr without SO_REUSEPORT 
            // and we rely on the kernel to route based on connected peer?
            // Actually, best practice for DTLS behind NAT is to reply from the same port.
            // If we use 'connect' on the original fd, we perform "connected UDP", 
            // but that stops us from listening for new clients on that fd easily without 
            // re-creating the listener.
            //
            // Minimalist approach usually used for simple relays:
            // 1. Peek at packet. If ClientHello, do cookie exchange.
            // 2. Once verified, 'connect' the main UDP socket to the client.
            // 3. Process session.
            // 4. Close/Reset socket for next client.
            //
            // But we want a "Relay", implying concurrency or at least persistent session.
            // Let's settle for: Respond from a new ephemeral port. 
            // Most DTLS clients (like browser WebRTC or OpenSSL client with suitable flags) 
            // handle the server changing ports or we can try to bind to the same port with SO_REUSEPORT.
            
            int on = 1;
            setsockopt(conn_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
            setsockopt(conn_fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
            
            // Bind to the listening interface/port
            bind(conn_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            
            // Connect to the client to filter traffic
            // We need to convert BIO_ADDR to sockaddr
            struct sockaddr_storage ss;
            socklen_t sslen = sizeof(ss);
            // OpenSSL 1.1+ BIO_ADDR is opaque, need helper or extract
            // But we can just use the address from the previous receive if we had it,
            // or trust BIO_ADDR.
            // Let's assume we can get it.
            // Actually, simpler: just use the new fd in a new BIO.
            
             // For minimalist purposes, let's just try to 'connect' 
             // using the BIO_ADDR information.
             // Converting BIO_ADDR to sockaddr:
             BIO_ADDR_rawaddress(client_addr, NULL, NULL); // ... getting complex.
             
             // Let's just use the `dtls_ssl` as is? 
             // No, because `dtls_ssl` is tied to `udp_fd` (listener). 
             // Attempting `SSL_accept` on `udp_fd` would work but would block 
             // the listener from other clients if we don't fork+handle properly.
             
             // If we fork, the child has `udp_fd`. 
             // If we use it directly, we steal the listener port. 
             // This is fine for the session if we don't care about new clients 
             // during the handshake?
             // But we want the parent to keep listening.
             
             // Let's use a new socket `conn_fd` and binding it to same port with SO_REUSEPORT.
             // Then `connect` it to the client address.
             // Then the kernel *should* deliver packets from that client to `conn_fd` 
             // because it's more specific (connected) than the listener (unconnected).
             
             // We need the client address in `sockaddr` format.
             // BIO_ADDR contains it.
             const struct sockaddr *caddr = BIO_ADDR_sockaddr(client_addr);
             connect(conn_fd, caddr, sizeof(struct sockaddr_in6)); 

            // Set the new fd to the SSL object
            BIO *new_bio = BIO_new_dgram(conn_fd, BIO_CLOSE);
            SSL_set_bio(dtls_ssl, new_bio, new_bio);
             
            // Finish handshake
            if (SSL_accept(dtls_ssl) <= 0) {
                 ERR_print_errors_fp(stderr);
                 exit(1);
            }

            
            std::cout << "[+] DTLS Handshake complete. PSK Identity: " << PSK_IDENTITY << std::endl;
            
            // Connect Upstream
            SSL *upstream_ssl = NULL;
            int upstream_fd = -1;
            if (create_upstream_connection(tls_ctx, &upstream_ssl, &upstream_fd) != 0) {
                std::cerr << "[-] Failed to connect to upstream." << std::endl;
                exit(1);
            }
            std::cout << "[+] Connected to upstream: " << UPSTREAM_HOST << std::endl;
            
            // Relay Loop
            fd_set read_fds;
            char buf[4096];
            
            while (true) {
                FD_ZERO(&read_fds);
                FD_SET(conn_fd, &read_fds);
                FD_SET(upstream_fd, &read_fds);
                
                int max_fd = (conn_fd > upstream_fd) ? conn_fd : upstream_fd;
                
                if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) break;
                
                // From DTLS Client -> Upstream
                if (FD_ISSET(conn_fd, &read_fds)) {
                    int len = SSL_read(dtls_ssl, buf, sizeof(buf));
                    if (len <= 0) break; // Error or close
                    
                    // Write to Upstream TLS
                    if (SSL_write(upstream_ssl, buf, len) <= 0) break;
                }
                
                // From Upstream -> DTLS Client
                if (FD_ISSET(upstream_fd, &read_fds)) {
                    int len = SSL_read(upstream_ssl, buf, sizeof(buf));
                    if (len <= 0) break;
                    
                    // Write back to DTLS
                    if (SSL_write(dtls_ssl, buf, len) <= 0) break;
                }
            }
            
            // Cleanup Child
            SSL_free(dtls_ssl);
            SSL_free(upstream_ssl);
            close(upstream_fd); // conn_fd closed by BIO_CLOSE
            SSL_CTX_free(dtls_ctx);
            SSL_CTX_free(tls_ctx);
            std::cout << "[*] Connection closed." << std::endl;
            exit(0);

        } else if (pid > 0) {
            // Parent
            SSL_free(dtls_ssl); // Free the SSL structure we handed off (child has its copy?)
            // Actually, we need to be careful with SSL_free in parent if we just forked.
            // The structure is copied memory-wise but not logically ref-counted across processes nicely.
            // Reference: 'fork' copies address space. Child has copy of 'dtls_ssl'.
            // Parent can safely free its pointer to 'dtls_ssl' as it's not using it,
            // assuming internal ref counts (if any) are not shared memory.
            // Standard fork usage: parent closes descriptors/frees structures it doesn't need.
            
            // BIO note: The BIO in parent was attached to udp_fd. We must NOT close udp_fd in BIO_free
            // because we need it for the next listen.
            // But we set BIO_NOCLOSE earlier: BIO_new_dgram(udp_fd, BIO_NOCLOSE);
            // So SSL_free(dtls_ssl) will free the BIO memory but NOT close the socket. Correct.
            continue;
        } else {
            perror("fork");
        }
    }

    close(udp_fd);
    SSL_CTX_free(dtls_ctx);
    SSL_CTX_free(tls_ctx);
    return 0;
}
