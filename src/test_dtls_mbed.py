import socket
import struct
import sys
import contextlib

try:
    from mbedtls import tls
    from mbedtls.pk import RSA, ECC
    from mbedtls import exceptions
except ImportError:
    print("[ERROR] 'python-mbedtls' required. Run: pip install python-mbedtls")
    sys.exit(1)

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 13370
PSK_ID = "client1"
PSK_KEY = b'A' * 32

def main():
    print(f"[DTLS] Connecting to {RELAY_HOST}:{RELAY_PORT} via mbedTLS...")

    conf = tls.DTLSConfiguration(
        pre_shared_key=(PSK_ID, PSK_KEY),
        validate_certificates=False
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((RELAY_HOST, RELAY_PORT))

    try:
        # Client Context
        ctx = tls.ClientContext(conf)
        
        # Wrap Socket
        # mbedtls wrapper for DTLS
        # Note: python-mbedtls might handle blocking differently.
        with ctx.wrap_socket(sock, server_hostname=None) as dtls_sock:
            # Handshake
            dtls_sock.do_handshake()
            print("[DTLS] Handshake OK")

            # Send Payload
            req = b"GET /time HTTP/1.1\r\nHost: clob.polymarket.com\r\nConnection: close\r\n\r\n"
            dtls_sock.sendall(req)
            print(f"[SENT] {len(req)} bytes")

            # Receive
            data = dtls_sock.recv(4096)
            if data:
                print(f"[RECV] {len(data)} bytes:\n{data.decode('utf-8', errors='ignore')}")
            
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
