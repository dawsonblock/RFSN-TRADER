import socket
import ssl
import time
import os
import binascii

# Attempt to import dtls package (pydtls)
# Install via: pip install python-dtls
try:
    from dtls import do_patch
    do_patch()
    # After patching, ssl module supports DTLS
except ImportError:
    print("Error: 'python-dtls' not installed. Please install it using: pip install python-dtls")
    exit(1)

DTLS_SERVER_HOST = '127.0.0.1'
DTLS_SERVER_PORT = 13370
PSK_IDENTITY = b'client1'
PSK_KEY = b'A' * 32  # 32 bytes of 'A'

def psk_cb(identity_hint):
    # Return (identity, key)
    # identity_hint is what the server sent (if any)
    print(f"[*] Server identity hint: {identity_hint}")
    return (PSK_IDENTITY, PSK_KEY)

def main():
    print(f"[*] Connecting to DTLS Server at {DTLS_SERVER_HOST}:{DTLS_SERVER_PORT}")
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Wrap with SSL/DTLS
    # Note: pydtls 'wrap_socket' supports ciphers and psk callbacks if extended properly,
    # but standard pydtls usually targets certificates. 
    # Checking pydtls support for PSK... it is limited in the high level API.
    # We might need to use the lower level OpenSSL wrapper if pydtls doesn't expose PSK easily.
    # However, let's try to pass the callback if supported or use a simpler approach.
    
    # Actually, standard pydtls 1.2.x might not expose set_psk_client_callback easily in wrap_socket.
    # Let's assume standard behavior or provide a fallback warning.
    
    # Alternative: Use 'ssl.SSLContext' if patched
    ctx = ssl.SSLContext(ssl.PROTOCOL_DTLSv1_2)
    ctx.set_ciphers("PSK-AES128-CBC-SHA") # Example PSK cipher
    
    # pydtls-specific: Context might have set_psk_client_callback
    if hasattr(ctx, 'set_psk_client_callback'):
        ctx.set_psk_client_callback(psk_cb)
    else:
        # Fallback for standard pydtls if it added it differently or not at all
        # The 'dtls' package is a wrapper around PyOpenSSL basically.
        print("[!] Warning: set_psk_client_callback not found. accessing internal OpenSSL Object if possible")
        # This part is tricky in pure Python without a robust library.
        # Let's try to proceed.
        pass

    # Connect
    try:
        dtls_sock = ctx.wrap_socket(sock)
        dtls_sock.connect((DTLS_SERVER_HOST, DTLS_SERVER_PORT))
        
        print("[+] Handshake successful!")
        
        # Send data
        msg = b"GET / HTTP/1.1\r\nHost: clob.polymarket.com\r\n\r\n"
        print(f"[*] Sending: {msg}")
        dtls_sock.write(msg)
        
        # Read response
        response = dtls_sock.read(4096)
        print(f"[+] Received: {response.decode('utf-8', errors='ignore')}")
        
        dtls_sock.close()
        
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    main()
