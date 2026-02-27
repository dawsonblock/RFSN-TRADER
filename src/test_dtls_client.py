import socket
import sys
import time
from dtls import do_patch
from dtls.sslconnection import SSLConnection
from dtls.err import SSLError

# This patch enables DTLS support in the python socket module if the 'dtls' package is installed.
do_patch()

# Configuration
DTLS_HOST = "127.0.0.1"
DTLS_PORT = 13370
PSK_IDENTITY = "client1"
PSK_KEY = b'\x41' * 32 

def psk_callback(identity_hint):
    '''
    Callback to provide the PSK key and identity.
    Returns (identity, key) tuple.
    '''
    print(f"Server requested PSK. Hint: {identity_hint}")
    # Identity (bytes), Key (bytes)
    return PSK_IDENTITY.encode('utf-8'), PSK_KEY

def main():
    print(f"Connecting to DTLS Relay at {DTLS_HOST}:{DTLS_PORT}...")

    # Create a UDP socket (DTLS uses UDP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((DTLS_HOST, DTLS_PORT))

    # Wrap the socket with DTLS
    try:
        sc = SSLConnection(
            sock, 
            keyfile=None, 
            certfile=None, 
            server_side=False, 
            ca_certs=None,
            do_handshake_on_connect=False,
            psk_cb=psk_callback,
            # Force a PSK cipher suite if possible or rely on auto-negotiation
            ciphers="PSK-AES128-CBC-SHA" 
        )
    except Exception as e:
        print(f"Failed to create SSLConnection: {e}")
        return

    try:
        print("Starting Handshake...")
        try:
            sc.connect()
        except SSLError as e:
            print(f"DTLS Handshake Failed: {e}")
            return

        print("DTLS Handshake successful!")
        print(f"Cipher: {sc.get_cipher_name()}")
        
        request = (
            "GET /time HTTP/1.1\r\n"
            "Host: clob.polymarket.com\r\n"
            "User-Agent: DTLS-Test-Client/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        
        print(f"Sending Payload ({len(request)} bytes)...")
        sc.write(request.encode('utf-8'))
        
        print("Reading Response...")
        
        sock.settimeout(5.0)
        
        while True:
            try:
                data = sc.read(4096)
                if not data:
                    break
                print(f"\n--- Response Chunk ({len(data)} bytes) ---")
                print(data.decode('utf-8', errors='replace'))
            except socket.timeout:
                print("\nRead timeout.")
                break
            except Exception as e:
                print(f"\nRead error/Closed: {e}")
                break
                
    except Exception as e:
        print(f"Connection error: {e}")
    
    finally:
        print("\nClosing connection.")
        try:
            sc.shutdown()
        except:
            pass
        sock.close()

if __name__ == "__main__":
    main()
