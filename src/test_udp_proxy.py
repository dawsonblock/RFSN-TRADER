import socket
import time

def send_test_packet():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = b"GET / HTTP/1.1\r\nHost: clob.polymarket.com\r\n\r\n"
    
    print("Sending packet to localhost:5000...")
    sock.sendto(msg, ("127.0.0.1", 5000))
    sock.close()
    print("Packet sent.")

if __name__ == "__main__":
    send_test_packet()
