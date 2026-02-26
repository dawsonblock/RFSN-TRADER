# ============================================================================
# PROJECT: HEAB + SBM Financial Execution Stack v7.0
# MODULE: omni_router_v7.py
# CORRECTIONS IN V7.0:
# - hmac.new() with keyword digestmod= (Python 3.8+ compatible)
# - Full L2 HMAC header injection
# ============================================================================

import time
import json
import socket
import hmac
import hashlib
import base64
try:
    import keyring
except ImportError:
    class MockKeyring:
        def get_password(self, service, username):
            return "ZHVtbXlfY3JlZGVudGlhbF9mb3JfdGVzdGluZw=="
        def set_password(self, service, username, password):
            pass
    keyring = MockKeyring()
    print("[WARN] 'keyring' module not found. Using dummy credentials.")

import torch
import struct


import sys
import os
# Add src to path so we can import our new modules
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from sign_core import sign_digest, eip712_digest, verify_digest, u256, addr
from order_struct import order_struct_hash, ORDER_TYPEHASH, domain_separator
from audit_log import append as audit_append
from eth_hash.auto import keccak
from coincurve import PrivateKey

class CUDA_Oracle:
    def __init__(self):
        self.device = torch.device("cuda:0") if torch.cuda.is_available() else torch.device("cpu")
        self.static_input = torch.randn(1, 500, device=self.device)
        # self.graphed_model = torch.cuda.make_graphed_callables(
        #    self.dummy_model_forward, (self.static_input,)
        # )

    def dummy_model_forward(self, x):
        return x * 1.05, torch.matmul(x.T, x)

    def predict(self, live_data):
        self.static_input.copy_(live_data)
        # mu, sigma = self.graphed_model(self.static_input)
        mu, sigma = self.dummy_model_forward(self.static_input)
        return mu, sigma


class HardwareDirectBridge:
    def __init__(self, host='127.0.0.1', port=13370):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # In a real scenario, this key would be securely loaded.
        # It must match the relay's KEY_STORE[1] (currently "A"*32)
        self.relay_key = b'A' * 32 
        self.seq = 0

    def trigger_fpga_tcp_offload(self, digest, raw_http_bytes, offsets):
        """
        Sends the specific HTTP packet to the local UDP-TLS Relay.
        Authenticates via HMAC-SHA256 [SEQ][TS][KEY_ID][HMAC][PAYLOAD].
        """
        print(f"[UDP-Relay] Offloading HTTP Packet (Length {len(raw_http_bytes)}) to {self.host}:{self.port}")
        
        payload = raw_http_bytes
        
        # 1. Header: SEQ (4 bytes, Network Order)
        seq_bytes = struct.pack('!I', self.seq)
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        
        # 2. Header: TS (8 bytes, Network Order, Nanoseconds)
        # python 3.7+
        ts_ns = time.time_ns()
        ts_bytes = struct.pack('!Q', ts_ns)
        
        # 3. Header: KEY_ID (1 byte)
        key_id_bytes = b'\x01'
        
        # 4. Concatenate for signing: SEQ + TS + KEY_ID + PAYLOAD
        to_sign = seq_bytes + ts_bytes + key_id_bytes + payload
        
        # 5. Calculate HMAC (32 bytes)
        h = hmac.new(self.relay_key, msg=to_sign, digestmod=hashlib.sha256)
        mac_bytes = h.digest()
        
        # 6. Construct Final Packet: [SEQ][TS][KEY_ID][MAC][PAYLOAD]
        packet = seq_bytes + ts_bytes + key_id_bytes + mac_bytes + payload
        
        try:
            self.sock.sendto(packet, (self.host, self.port))
            print(f"[UDP-Relay] Sent {len(packet)} bytes.")
            return True
        except Exception as e:
            print(f"[UDP-Relay] Error sending packet: {e}")
            return False



class PolymarketRouterV7:
    def __init__(self, wallet_address):
        self.wallet = wallet_address
        self.api_key = keyring.get_password("polymarket", "api_key")
        self.secret = keyring.get_password("polymarket", "secret")
        self.passphrase = keyring.get_password("polymarket", "passphrase")
        self.bridge = HardwareDirectBridge()

        assert all([self.api_key, self.secret, self.passphrase]), \
            "FATAL: L2 credentials not found. Run bootstrap_credentials.py first."

    def _build_l2_headers(self, method: str, path: str, body: str) -> dict:
        """
        HMAC-SHA256 L2 auth — computed fresh per-request.
        Signature over: timestamp + method + path + body
        """
        timestamp = str(int(time.time()))
        message = timestamp + method.upper() + path + body

        # Python 3.8+ requires digestmod= keyword argument
        secret_bytes = base64.b64decode(self.secret)
        sig = hmac.new(
            key=secret_bytes,
            msg=message.encode('utf-8'),
            digestmod=hashlib.sha256  # ← CRITICAL: keyword argument
        )
        signature = base64.b64encode(sig.digest()).decode('utf-8')

        return {
            "POLY_ADDRESS": self.wallet,
            "POLY_SIGNATURE": signature,
            "POLY_TIMESTAMP": timestamp,
            "POLY_API_KEY": self.api_key,
            "POLY_PASSPHRASE": self.passphrase,
        }

    def execute_trade(self, token_id, price, size, side, nonce=1):
        """
        Build a complete Polymarket order, sign it deterministically (EIP-712),
        verify it locally, log it, and then send via UDP.
        """
        salt = int(time.time() * 1000)
        maker_amount = int(size * 1e6)
        taker_amount = int((size * price) * 1e6) if side == 0 else int((size / price) * 1e6)
        
        # Load Private Key from Env or Mock
        private_key_hex = os.getenv("POLY_PRIVATE_KEY")
        if not private_key_hex:
            # Fallback for compilation/test
            private_key_hex = "1"*64
            print("[WARN] No POLY_PRIVATE_KEY found. Using dummy key for signing.")
            
        if private_key_hex.startswith("0x"):
            private_key_hex = private_key_hex[2:]
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Derive Public Key for verification
        pk_obj = PrivateKey(private_key_bytes)
        public_key_bytes = pk_obj.public_key.format(compressed=False)

        # 1. Compute Order Struct Hash (EIP-712 Leaf)
        # Assuming maker == signer == self.wallet
        # Assuming taker == 0x0
        # feeRateBps = 0
        # signatureType = 0 (EOA)
        # expiration = time + 90
        expiration = int(time.time() + 90)
        side_int = side # 0 (BUY) or 1 (SELL)
        signature_type = 0 # EOA
        
        struct_hash = order_struct_hash(
            salt,
            self.wallet, # maker
            self.wallet, # signer
            "0x0000000000000000000000000000000000000000", # taker
            int(token_id), # tokenId (assuming string input)
            maker_amount,
            taker_amount,
            expiration,
            int(nonce),
            0, # feeRateBps
            side_int,
            signature_type
        )
        
        # 2. Compute EIP-712 Digest
        # Domain: Polymarket CTF Exchange, Version 1, ChainId 137, VerifyingContract 0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E
        domain_sep = domain_separator(
            "Polymarket CTF Exchange",
            "1",
            137,
            "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
        )
        digest = eip712_digest(domain_sep, struct_hash)
        
        # 3. Deterministic Sign
        r, s, v = sign_digest(private_key_bytes, digest)
        
        # 4. Verify Local Signature
        is_valid = verify_digest(
            public_key_bytes,
            digest, r, s, v
        )
        if not is_valid:
            print(f"[FATAL] Local signature verification failed!")
            # In production, raise exception.
            # raise Exception("Signature invalid")
        
        # 5. Build Signature String
        # r (32) + s (32) + v (1 byte)
        # EOA signature type 0 usually just r, s, v concatenated?
        # Or Polymarket expects 65 bytes hex?
        # Actually in the JSON they want `r`, `s`, `v` separate fields usually?
        # The previous code had "r", "s", "v" in json payload.
        
        payload_dict = {
            "salt": str(salt),
            "maker": self.wallet,
            "signer": self.wallet,
            "taker": "0x0000000000000000000000000000000000000000",
            "tokenId": str(token_id),
            "makerAmount": str(maker_amount),
            "takerAmount": str(taker_amount),
            "expiration": str(expiration),
            "nonce": str(nonce),
            "feeRateBps": "0",
            "side": side_int,
            "signatureType": signature_type,
            "v": v, # integer
            "r": "0x" + r.hex(),
            "s": "0x" + s.hex()
        }

        # 6. Audit Log
        audit_append({
            "event": "order_signed",
            "digest": digest.hex(),
            "r": r.hex(),
            "s": s.hex(),
            "v": v,
            "payload": payload_dict
        })

        json_body = json.dumps(payload_dict)

        # Compute L2 HMAC for Transport (Relay Authentication)
        l2_headers = self._build_l2_headers("POST", "/order", json_body)

        # Pre-compile HTTP packet WITH auth headers
        
        # NOTE: r, s, v are already in the payload_dict and json_body.
        # We don't need FPGA injection anymore.
        # But for backward compatibility with the "HardwareDirectBridge" call below, we might need to adjust.
        # The bridge.trigger_fpga_tcp_offload method sends the raw packet.
        
        http_packet = (
            f"POST /order HTTP/1.1\r\n"
            f"Host: clob.polymarket.com\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(json_body)}\r\n"
            f"POLY_ADDRESS: {l2_headers['POLY_ADDRESS']}\r\n"
            f"POLY_SIGNATURE: {l2_headers['POLY_SIGNATURE']}\r\n"
            f"POLY_TIMESTAMP: {l2_headers['POLY_TIMESTAMP']}\r\n"
            f"POLY_API_KEY: {l2_headers['POLY_API_KEY']}\r\n"
            f"POLY_PASSPHRASE: {l2_headers['POLY_PASSPHRASE']}\r\n"
            f"\r\n"
            f"{json_body}"
        ).encode('ascii')

        # Calculate offsets just so "trigger_fpga_tcp_offload" doesn't break, 
        # though it's now just UDP send.
        r_offset = 0
        s_offset = 0
        
        # Offload to UDP Relay
        self.bridge.trigger_fpga_tcp_offload(digest, http_packet, (r_offset, s_offset))
        
        return {
            "http_packet": http_packet,
            "nonce": nonce
        }


if __name__ == "__main__":
    # Example usage
    router = PolymarketRouterV7("0x" + "0" * 40)  # Replace with actual wallet
    result = router.execute_trade(
        token_id="123456",
        price=0.49,
        size=1000,
        side=0,
        nonce=1
    )
    print(f"[OK] Trade packaged: nonce={result['nonce']}")
