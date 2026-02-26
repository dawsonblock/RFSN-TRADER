import sys

print("=== Python Verification for Keccak-256 ===")

try:
    from web3 import Web3
    def keccak256(data):
        return Web3.keccak(data).hex()[2:]
except ImportError:
    try:
        from eth_hash.auto import keccak
        def keccak256(data):
            return keccak(data).hex()
    except ImportError:
        try:
            from Crypto.Hash import keccak
            def keccak256(data):
                k = keccak.new(digest_bits=256)
                k.update(data)
                return k.hexdigest()
        except ImportError:
            print("[FATAL] Required libraries missing. Install one of:")
            print("  pip install web3")
            print("  pip install eth-hash[pycryptodome]")
            print("  pip install pycryptodome")
            sys.exit(1)

# Test 1: String
msg = b"Hello World"
print(f"String 'Hello World': {keccak256(msg)}")

# Test 2: uint256 (Big Endian)
# 0x1234567890ABCDEF padded to 32 bytes
val = 0x1234567890ABCDEF
encoded = val.to_bytes(32, byteorder='big')
print(f"uint256 (0x1234..EF): {keccak256(encoded)}")
