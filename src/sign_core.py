from eth_hash.auto import keccak
from eth_utils import to_bytes
from coincurve import PrivateKey, PublicKey

# ---------- fixed-width helpers ----------

def u256(x: int) -> bytes:
    return x.to_bytes(32, "big")

def addr(a: str) -> bytes:
    # hex string "0x..." -> 20 bytes left-padded to 32 (EIP-712 standard for address type handling in struct hash)
    # Note: EIP-712 `address` type is 160-bit. In `encodedData`, it's padded to 32 bytes.
    raw = bytes.fromhex(a[2:])
    return b"\x00" * 12 + raw

def b32(x: bytes) -> bytes:
    assert len(x) == 32
    return x

# ---------- EIP-712 core ----------

EIP191_PREFIX = b"\x19\x01"

def eip712_digest(domain_separator: bytes, struct_hash: bytes) -> bytes:
    assert len(domain_separator) == 32
    assert len(struct_hash) == 32
    return keccak(EIP191_PREFIX + domain_separator + struct_hash)

# ---------- deterministic secp256k1 ----------

def sign_digest(privkey_32: bytes, digest_32: bytes):
    assert len(privkey_32) == 32
    assert len(digest_32) == 32

    pk = PrivateKey(privkey_32)

    # 65-byte recoverable signature (r||s||v)
    # coincurve uses libsecp256k1 RFC6979 deterministic nonce generation
    sig65 = pk.sign_recoverable(digest_32, hasher=None)

    r = sig65[:32]
    s = sig65[32:64]
    v = sig65[64]  # recovery id (0 or 1) + 27 usually, but here raw

    return r, s, v

def verify_digest(pubkey_bytes: bytes, digest_32: bytes, r: bytes, s: bytes, v: int) -> bool:
    assert len(digest_32) == 32
    sig65 = r + s + bytes([v])
    pub = PublicKey(pubkey_bytes)
    try:
        # verify returns boolean or raises
        # coincurve verify expects (signature, message, hasher)
        # signature can be 64 bytes (compact) or inclusive of recovery byte if supported
        # standard verify for public key doesn't always take recovery byte.
        # Let's use recovering the public key from signature which is more robust for "verification" of signer.
        
        recovered_pub = PublicKey.from_signature_and_message(sig65, digest_32, hasher=None)
        return recovered_pub.format(compressed=False) == pubkey_bytes
    except Exception as e:
        return False
