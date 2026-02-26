from eth_hash.auto import keccak
from coincurve import PrivateKey
from sign_core import eip712_digest, sign_digest, verify_digest

# --- deterministic test vectors ---

# fixed private key (DO NOT USE IN PRODUCTION)
priv = bytes.fromhex("1" * 64)

pk = PrivateKey(priv)
pub = pk.public_key.format(compressed=False)

# fake domain + struct hash (replace later with real EIP712)
domain = keccak(b"domain:test:v1")
struct = keccak(b"order:test")

digest = eip712_digest(domain, struct)

r, s, v = sign_digest(priv, digest)

ok = verify_digest(pub, digest, r, s, v)

print("digest:", digest.hex())
print("r:", r.hex())
print("s:", s.hex())
print("v:", v)
print("verify:", ok)

assert ok, "Signature verification failed"
