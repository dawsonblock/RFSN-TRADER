from eth_hash.auto import keccak
from sign_core import u256, addr, b32, eip712_digest

# EIP-712 TypeHash for Polymarket Order
# Order(uint256 salt,address maker,address signer,address taker,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint256 expiration,uint256 nonce,uint256 feeRateBps,uint8 side,uint8 signatureType)
# Hash: 0xd6d987d69cd84c471c6046e75466d7ad908ba6e8c78c2e9de453664360e227df (calculated locally to verify)
ORDER_TYPE_STR = b"Order(uint256 salt,address maker,address signer,address taker,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint256 expiration,uint256 nonce,uint256 feeRateBps,uint8 side,uint8 signatureType)"
ORDER_TYPEHASH = keccak(ORDER_TYPE_STR)

# EIP-712 Domain TypeHash (standard per EIP-712)
DOMAIN_TYPE_STR = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
DOMAIN_TYPEHASH = keccak(DOMAIN_TYPE_STR)

def domain_separator(name: str, version: str, chain_id: int, verifying_contract: str) -> bytes:
    """
    Computes the EIP-712 Domain Separator.
    """
    return keccak(
        DOMAIN_TYPEHASH +
        keccak(name.encode('utf-8')) +
        keccak(version.encode('utf-8')) +
        u256(chain_id) +
        addr(verifying_contract)
    )

def order_struct_hash(
    salt: int,
    maker: str,
    signer: str,
    taker: str,
    token_id: int,
    maker_amount: int,
    taker_amount: int,
    expiration: int,
    nonce: int,
    fee_rate_bps: int,
    side: int,
    signature_type: int
) -> bytes:
    """
    Computes the EIP-712 structHash for a Polymarket Order.
    All scalar values are encoded to 32 bytes (u256), except side/signatureType which are uint8 (padded to 32 bytes in encodedData).
    Addresses are padded to 32 bytes.
    """
    return keccak(
        ORDER_TYPEHASH +
        u256(salt) +
        addr(maker) +
        addr(signer) +
        addr(taker) +
        u256(token_id) +
        u256(maker_amount) +
        u256(taker_amount) +
        u256(expiration) +
        u256(nonce) +
        u256(fee_rate_bps) +
        u256(side) +            # uint8 encoded as uint256 (32 bytes) in hashed struct
        u256(signature_type)    # uint8 encoded as uint256 (32 bytes) in hashed struct
    )
