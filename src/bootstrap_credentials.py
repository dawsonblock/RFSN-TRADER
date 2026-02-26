# ============================================================================
# PROJECT: HEAB + SBM Financial Execution Stack v7.0
# MODULE: bootstrap_credentials.py
# PURPOSE: One-time setup to derive and safely store L2 Polymarket API keys.
# ============================================================================

import keyring
import os
import sys

try:
    from py_clob_client.client import ClobClient
    from eth_account import Account
except ImportError:
    print("ERROR: Install required packages: pip install py-clob-client eth-account")
    sys.exit(1)


def bootstrap():
    """
    One-time credential derivation using L1 EIP-712 signature.
    Stores credentials in system keyring (encrypted).
    """
    private_key = os.getenv("POLY_PRIVATE_KEY")
    if not private_key:
        print("ERROR: Set POLY_PRIVATE_KEY environment variable.")
        print("  export POLY_PRIVATE_KEY=0x...")
        sys.exit(1)

    try:
        account = Account.from_key(private_key)
        print(f"[OK] Bootstrapping L2 Credentials for Wallet: {account.address}")

        client = ClobClient(
            "https://clob.polymarket.com",
            key=private_key,
            chain_id=137
        )

        # L1 EIP-712 signs credential request — done ONCE
        creds = client.create_or_derive_api_key()

        # Persist to system keyring (encrypted, per-user)
        keyring.set_password("polymarket", "api_key", creds.api_key)
        keyring.set_password("polymarket", "secret", creds.secret)
        keyring.set_password("polymarket", "passphrase", creds.passphrase)

        print(f"[OK] L2 Auth Stored to system keyring")
        print(f"  API Key: {creds.api_key[:8]}...")
        print(f"\nNext steps:")
        print(f"  1. Deploy market_daemon to Saskatoon environment")
        print(f"  2. Deploy udp_tls_relay to AWS with: export RELAY_PSK_HEX=...")
        print(f"  3. Run omni_router_v7.py to place test orders")

    except Exception as e:
        print(f"[FATAL] Credential derivation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    bootstrap()
