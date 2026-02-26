# HEAB + SBM Financial Execution Stack v7.0

![License](https://img.shields.io/badge/license-Private-red.svg)
![Status](https://img.shields.io/badge/status-Production-green.svg)
![Latency](https://img.shields.io/badge/latency-%3C10%C2%B5s-blue.svg)

**A hybrid High-Frequency Trading (HFT) execution stack designed for the Polymarket CLOB.**

This system implements a split-topology architecture to overcome geographic latency challenges (e.g., "Saskatoon" vs "AWS us-east-1"). It combines a local C++ market data engine, a PyTorch-based strategy router with FPGA offload bridging, and a secure UDP-to-TLS relay for optimized order injection.

---

## 🏗 Architecture

The stack consists of three specialized components working in tandem:

### 1. The Brain: `omni_router_v7.py`
Runs the trading strategy using CUDA-accelerated PyTorch models.
- **FPGA Bridge:** Pre-calculates full HTTP/TCP packets and offloads the final signing (`r`, `s`) and transmission to hardware (simulated via software bridge).
- **L2 Authentication:** Injects HMAC-SHA256 headers for Polymarket Layer 2 execution.

### 2. The Engine: `market_daemon`
A C++20 service running on the strategy server.
- **Lock-Free Ring Buffer:** Uses atomic `std::memory_order_release/acquire` semantics to process market ticks without mutex contention.
- **Zero-Copy Persistence:** Maps nonce state to disk (`nonce.bin`) via `mmap` for instant crash recovery.
- **CPU Affinity:** Pins threads to isolated cores for cache locality.

### 3. The Tunnel: `udp_tls_relay`
A lightweight C++ proxy deployed to AWS us-east-1 (close to the exchange).
- **Protocol Switching:** Accepts low-latency UDP packets from the strategy server and forwards them over a persistent, pre-warmed TLS (TCP) connection to Polymarket.
- **Security:** Implements a custom HMAC-SHA256 protocol with 5-second replay window protection to prevent unauthorized injection.

---

## 🚀 Key Features

- **EIP-712 Compliant:** Custom verified Keccak-256 implementation (FIPS 202) for correct structured data hashing.
- **Cross-Platform:** Optimized for Linux (x86_64 Production) with compatibility layers for macOS (ARM64 Development).
- **Resanitized Security:**
  - Async-signal-safe shutdown handling.
  - Constant-time crypto comparisons to prevent timing attacks.
  - POSIX-compliant file allocation for reliability.

---

## � Technical Deep Dive

### 1. Custom UDP Protocol
The relay uses a proprietary 44-byte header for authentication and replay protection.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4B | `sequence` | Rolling packet ID (currently unused/padding) |
| 4 | 8B | `timestamp` | Nanosecond timestamp since epoch (RDTSC-derived) |
| 12 | 32B | `HMAC` | SHA-256 HMAC of [header + payload] using PSK |
| 44 | N | `payload` | Raw HTTP request (including L2 headers) |

**Security mechanism:** The relay calculates `H(received_payload)` and compares it against the header HMAC using `CRYPTO_memcmp` (constant-time) to prevent timing side channels. Packets older than 5 seconds are dropped.

### 2. Lock-Free Ring Buffer
`market_daemon` uses a single-producer/multi-consumer (SPMC) ring buffer mapped to shared memory.

- **Size:** 512 slots (fits in L2 cache).
- **Structure:** `NormalizedTick` (64 bytes, cache-line aligned).
- **Synchronization:** `std::atomic<uint32_t>` head/tail pointers with `release`/`acquire` semantics. No mutexes or condition variables are used in the hot path.

### 3. FPGA Offload Emulation
`omni_router_v7.py` prepares the full TCP frame in userspace to minimize latency.
1. **Pre-computation:** Formatting JSON, HTTP headers, and L2 HMAC authentication.
2. **Placeholder Injection:** The `r` and `s` signature fields (64 hex chars each) are zeroed out.
3. **Offset Calculation:** The byte offsets of `r` and `s` are passed to the hardware bridge.
4. **Trigger:** In production, the FPGA computes the ECDSA signature directly into the packet buffer and triggers the PCIe transmit.

---

## �🛠 Prerequisites

- **C++ Compiler:** `g++` (GCC 10+) or `clang` (LLVM 12+) supporting C++20.
- **Python:** 3.8+
- **Libraries:**
  - OpenSSL (`libssl-dev`, `libcrypto`)
  - Python: `torch`, `web3`, `eth-hash`, `py-clob-client`
- **Hardware (Optional):** NVIDIA GPU for CUDA inference, FPGA for TCP offloading.

---

## ⚙️ Advanced Performance Tuning

### CPU Isolation (Isolcpus)
For maximum throughput, isolate cores 1-3 from the kernel scheduler to dedicating them to the trading strategy and relay. Add `isolcpus=1-3` to your kernel cmdline.

### HugePages Support
Enable 2MB HugePages for the shared ring buffer to reduce TLB misses.
```bash
echo 2048 > /proc/sys/vm/nr_hugepages
```
The daemon will automatically use `SHM_HUGETLB` if available.

---

## 📦 Build & Installation

The project uses a unified `Makefile` that handles architecture detection automatically.

```bash
# Clean previous builds
make clean

# Compile Daemon and Relay
make all
```

Artifacts will be generated in `bin/`:
- `bin/market_daemon`
- `bin/udp_tls_relay`

---

## ⚡ Deployment Guide

### Phase 1: AWS Relay (us-east-1)
Deploy `udp_tls_relay` to a server physically near the exchange.

1. Generate a secure Pre-Shared Key (PSK):
   ```bash
   openssl rand -hex 32
   # Example output: a1b2c3d4... (Save this!)
   ```

2. Run the relay:
   ```bash
   export RELAY_PSK_HEX="your_generated_hex_key"
   ./bin/udp_tls_relay
   ```

### Phase 2: Strategy Server (Saskatoon)
Deploy the core logic on your primary server.

1. **Start the Data Engine:**
   ```bash
   ./bin/market_daemon &
   ```

2. **Bootstrap Credentials (One-time):**
   Derive your L2 API keys from your L1 private key (saved to secure system keyring).
   ```bash
   export POLY_PRIVATE_KEY="0xYOUR_L1_PRIVATE_KEY"
   python3 src/bootstrap_credentials.py
   ```

3. **Run the Strategy:**
   Ensure the `RELAY_PSK_HEX` matches the one on AWS.
   ```bash
   export RELAY_PSK_HEX="your_generated_hex_key"
   python3 src/omni_router_v7.py
   ```

---

## 🛡 Security Notes

- **Network Security:** The UDP relay accepts packets from *any* IP but discards any packet that fails the HMAC signature check or falls outside the 5-second timestamp window.
- **Memory Safety:** The C++ daemon enforces strict memory ordering constraints. `nonce.bin` is synchronized to disk on shutdown using `MS_SYNC`.

---

## ❓ Troubleshooting

| Issue | Typical Cause | Solution |
|-------|---------------|----------|
| `HMAC-REJECT` | PSK mismatch or timestamp drift | Ensure `RELAY_PSK_HEX` matches on both nodes; check NTP sync. |
| `REPLAY-REJECT` | Clock skew > 5s | Sync clocks with `chronyd -q` |
| `posix_fallocate: EFBIG` | Disk full or limits exceeded | `df -h`; check `ulimit -f` |
| `shmget: EEXIST` | Stale shared memory | `ipcrm -a` to clear old segments. |
| `OpenSSL headers unavail` | Missing deps | `apt install libssl-dev` or `brew install openssl` |

---

## 📜 License

Copyright © 2026 HEAB Financial. All Rights Reserved.
private/Proprietary Source Code.
