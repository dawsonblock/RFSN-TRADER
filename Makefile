# ============================================================================
# PROJECT: HEAB + SBM Financial Execution Stack v7.0
# BUILD CONFIGURATION
# ============================================================================

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS (Apple Silicon/Intel)
    OPENSSL_INCLUDE := -I/opt/homebrew/include
    OPENSSL_LIB := -L/opt/homebrew/lib
else
    # Linux (Production)
    OPENSSL_INCLUDE :=
    OPENSSL_LIB :=
endif

CXX        = g++
CXXFLAGS   = -std=c++20 -O3 -march=native -Wall -Wextra -pthread -fPIC $(OPENSSL_INCLUDE)
LDFLAGS    = $(OPENSSL_LIB) -lssl -lcrypto -pthread

DAEMON_SRC     = src/market_daemon.cpp
RELAY_SRC      = aws_proxy/udp_tls_relay.cpp
DAEMON_OBJ     = build/market_daemon.o
RELAY_OBJ      = build/udp_tls_relay.o

DAEMON_BIN     = bin/market_daemon
RELAY_BIN      = bin/udp_tls_relay

.PHONY: all daemon relay clean help

all: daemon relay

daemon: $(DAEMON_BIN)

relay: $(RELAY_BIN)

$(DAEMON_BIN): $(DAEMON_OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[BUILD] ✓ market_daemon compiled"

$(RELAY_BIN): $(RELAY_OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "[BUILD] ✓ udp_tls_relay compiled"

$(DAEMON_OBJ): $(DAEMON_SRC)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(RELAY_OBJ): $(RELAY_SRC)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf build bin
	rm -f nonce.bin
	@echo "[CLEAN] ✓ Artifacts removed"

help:
	@echo "HEAB + SBM Financial Execution Stack v7.0"
	@echo ""
	@echo "Targets:"
	@echo "  make daemon    — Build market_daemon (Saskatoon)"
	@echo "  make relay     — Build udp_tls_relay (AWS)"
	@echo "  make all       — Build both"
	@echo "  make clean     — Remove build artifacts"
	@echo ""
	@echo "Deployment:"
	@echo "  Saskatoon: ./bin/market_daemon"
	@echo "  AWS:       export RELAY_PSK_HEX=... && ./bin/udp_tls_relay"
	@echo "  Router:    python3 src/bootstrap_credentials.py && python3 src/omni_router_v7.py"
