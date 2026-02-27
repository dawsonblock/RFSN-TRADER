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
CXXFLAGS   = -std=c++20 -O3 -march=native -Wall -Wextra -pthread -fPIC $(OPENSSL_INCLUDE) -Wno-deprecated-declarations
LDFLAGS    = $(OPENSSL_LIB) -lssl -lcrypto -pthread

# Add separate CXXFLAGS for client if needed (e.g. C++17 compat) but C++20 is fine.
# We'll use the same flags for consistency.

DAEMON_SRC     = src/market_daemon.cpp
RELAY_SRC      = aws_proxy/dtls_relay_poll.cpp
SENDER_SRC     = src/udp_sender.cpp
CLIENT_SRC     = src/dtls_client.cpp

DAEMON_OBJ     = build/market_daemon.o
RELAY_OBJ      = build/dtls_relay_poll.o
SENDER_OBJ     = build/udp_sender.o
CLIENT_OBJ     = build/dtls_client.o

DAEMON_BIN     = bin/market_daemon
RELAY_BIN      = bin/udp_tls_relay
SENDER_BIN     = bin/udp_sender
CLIENT_BIN     = bin/dtls_client

.PHONY: all daemon relay sender client clean help

all: daemon relay sender client

daemon: $(DAEMON_BIN)

relay: $(RELAY_BIN)

sender: $(SENDER_BIN)

client: $(CLIENT_BIN)

$(DAEMON_BIN): $(DAEMON_OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $(DAEMON_OBJ) $(LDFLAGS)
	@echo "[BUILD] ✓ market_daemon compiled"

$(RELAY_BIN): $(RELAY_OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $(RELAY_OBJ) $(LDFLAGS)
	@echo "[BUILD] ✓ udp_tls_relay (DTLS) compiled"

$(SENDER_BIN): $(SENDER_OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $(SENDER_OBJ) $(LDFLAGS)
	@echo "[BUILD] ✓ udp_sender compiled"

$(CLIENT_BIN): $(CLIENT_OBJ)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ $(CLIENT_OBJ) $(LDFLAGS)
	@echo "[BUILD] ✓ dtls_client compiled"

build/%.o: src/%.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

build/dtls_relay_poll.o: aws_proxy/dtls_relay_poll.cpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf build bin
	rm -f nonce.bin
	@echo "[CLEAN] ✓ Artifacts removed"

help:
	@echo "Usage: make [target]"
	@echo "  all      : Build all components"
	@echo "  daemon   : Build market_daemon"
	@echo "  relay    : Build udp_tls_relay (DTLS)"
	@echo "  sender   : Build udp_sender"
	@echo "  client   : Build dtls_client (Test Tool)"
	@echo "  clean    : Remove build artifacts"
