#include "keccak_nonce_manager.hpp"
#include <iostream>
#include <iomanip>
#include <vector>

void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== Keccak-256 EIP-712 Logic Test ===\n";

    // Test 1: String "Hello World"
    {
        Keccak256 k;
        uint8_t out[32];
        std::string msg = "Hello World";
        k.update((const uint8_t*)msg.data(), msg.size());
        k.final(out);
        print_hex("String 'Hello World'", out, 32);
    }

    // Test 2: uint256 Encoded (0x1234567890ABCDEF)
    {
        uint8_t out[32];
        uint64_t val = 0x1234567890ABCDEF;
        uint8_t encoded[32];
        
        // Simulate encoded buffer (Big Endian)
        std::memset(encoded, 0, 32);
        for (int i = 0; i < 8; ++i) {
            encoded[31 - i] = (val >> (i * 8)) & 0xFF; // Big Endian: LSB at index 31
        }
        
        Keccak256 k;
        k.update(encoded, 32);
        k.final(out);
        
        print_hex("uint256 (0x1234..EF)", out, 32);
    }

    return 0;
}
