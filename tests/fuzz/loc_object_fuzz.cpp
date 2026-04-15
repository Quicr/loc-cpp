// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Fuzzer for LOC object encoding/decoding
// Build with: clang++ -g -fsanitize=fuzzer,address -std=c++20 loc_object_fuzz.cpp -I../../include -o loc_object_fuzz

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "loc/loc.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 4) return 0;

    // Use first 2 bytes to determine split points
    std::size_t public_len = data[0] % (size - 2);
    std::size_t private_len = data[1] % (size - 2 - public_len);

    const std::uint8_t* public_data = data + 2;
    const std::uint8_t* payload_data = data + 2 + public_len;
    std::size_t payload_size = size - 2 - public_len;

    loc::byte_span public_span{reinterpret_cast<const loc::byte*>(public_data), public_len};
    loc::byte_span payload_span{reinterpret_cast<const loc::byte*>(payload_data), payload_size};

    // Ensure private_len doesn't exceed payload_size
    if (private_len > payload_size) {
        private_len = payload_size;
    }

    // Test decoding - should never crash
    auto result = loc::decode_loc_object(public_span, payload_span, private_len);

    if (result.has_value()) {
        // Verify spans are within bounds
        if (result->private_properties.size() != private_len) {
            __builtin_trap();
        }
        if (result->payload.size() != payload_size - private_len) {
            __builtin_trap();
        }

        // Try to parse properties
        auto public_props = loc::collect_properties(result->public_properties);
        auto private_props = loc::collect_properties(result->private_properties);
        (void)public_props;
        (void)private_props;
    }

    return 0;
}
