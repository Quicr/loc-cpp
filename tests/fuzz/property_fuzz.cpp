// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Fuzzer for property encoding/decoding
// Build with: clang++ -g -fsanitize=fuzzer,address -std=c++20 property_fuzz.cpp -I../../include -o property_fuzz

#include <cstddef>
#include <cstdint>
#include <vector>

#include "loc/loc.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;

    loc::byte_span span{reinterpret_cast<const loc::byte*>(data), size};

    // Test property decoding - should never crash
    std::vector<loc::property_view> props;
    auto result = loc::decode_properties(span, [&](const loc::property_view& prop) {
        props.push_back(prop);

        // Try to decode varint value if appropriate
        if (prop.is_varint()) {
            auto val = prop.as_varint();
            (void)val;  // Just check it doesn't crash
        }

        return true;
    });

    // If decoding succeeded, verify all properties are valid
    if (result.has_value()) {
        for (const auto& prop : props) {
            // Property ID semantics should be consistent
            if (loc::is_varint_property(prop.id) != prop.is_varint()) {
                __builtin_trap();
            }
        }
    }

    // Test collect_properties API
    auto collected = loc::collect_properties(span);
    if (collected.has_value()) {
        // Should match visitor-based approach
        if (collected->size() != props.size()) {
            __builtin_trap();
        }
    }

    return 0;
}
