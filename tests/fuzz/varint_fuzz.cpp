// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Fuzzer for varint encoding/decoding
// Build with: clang++ -g -fsanitize=fuzzer,address -std=c++20 varint_fuzz.cpp -I../../include -o varint_fuzz

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "loc/loc.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;

    // Test QUIC varint decoding
    {
        loc::byte_span span{reinterpret_cast<const loc::byte*>(data), size};
        auto result = loc::decode_varint<loc::quic_varint>(span);
        if (result.has_value()) {
            // Verify roundtrip
            auto encoded = loc::encode_varint<loc::quic_varint>(*result);
            loc::byte_span encoded_span{encoded.data(), encoded.size()};
            auto roundtrip = loc::decode_varint<loc::quic_varint>(encoded_span);
            if (!roundtrip.has_value() || *roundtrip != *result) {
                __builtin_trap();
            }
        }
    }

    // Test MOQ varint decoding
    {
        loc::byte_span span{reinterpret_cast<const loc::byte*>(data), size};
        auto result = loc::decode_varint<loc::moq_varint>(span);
        if (result.has_value()) {
            // Verify roundtrip
            auto encoded = loc::encode_varint<loc::moq_varint>(*result);
            loc::byte_span encoded_span{encoded.data(), encoded.size()};
            auto roundtrip = loc::decode_varint<loc::moq_varint>(encoded_span);
            if (!roundtrip.has_value() || *roundtrip != *result) {
                __builtin_trap();
            }
        }
    }

    // Test encoding from uint64 values extracted from input
    if (size >= 8) {
        std::uint64_t value;
        std::memcpy(&value, data, sizeof(value));

        // QUIC encoding
        auto quic_encoded = loc::encode_varint<loc::quic_varint>(value);
        loc::byte_span quic_span{quic_encoded.data(), quic_encoded.size()};
        auto quic_decoded = loc::decode_varint<loc::quic_varint>(quic_span);
        if (quic_decoded.has_value() && *quic_decoded != value) {
            __builtin_trap();
        }

        // MOQ encoding always succeeds
        auto moq_encoded = loc::encode_varint<loc::moq_varint>(value);
        loc::byte_span moq_span{moq_encoded.data(), moq_encoded.size()};
        auto moq_decoded = loc::decode_varint<loc::moq_varint>(moq_span);
        if (!moq_decoded.has_value() || *moq_decoded != value) {
            __builtin_trap();
        }
    }

    return 0;
}
