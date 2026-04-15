// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "doctest/doctest.h"
#include "loc/loc.hpp"

TEST_CASE("varint roundtrip") {
    constexpr std::array<std::uint64_t, 10> values{
        0,
        1,
        63,
        64,
        127,
        128,
        255,
        16'383,
        16'384,
        0xffff'ffffULL,
    };

    for (const auto value : values) {
        auto encoded = loc::encode_varint(value);
        loc::byte_span span{encoded.data(), encoded.size()};
        auto decoded = loc::decode_varint(span);
        REQUIRE(decoded.has_value());
        CHECK_EQ(*decoded, value);
        CHECK(span.empty());
    }
}

TEST_CASE("quic varint encoding") {
    SUBCASE("single byte values") {
        auto encoded = loc::encode_varint<loc::quic_varint>(37);
        REQUIRE_EQ(encoded.size(), 1U);
        CHECK_EQ(std::to_integer<std::uint8_t>(encoded[0]), 0x25U);
    }

    SUBCASE("two byte values") {
        auto encoded = loc::encode_varint<loc::quic_varint>(15'293);
        REQUIRE_EQ(encoded.size(), 2U);
        CHECK_EQ(std::to_integer<std::uint8_t>(encoded[0]), 0x7bU);
        CHECK_EQ(std::to_integer<std::uint8_t>(encoded[1]), 0xbdU);
    }

    SUBCASE("four byte values") {
        auto encoded = loc::encode_varint<loc::quic_varint>(494'878'333);
        REQUIRE_EQ(encoded.size(), 4U);
        CHECK_EQ(std::to_integer<std::uint8_t>(encoded[0]), 0x9dU);
    }
}

TEST_CASE("moq varint encoding") {
    SUBCASE("single byte values") {
        auto encoded = loc::encode_varint<loc::moq_varint>(37);
        REQUIRE_EQ(encoded.size(), 1U);
        CHECK_EQ(std::to_integer<std::uint8_t>(encoded[0]), 0x25U);
    }

    SUBCASE("two byte values for 128") {
        auto encoded = loc::encode_varint<loc::moq_varint>(128);
        REQUIRE_EQ(encoded.size(), 2U);
        CHECK_EQ(std::to_integer<std::uint8_t>(encoded[0]), 0x80U);
        CHECK_EQ(std::to_integer<std::uint8_t>(encoded[1]), 0x01U);
    }
}

TEST_CASE("varint rejects non-minimal encodings") {
    SUBCASE("quic varint") {
        std::array data{std::byte{0x40}, std::byte{0x01}};
        loc::byte_span span{data.data(), data.size()};
        auto decoded = loc::decode_varint<loc::quic_varint>(span);
        CHECK_FALSE(decoded.has_value());
        CHECK_EQ(decoded.error(), loc::errc::non_minimal);
    }

    SUBCASE("moq varint") {
        std::array data{std::byte{0x80}, std::byte{0x00}};
        loc::byte_span span{data.data(), data.size()};
        auto decoded = loc::decode_varint<loc::moq_varint>(span);
        CHECK_FALSE(decoded.has_value());
        CHECK_EQ(decoded.error(), loc::errc::non_minimal);
    }
}

TEST_CASE("quic varint rejects values beyond 62 bits") {
    std::array<loc::byte, 8> buf{};
    auto result = loc::quic_varint::encode(4'611'686'018'427'387'904ULL, buf);
    CHECK_FALSE(result.has_value());
    CHECK_EQ(result.error(), loc::errc::overflow);
}

TEST_CASE("varint handles truncated input") {
    std::array data{std::byte{0x40}};  // QUIC 2-byte prefix but only 1 byte
    loc::byte_span span{data.data(), data.size()};
    auto decoded = loc::decode_varint<loc::quic_varint>(span);
    CHECK_FALSE(decoded.has_value());
    CHECK_EQ(decoded.error(), loc::errc::truncated);
}

TEST_CASE("varint handles empty input") {
    loc::byte_span span{};
    auto decoded = loc::decode_varint<loc::quic_varint>(span);
    CHECK_FALSE(decoded.has_value());
    CHECK_EQ(decoded.error(), loc::errc::truncated);
}

TEST_CASE("varint encoded size calculation") {
    CHECK_EQ(loc::quic_varint::encoded_size(0), 1U);
    CHECK_EQ(loc::quic_varint::encoded_size(63), 1U);
    CHECK_EQ(loc::quic_varint::encoded_size(64), 2U);
    CHECK_EQ(loc::quic_varint::encoded_size(16'383), 2U);
    CHECK_EQ(loc::quic_varint::encoded_size(16'384), 4U);
    CHECK_EQ(loc::quic_varint::encoded_size(1'073'741'823), 4U);
    CHECK_EQ(loc::quic_varint::encoded_size(1'073'741'824), 8U);

    CHECK_EQ(loc::moq_varint::encoded_size(0), 1U);
    CHECK_EQ(loc::moq_varint::encoded_size(127), 1U);
    CHECK_EQ(loc::moq_varint::encoded_size(128), 2U);
    CHECK_EQ(loc::moq_varint::encoded_size(16'383), 2U);
    CHECK_EQ(loc::moq_varint::encoded_size(16'384), 3U);
}
