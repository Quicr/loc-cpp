// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <cstddef>
#include <cstdint>

#include "doctest/doctest.h"
#include "loc/loc.hpp"

TEST_CASE("property roundtrip preserves byte spans") {
    std::array config{std::byte{0x01}, std::byte{0x64}, std::byte{0x00}, std::byte{0x1f}};
    auto properties = std::array{
        loc::property::from_varint(loc::property_id::timestamp, 1234),
        loc::property::from_bytes(loc::property_id::video_config, loc::byte_span{config.data(), config.size()}),
    };

    auto encoded = loc::encode_properties(std::span{properties});

    auto decoded = loc::collect_properties(loc::byte_span{encoded.data(), encoded.size()});
    REQUIRE(decoded.has_value());
    REQUIRE_EQ(decoded->size(), 2U);

    CHECK_EQ((*decoded)[0].id, loc::property_id::timestamp);
    CHECK((*decoded)[0].is_varint());

    CHECK_EQ((*decoded)[1].id, loc::property_id::video_config);
    CHECK_FALSE((*decoded)[1].is_varint());
    CHECK_EQ(loc::to_hex((*decoded)[1].data), "0164001f");
}

TEST_CASE("property kind mismatch is rejected at encoding") {
    // Create a property that claims to be varint but has odd ID (which expects bytes)
    auto prop = loc::property::from_varint(loc::property_id::video_config, 42);  // ID 13 is odd

    std::array<loc::byte, 32> buf{};
    auto result = loc::encode_property(prop, buf);
    CHECK_FALSE(result.has_value());
    CHECK_EQ(result.error(), loc::errc::type_mismatch);
}

TEST_CASE("property with small buffer optimization") {
    // Small values should use inline storage
    auto small_prop = loc::property::from_varint(loc::property_id::timestamp, 42);
    CHECK_EQ(small_prop.id(), loc::property_id::timestamp);
    CHECK(small_prop.is_varint());

    auto val = small_prop.as_varint();
    REQUIRE(val.has_value());
    CHECK_EQ(*val, 42ULL);
}

TEST_CASE("property copy and move semantics") {
    std::array config{std::byte{0x01}, std::byte{0x64}};
    auto original = loc::property::from_bytes(loc::property_id::video_config, loc::byte_span{config.data(), config.size()});

    SUBCASE("copy construction") {
        auto copy = original;
        CHECK_EQ(copy.id(), original.id());
        CHECK_EQ(loc::to_hex(copy.data()), loc::to_hex(original.data()));
    }

    SUBCASE("move construction") {
        auto moved = std::move(original);
        CHECK_EQ(moved.id(), loc::property_id::video_config);
        CHECK_EQ(loc::to_hex(moved.data()), "0164");
    }

    SUBCASE("copy assignment") {
        loc::property copy;
        copy = original;
        CHECK_EQ(copy.id(), original.id());
        CHECK_EQ(loc::to_hex(copy.data()), loc::to_hex(original.data()));
    }
}

TEST_CASE("property_view decoding") {
    auto prop = loc::property::from_varint(loc::property_id::timestamp, 12345);
    auto view = prop.view();

    CHECK_EQ(view.id, loc::property_id::timestamp);
    CHECK(view.is_varint());

    auto val = view.as_varint();
    REQUIRE(val.has_value());
    CHECK_EQ(*val, 12345ULL);
}

TEST_CASE("decode_properties with visitor") {
    auto properties = std::array{
        loc::property::from_varint(loc::property_id::timestamp, 1000),
        loc::property::from_varint(loc::property_id::timescale, 90000),
    };

    auto encoded = loc::encode_properties(std::span{properties});

    std::vector<std::uint64_t> ids;
    std::vector<std::uint64_t> values;

    auto result = loc::decode_properties(loc::byte_span{encoded.data(), encoded.size()},
        [&](const loc::property_view& prop) {
            ids.push_back(prop.id);
            if (auto val = prop.as_varint(); val) {
                values.push_back(*val);
            }
            return true;
        });

    REQUIRE(result.has_value());
    REQUIRE_EQ(ids.size(), 2U);
    CHECK_EQ(ids[0], loc::property_id::timestamp);
    CHECK_EQ(ids[1], loc::property_id::timescale);
    CHECK_EQ(values[0], 1000ULL);
    CHECK_EQ(values[1], 90000ULL);
}

TEST_CASE("decode_properties early termination") {
    auto properties = std::array{
        loc::property::from_varint(loc::property_id::timestamp, 1000),
        loc::property::from_varint(loc::property_id::timescale, 90000),
        loc::property::from_varint(loc::property_id::audio_level, 42),
    };

    auto encoded = loc::encode_properties(std::span{properties});

    std::size_t count = 0;
    auto result = loc::decode_properties(loc::byte_span{encoded.data(), encoded.size()},
        [&](const loc::property_view&) {
            ++count;
            return count < 2;  // Stop after 2 properties
        });

    REQUIRE(result.has_value());
    CHECK_EQ(count, 2U);
}
