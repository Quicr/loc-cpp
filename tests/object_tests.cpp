// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <cstddef>

#include "doctest/doctest.h"
#include "loc/loc.hpp"

TEST_CASE("loc_object encode and decode roundtrip") {
    loc::loc_object obj;
    obj.timestamp(777)
       .add_private(loc::property::from_bytes(13, loc::byte_span{}));

    std::array payload{std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};
    obj.set_payload(loc::byte_span{payload.data(), payload.size()});

    auto encoded = obj.encode();

    // Calculate private properties length for decoding
    auto private_props = std::array{loc::property::from_bytes(13, loc::byte_span{})};
    auto private_encoded = loc::encode_properties(std::span{private_props});

    auto decoded = loc::decode_loc_object(
        encoded.public_view(),
        encoded.payload_view(),
        private_encoded.size());

    REQUIRE(decoded.has_value());
    CHECK_EQ(loc::to_hex(decoded->private_properties), loc::to_hex(loc::byte_span{private_encoded.data(), private_encoded.size()}));
    CHECK_EQ(loc::to_hex(decoded->payload), "deadbeef");
}

TEST_CASE("loc_object builder API") {
    loc::loc_object frame;

    frame.timestamp(1'716'123'456ULL)
         .timescale(90'000ULL)
         .frame_marking({
             .independent = true,
             .discardable = false,
             .base_layer_sync = true,
             .temporal_id = 2,
             .spatial_id = 1
         });

    auto encoded = frame.encode();
    auto props = loc::collect_properties(encoded.public_view());

    REQUIRE(props.has_value());
    REQUIRE_EQ(props->size(), 3U);

    CHECK_EQ((*props)[0].id, loc::property_id::timestamp);
    CHECK_EQ((*props)[1].id, loc::property_id::timescale);
    CHECK_EQ((*props)[2].id, loc::property_id::video_frame_marking);
}

TEST_CASE("loc_object with audio level") {
    loc::loc_object audio_frame;

    audio_frame.timescale(48'000ULL)
               .audio_level_info({.level = 42, .voice_activity = true});

    auto encoded = audio_frame.encode();
    auto props = loc::collect_properties(encoded.public_view());

    REQUIRE(props.has_value());
    REQUIRE_EQ(props->size(), 2U);

    auto level_val = (*props)[1].as_varint();
    REQUIRE(level_val.has_value());

    auto level = loc::audio_level::decode(*level_val);
    REQUIRE(level.has_value());
    CHECK_EQ(level->level, 42);
    CHECK(level->voice_activity);
}

TEST_CASE("decode_loc_object handles truncated input") {
    std::array<loc::byte, 4> pub_props{};
    std::array<loc::byte, 2> payload{};

    // Claim more private properties than payload contains
    auto result = loc::decode_loc_object(
        loc::byte_span{pub_props.data(), pub_props.size()},
        loc::byte_span{payload.data(), payload.size()},
        10);  // More than payload size

    CHECK_FALSE(result.has_value());
    CHECK_EQ(result.error(), loc::errc::truncated);
}

TEST_CASE("loc_object with payload") {
    std::array payload_data{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x65}, std::byte{0x88}, std::byte{0x84}, std::byte{0x21},
    };

    loc::loc_object frame;
    frame.set_payload(loc::byte_span{payload_data.data(), payload_data.size()});

    auto encoded = frame.encode();
    CHECK_EQ(encoded.payload_view().size(), 8U);
    CHECK_EQ(loc::to_hex(encoded.payload_view()), "0000000165888421");
}

TEST_CASE("loc_object accessors") {
    loc::loc_object obj;
    obj.timestamp(100)
       .add_private(loc::property::from_varint(loc::property_id::timestamp, 200));

    std::array payload{std::byte{0x42}};
    obj.set_payload(loc::byte_span{payload.data(), payload.size()});

    CHECK_EQ(obj.public_properties().size(), 1U);
    CHECK_EQ(obj.private_properties().size(), 1U);
    CHECK_EQ(obj.payload().size(), 1U);
}
