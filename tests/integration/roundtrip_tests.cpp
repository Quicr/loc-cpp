// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <cstddef>
#include <cstdint>

#include "doctest/doctest.h"
#include "loc/loc.hpp"

TEST_CASE("integration roundtrip for video object") {
    loc::video_frame_marking marking{
        .independent = true,
        .discardable = true,
        .base_layer_sync = true,
        .temporal_id = 2,
        .spatial_id = 1,
    };

    loc::loc_object obj;
    obj.timestamp(90'000)
       .timescale(90'000)
       .frame_marking(marking);

    std::array private_bytes{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    obj.add_private(loc::property::from_bytes(loc::property_id::video_config,
                                               loc::byte_span{private_bytes.data(), private_bytes.size()}));

    std::array payload{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x65}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
    };
    obj.set_payload(loc::byte_span{payload.data(), payload.size()});

    auto encoded = obj.encode();

    auto decoded_public = loc::collect_properties(encoded.public_view());
    REQUIRE(decoded_public.has_value());
    REQUIRE_EQ(decoded_public->size(), 3U);

    auto private_props = std::array{loc::property::from_bytes(loc::property_id::video_config,
                                                               loc::byte_span{private_bytes.data(), private_bytes.size()})};
    auto private_encoded = loc::encode_properties(std::span{private_props});

    auto object_view = loc::decode_loc_object(
        encoded.public_view(),
        encoded.payload_view(),
        private_encoded.size());
    REQUIRE(object_view.has_value());

    auto decoded_private = loc::collect_properties(object_view->private_properties);
    REQUIRE(decoded_private.has_value());
    REQUIRE_EQ(decoded_private->size(), 1U);
    CHECK_EQ(loc::to_hex(object_view->payload), "0000000165112233");

    auto decoded_marking_val = (*decoded_public)[2].as_varint();
    REQUIRE(decoded_marking_val.has_value());
    auto parsed = loc::video_frame_marking::decode(*decoded_marking_val);
    CHECK(parsed.independent);
    CHECK(parsed.discardable);
    CHECK(parsed.base_layer_sync);
    CHECK_EQ(parsed.temporal_id, 2);
    CHECK_EQ(parsed.spatial_id, 1);
}

TEST_CASE("integration roundtrip for audio object") {
    loc::audio_level level{
        .level = 63,
        .voice_activity = true,
    };

    loc::loc_object audio;
    audio.timescale(48'000)
         .audio_level_info(level);

    std::array payload{std::byte{0xf1}, std::byte{0x50}, std::byte{0x80}, std::byte{0x00}};
    audio.set_payload(loc::byte_span{payload.data(), payload.size()});

    auto encoded = audio.encode();

    auto decoded_public = loc::collect_properties(encoded.public_view());
    REQUIRE(decoded_public.has_value());
    REQUIRE_EQ(decoded_public->size(), 2U);

    auto level_val = (*decoded_public)[1].as_varint();
    REQUIRE(level_val.has_value());

    auto parsed = loc::audio_level::decode(*level_val);
    CHECK_EQ(parsed.level, 63);
    CHECK(parsed.voice_activity);
}

TEST_CASE("empty object roundtrip") {
    loc::loc_object empty;
    auto encoded = empty.encode();

    CHECK(encoded.public_view().empty());
    CHECK(encoded.payload_view().empty());

    auto object_view = loc::decode_loc_object(
        encoded.public_view(),
        encoded.payload_view(),
        0);
    REQUIRE(object_view.has_value());
    CHECK(object_view->public_properties.empty());
    CHECK(object_view->private_properties.empty());
    CHECK(object_view->payload.empty());
}
