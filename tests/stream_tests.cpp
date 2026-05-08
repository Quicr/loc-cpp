// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <cstddef>
#include <cstdint>

#include "doctest/doctest.h"
#include "loc/loc.hpp"

TEST_CASE("media_time conversions") {
    SUBCASE("from microseconds") {
        auto time = loc::media_time::from_us(1'000'000);  // 1 second
        CHECK_EQ(time.ticks, 1'000'000ULL);
        CHECK_EQ(time.timescale, 1'000'000ULL);
        CHECK_EQ(time.to_us(), 1'000'000ULL);
        CHECK_EQ(time.to_ms(), 1'000ULL);
    }

    SUBCASE("from milliseconds") {
        auto time = loc::media_time::from_ms(500);
        CHECK_EQ(time.ticks, 500ULL);
        CHECK_EQ(time.timescale, 1'000ULL);
        CHECK_EQ(time.to_ms(), 500ULL);
    }

    SUBCASE("from 90kHz video") {
        auto time = loc::media_time::from_90khz(90'000);  // 1 second
        CHECK_EQ(time.ticks, 90'000ULL);
        CHECK_EQ(time.timescale, 90'000ULL);
        CHECK_EQ(time.to_us(), 1'000'000ULL);
    }

    SUBCASE("from 48kHz audio") {
        auto time = loc::media_time::from_48khz(48'000);  // 1 second
        CHECK_EQ(time.ticks, 48'000ULL);
        CHECK_EQ(time.timescale, 48'000ULL);
        CHECK_EQ(time.to_ms(), 1'000ULL);
    }

    SUBCASE("timescale conversion") {
        auto time = loc::media_time::from_90khz(90'000);
        auto converted = time.convert_to(48'000);
        CHECK_EQ(converted.ticks, 48'000ULL);
        CHECK_EQ(converted.timescale, 48'000ULL);
    }
}

TEST_CASE("buffer_pool basic operations") {
    loc::buffer_pool pool(1024);

    SUBCASE("acquire returns buffer with capacity") {
        auto buf = pool.acquire();
        CHECK_GE(buf.capacity(), 1024U);
        CHECK(buf.empty());
    }

    SUBCASE("release and reuse") {
        auto buf1 = pool.acquire();
        buf1.resize(100);
        pool.release(std::move(buf1));
        CHECK_EQ(pool.pool_size(), 1U);

        auto buf2 = pool.acquire();
        CHECK(buf2.empty());  // Should be cleared
        CHECK_GE(buf2.capacity(), 1024U);
        CHECK_EQ(pool.pool_size(), 0U);
    }

    SUBCASE("max pool size respected") {
        pool.set_max_pool_size(2);
        // Acquire several buffers first, then release them all
        std::vector<std::vector<loc::byte>> buffers;
        for (int i = 0; i < 5; ++i) {
            buffers.push_back(pool.acquire());
        }
        for (auto& buf : buffers) {
            pool.release(std::move(buf));
        }
        CHECK_EQ(pool.pool_size(), 2U);
    }
}

TEST_CASE("stream_encoder basic usage") {
    loc::stream_encoder encoder;

    encoder.timestamp(loc::media_time::from_90khz(90'000))
           .frame_marking({.independent = true, .temporal_id = 1});

    std::array payload{std::byte{0xde}, std::byte{0xad}};
    encoder.set_payload(loc::byte_span{payload.data(), payload.size()});

    auto result = encoder.encode();
    CHECK_FALSE(result.public_view().empty());
    CHECK_FALSE(result.payload_view().empty());

    auto props = loc::collect_properties(result.public_view());
    REQUIRE(props.has_value());
    CHECK_GE(props->size(), 3U);  // timestamp, timescale, frame_marking
}

TEST_CASE("stream_encoder with buffer pool") {
    loc::buffer_pool pool;
    loc::stream_encoder encoder(&pool);

    encoder.timestamp(12345);
    std::array payload{std::byte{0x01}};
    encoder.set_payload(loc::byte_span{payload.data(), payload.size()});

    {
        auto result = encoder.encode();
        CHECK_FALSE(result.public_view().empty());
        // Explicitly release buffers back to pool
        result.release_to(pool);
    }
    // Buffer should be returned to pool after explicit release
    CHECK_EQ(pool.pool_size(), 2U);
}

TEST_CASE("stream_encoder reset and reuse") {
    loc::stream_encoder encoder;

    encoder.timestamp(100);
    auto result1 = encoder.encode();

    encoder.reset();
    encoder.timestamp(200).timescale(48000);
    auto result2 = encoder.encode();

    CHECK_NE(result1.public_view().size(), result2.public_view().size());
}

TEST_CASE("stream_decoder basic usage") {
    loc::loc_object obj;
    obj.timestamp(777)
       .timescale(90'000)
       .frame_marking({.independent = true, .spatial_id = 2});

    std::array payload{std::byte{0xca}, std::byte{0xfe}};
    obj.set_payload(loc::byte_span{payload.data(), payload.size()});

    auto encoded = obj.encode();

    loc::stream_decoder decoder;
    CHECK_EQ(decoder.current_state(), loc::stream_decoder<>::state::need_header);

    auto parse_result = decoder.parse_public(encoded.public_view());
    REQUIRE(parse_result.has_value());
    CHECK_EQ(decoder.current_state(), loc::stream_decoder<>::state::have_header);

    auto payload_result = decoder.parse_payload(encoded.payload_view(), 0);
    REQUIRE(payload_result.has_value());
    CHECK_EQ(decoder.current_state(), loc::stream_decoder<>::state::complete);

    CHECK_EQ(decoder.get_timestamp(), 777ULL);
    CHECK_EQ(decoder.get_timescale(), 90'000ULL);

    auto time = decoder.get_media_time();
    REQUIRE(time.has_value());
    CHECK_EQ(time->ticks, 777ULL);
    CHECK_EQ(time->timescale, 90'000ULL);

    auto marking = decoder.get_frame_marking();
    REQUIRE(marking.has_value());
    CHECK(marking->independent);
    CHECK_EQ(marking->spatial_id, 2);

    CHECK_EQ(decoder.payload().size(), 2U);
}

TEST_CASE("stream_decoder audio frame") {
    loc::loc_object obj;
    obj.timescale(48'000)
       .audio_level_info({.level = 63, .voice_activity = true});

    auto encoded = obj.encode();

    loc::stream_decoder decoder;
    REQUIRE(decoder.parse_public(encoded.public_view()).has_value());
    REQUIRE(decoder.parse_payload(encoded.payload_view(), 0).has_value());

    auto level = decoder.get_audio_level();
    REQUIRE(level.has_value());
    CHECK_EQ(level->level, 63);
    CHECK(level->voice_activity);
}

TEST_CASE("media_frame video construction") {
    auto frame = loc::media_frame::video(
        loc::media_time::from_90khz(90'000),
        {.independent = true, .base_layer_sync = true}
    );

    std::array payload{std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
    frame.set_payload(loc::byte_span{payload.data(), payload.size()});

    CHECK_EQ(frame.frame_type(), loc::media_frame::type::video);
    CHECK(frame.is_keyframe());
    CHECK_EQ(frame.time().timescale, 90'000ULL);
    CHECK_EQ(frame.payload().size(), 3U);

    auto obj = frame.to_loc_object();
    auto encoded = obj.encode();
    CHECK_FALSE(encoded.public_view().empty());
}

TEST_CASE("media_frame audio construction") {
    auto frame = loc::media_frame::audio(
        loc::media_time::from_48khz(480),
        {.level = 42, .voice_activity = true}
    );

    CHECK_EQ(frame.frame_type(), loc::media_frame::type::audio);
    CHECK_FALSE(frame.is_keyframe());

    auto level = frame.audio_level_info();
    REQUIRE(level.has_value());
    CHECK_EQ(level->level, 42);
}

TEST_CASE("media_frame with group info") {
    auto frame = loc::media_frame::video(
        loc::media_time::from_90khz(0),
        {.independent = true}
    );

    frame.set_group({
        .group_id = 100,
        .subgroup_id = 1,
        .sequence = 0,
        .priority = 5,
        .delivery_timeout_ms = 200
    });

    auto obj = frame.to_loc_object();
    auto encoded = obj.encode();

    auto props = loc::collect_properties(encoded.public_view());
    REQUIRE(props.has_value());

    bool found_group = false;
    bool found_priority = false;
    for (const auto& p : *props) {
        if (p.id == loc::property_id::group_id) {
            auto val = p.as_varint();
            REQUIRE(val.has_value());
            CHECK_EQ(*val, 100ULL);
            found_group = true;
        }
        if (p.id == loc::property_id::priority) {
            auto val = p.as_varint();
            REQUIRE(val.has_value());
            CHECK_EQ(*val, 5ULL);
            found_priority = true;
        }
    }
    CHECK(found_group);
    CHECK(found_priority);
}

TEST_CASE("encode into pre-allocated buffer") {
    loc::stream_encoder encoder;
    encoder.timestamp(12345).timescale(90000);

    auto size = encoder.public_encoded_size();
    std::vector<loc::byte> buf(size);

    auto result = encoder.encode_public_into(buf);
    REQUIRE(result.has_value());
    CHECK_EQ(*result, size);

    auto props = loc::collect_properties(loc::byte_span{buf.data(), buf.size()});
    REQUIRE(props.has_value());
    CHECK_EQ(props->size(), 2U);
}
