// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "loc/loc.hpp"

void basic_example() {
    std::cout << "=== Basic Video Frame ===\n";

    loc::loc_object frame;
    frame.timestamp(1'716'123'456ULL)
         .timescale(90'000ULL)
         .frame_marking({
             .independent = true,
             .discardable = false,
             .base_layer_sync = true,
             .temporal_id = 0,
             .spatial_id = 0
         });

    const std::array payload{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        std::byte{0x65}, std::byte{0x88}, std::byte{0x84}, std::byte{0x21},
    };
    frame.set_payload(loc::byte_span{payload.data(), payload.size()});

    auto encoded = frame.encode();
    std::cout << "public:  " << loc::to_hex(encoded.public_view()) << "\n";
    std::cout << "payload: " << loc::to_hex(encoded.payload_view()) << "\n\n";
}

void streaming_encoder_example() {
    std::cout << "=== Stream Encoder with Buffer Pool ===\n";

    loc::buffer_pool pool(4096);
    loc::stream_encoder encoder(&pool);

    // Encode a video keyframe
    encoder.timestamp(loc::media_time::from_90khz(0))
           .frame_marking({.independent = true, .base_layer_sync = true})
           .set_group({.group_id = 1, .subgroup_id = 0, .sequence = 0, .priority = 0});

    const std::array nal{std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x65}};
    encoder.set_payload(loc::byte_span{nal.data(), nal.size()});

    {
        auto result = encoder.encode();
        std::cout << "Frame 0 public:  " << loc::to_hex(result.public_view()) << "\n";
        std::cout << "Frame 0 payload: " << loc::to_hex(result.payload_view()) << "\n";
    }

    // Reuse encoder for next frame
    encoder.reset()
           .timestamp(loc::media_time::from_90khz(3003))  // ~33ms at 90kHz
           .frame_marking({.independent = false, .temporal_id = 1})
           .set_group({.group_id = 1, .subgroup_id = 0, .sequence = 1, .priority = 1});

    encoder.set_payload(loc::byte_span{nal.data(), nal.size()});

    {
        auto result = encoder.encode();
        std::cout << "Frame 1 public:  " << loc::to_hex(result.public_view()) << "\n";
    }

    std::cout << "Pool size after encoding: " << pool.pool_size() << " buffers\n\n";
}

void streaming_decoder_example() {
    std::cout << "=== Stream Decoder ===\n";

    // First encode a frame
    loc::loc_object obj;
    obj.timestamp(90'000)
       .timescale(90'000)
       .frame_marking({.independent = true, .spatial_id = 1});

    const std::array payload{std::byte{0xca}, std::byte{0xfe}};
    obj.set_payload(loc::byte_span{payload.data(), payload.size()});
    auto encoded = obj.encode();

    // Now decode it
    loc::stream_decoder decoder;

    (void)decoder.parse_public(encoded.public_view());
    (void)decoder.parse_payload(encoded.payload_view(), 0);

    if (auto time = decoder.get_media_time()) {
        std::cout << "Timestamp: " << time->ticks << " / " << time->timescale
                  << " = " << time->to_ms() << " ms\n";
    }

    if (auto marking = decoder.get_frame_marking()) {
        std::cout << "Keyframe: " << (marking->independent ? "yes" : "no") << "\n";
        std::cout << "Spatial ID: " << static_cast<int>(marking->spatial_id) << "\n";
    }

    std::cout << "Payload: " << loc::to_hex(decoder.payload()) << "\n\n";
}

void media_frame_example() {
    std::cout << "=== Media Frame Helper ===\n";

    // Video keyframe
    auto video = loc::media_frame::video(
        loc::media_time::from_us(0),
        {.independent = true, .base_layer_sync = true}
    );
    video.set_group({
        .group_id = 1,
        .subgroup_id = 0,
        .sequence = 0,
        .priority = 0,
        .delivery_timeout_ms = 100
    });

    const std::array h264_idr{std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x65}};
    video.set_payload(loc::byte_span{h264_idr.data(), h264_idr.size()});

    std::cout << "Video frame:\n";
    std::cout << "  Type: " << (video.frame_type() == loc::media_frame::type::video ? "video" : "other") << "\n";
    std::cout << "  Keyframe: " << (video.is_keyframe() ? "yes" : "no") << "\n";
    std::cout << "  Time: " << video.time().to_us() << " us\n";

    auto loc_obj = video.to_loc_object();
    auto encoded = loc_obj.encode();
    std::cout << "  Encoded public: " << loc::to_hex(encoded.public_view()) << "\n";

    // Audio frame
    auto audio = loc::media_frame::audio(
        loc::media_time::from_48khz(480),  // 10ms of audio
        {.level = 42, .voice_activity = true}
    );

    const std::array opus_frame{std::byte{0xfc}, std::byte{0xff}};
    audio.set_payload(loc::byte_span{opus_frame.data(), opus_frame.size()});

    std::cout << "\nAudio frame:\n";
    std::cout << "  Type: " << (audio.frame_type() == loc::media_frame::type::audio ? "audio" : "other") << "\n";
    std::cout << "  Time: " << audio.time().to_ms() << " ms\n";
    if (auto level = audio.audio_level_info()) {
        std::cout << "  Audio level: " << static_cast<int>(level->level) << " dB\n";
        std::cout << "  Voice activity: " << (level->voice_activity ? "yes" : "no") << "\n";
    }

    std::cout << "\n";
}

void timestamp_conversion_example() {
    std::cout << "=== Timestamp Conversions ===\n";

    // Video at 90kHz (1 second)
    auto video_time = loc::media_time::from_90khz(90'000);
    std::cout << "90kHz video (1s): " << video_time.ticks << " ticks\n";
    std::cout << "  -> microseconds: " << video_time.to_us() << "\n";
    std::cout << "  -> milliseconds: " << video_time.to_ms() << "\n";

    // Convert to 48kHz audio timescale
    auto audio_time = video_time.convert_to(48'000);
    std::cout << "  -> 48kHz: " << audio_time.ticks << " samples\n";

    // Create from microseconds with custom timescale
    auto custom = loc::media_time::from_us(33333, 90'000);  // ~1 frame at 30fps
    std::cout << "\n33.3ms in 90kHz: " << custom.ticks << " ticks\n";

    std::cout << "\n";
}

int main() {
    basic_example();
    streaming_encoder_example();
    streaming_decoder_example();
    media_frame_example();
    timestamp_conversion_example();

    return 0;
}
