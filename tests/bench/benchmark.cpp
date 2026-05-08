// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "loc/loc.hpp"

namespace {

using clock_type = std::chrono::high_resolution_clock;
using duration_type = std::chrono::nanoseconds;

struct benchmark_result {
    std::string name;
    std::size_t iterations;
    duration_type total_time;
    double ns_per_op;
    double ops_per_sec;
};

template <typename Func>
benchmark_result run_benchmark(const std::string& name, std::size_t iterations, Func&& func) {
    // Warmup
    for (std::size_t i = 0; i < iterations / 10; ++i) {
        func();
    }

    auto start = clock_type::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        func();
    }
    auto end = clock_type::now();

    auto total = std::chrono::duration_cast<duration_type>(end - start);
    double ns_per_op = static_cast<double>(total.count()) / static_cast<double>(iterations);
    double ops_per_sec = 1e9 / ns_per_op;

    return {name, iterations, total, ns_per_op, ops_per_sec};
}

void print_result(const benchmark_result& r) {
    std::cout << std::left << std::setw(45) << r.name
              << std::right << std::setw(12) << std::fixed << std::setprecision(1) << r.ns_per_op << " ns/op"
              << std::setw(15) << std::fixed << std::setprecision(0) << r.ops_per_sec << " ops/sec"
              << "\n";
}

// Compiler barrier to prevent dead code elimination
template <typename T>
void do_not_optimize(T const& value) {
#if defined(__clang__) || defined(__GNUC__)
    asm volatile("" : : "r,m"(value) : "memory");
#else
    volatile auto dummy = value;
    (void)dummy;
#endif
}

}  // namespace

int main() {
    constexpr std::size_t iterations = 1'000'000;

    std::cout << "\nLOC Benchmark Results\n";
    std::cout << std::string(75, '=') << "\n\n";

    // Varint encoding benchmarks
    {
        std::cout << "Varint Encoding\n";
        std::cout << std::string(75, '-') << "\n";

        print_result(run_benchmark("quic_varint::encode(42)", iterations, []() {
            auto result = loc::encode_varint<loc::quic_varint>(42);
            do_not_optimize(result.data());
        }));

        print_result(run_benchmark("quic_varint::encode(16383)", iterations, []() {
            auto result = loc::encode_varint<loc::quic_varint>(16383);
            do_not_optimize(result.data());
        }));

        print_result(run_benchmark("quic_varint::encode(1073741823)", iterations, []() {
            auto result = loc::encode_varint<loc::quic_varint>(1073741823);
            do_not_optimize(result.data());
        }));

        print_result(run_benchmark("moq_varint::encode(42)", iterations, []() {
            auto result = loc::encode_varint<loc::moq_varint>(42);
            do_not_optimize(result.data());
        }));

        print_result(run_benchmark("moq_varint::encode(16383)", iterations, []() {
            auto result = loc::encode_varint<loc::moq_varint>(16383);
            do_not_optimize(result.data());
        }));

        std::cout << "\n";
    }

    // Varint decoding benchmarks
    {
        std::cout << "Varint Decoding\n";
        std::cout << std::string(75, '-') << "\n";

        auto quic_1byte = loc::encode_varint<loc::quic_varint>(42);
        auto quic_2byte = loc::encode_varint<loc::quic_varint>(16383);
        auto quic_4byte = loc::encode_varint<loc::quic_varint>(1073741823);

        print_result(run_benchmark("quic_varint::decode(1 byte)", iterations, [&]() {
            loc::byte_span span{quic_1byte.data(), quic_1byte.size()};
            auto result = loc::decode_varint<loc::quic_varint>(span);
            do_not_optimize(*result);
        }));

        print_result(run_benchmark("quic_varint::decode(2 bytes)", iterations, [&]() {
            loc::byte_span span{quic_2byte.data(), quic_2byte.size()};
            auto result = loc::decode_varint<loc::quic_varint>(span);
            do_not_optimize(*result);
        }));

        print_result(run_benchmark("quic_varint::decode(4 bytes)", iterations, [&]() {
            loc::byte_span span{quic_4byte.data(), quic_4byte.size()};
            auto result = loc::decode_varint<loc::quic_varint>(span);
            do_not_optimize(*result);
        }));

        auto moq_1byte = loc::encode_varint<loc::moq_varint>(42);
        auto moq_2byte = loc::encode_varint<loc::moq_varint>(16383);

        print_result(run_benchmark("moq_varint::decode(1 byte)", iterations, [&]() {
            loc::byte_span span{moq_1byte.data(), moq_1byte.size()};
            auto result = loc::decode_varint<loc::moq_varint>(span);
            do_not_optimize(*result);
        }));

        print_result(run_benchmark("moq_varint::decode(2 bytes)", iterations, [&]() {
            loc::byte_span span{moq_2byte.data(), moq_2byte.size()};
            auto result = loc::decode_varint<loc::moq_varint>(span);
            do_not_optimize(*result);
        }));

        std::cout << "\n";
    }

    // Property benchmarks
    {
        std::cout << "Property Operations\n";
        std::cout << std::string(75, '-') << "\n";

        print_result(run_benchmark("property::from_varint", iterations, []() {
            auto prop = loc::property::from_varint(loc::property_id::timestamp, 1716123456ULL);
            do_not_optimize(prop.data().data());
        }));

        std::array<loc::byte, 64> bytes{};
        print_result(run_benchmark("property::from_bytes(64)", iterations, [&]() {
            auto prop = loc::property::from_bytes(loc::property_id::video_config,
                                                   loc::byte_span{bytes.data(), bytes.size()});
            do_not_optimize(prop.data().data());
        }));

        auto props = std::array{
            loc::property::from_varint(loc::property_id::timestamp, 1716123456ULL),
            loc::property::from_varint(loc::property_id::timescale, 90000ULL),
            loc::property::from_varint(loc::property_id::video_frame_marking, 7ULL),
        };

        print_result(run_benchmark("encode_properties(3 props)", iterations, [&]() {
            auto encoded = loc::encode_properties(std::span{props});
            do_not_optimize(encoded.data());
        }));

        auto encoded_props = loc::encode_properties(std::span{props});
        print_result(run_benchmark("collect_properties(3 props)", iterations, [&]() {
            auto decoded = loc::collect_properties(loc::byte_span{encoded_props.data(), encoded_props.size()});
            do_not_optimize(decoded->data());
        }));

        std::cout << "\n";
    }

    // LOC object benchmarks
    {
        std::cout << "LOC Object Operations\n";
        std::cout << std::string(75, '-') << "\n";

        std::array<loc::byte, 1024> payload_data{};
        std::mt19937 rng(42);
        for (auto& b : payload_data) {
            b = static_cast<loc::byte>(rng() & 0xFF);
        }

        print_result(run_benchmark("loc_object::encode (video frame)", iterations / 10, [&]() {
            loc::loc_object frame;
            frame.timestamp(1716123456ULL)
                 .timescale(90000ULL)
                 .frame_marking({.independent = true, .discardable = false, .base_layer_sync = true})
                 .set_payload(loc::byte_span{payload_data.data(), payload_data.size()});

            auto encoded = frame.encode();
            do_not_optimize(encoded.public_view().data());
        }));

        loc::loc_object sample_frame;
        sample_frame.timestamp(1716123456ULL)
                    .timescale(90000ULL)
                    .frame_marking({.independent = true});
        sample_frame.set_payload(loc::byte_span{payload_data.data(), payload_data.size()});
        auto sample_encoded = sample_frame.encode();

        print_result(run_benchmark("decode_loc_object", iterations, [&]() {
            auto decoded = loc::decode_loc_object(
                sample_encoded.public_view(),
                sample_encoded.payload_view(),
                0);
            do_not_optimize(decoded->payload.data());
        }));

        std::cout << "\n";
    }

    // Streaming encoder benchmarks (NEW)
    {
        std::cout << "Stream Encoder Operations\n";
        std::cout << std::string(75, '-') << "\n";

        std::array<loc::byte, 1024> payload_data{};
        std::mt19937 rng(42);
        for (auto& b : payload_data) {
            b = static_cast<loc::byte>(rng() & 0xFF);
        }

        // Without buffer pool
        print_result(run_benchmark("stream_encoder (no pool)", iterations / 10, [&]() {
            loc::stream_encoder encoder;
            encoder.timestamp(loc::media_time::from_90khz(90000))
                   .frame_marking({.independent = true, .base_layer_sync = true})
                   .set_payload(loc::byte_span{payload_data.data(), payload_data.size()});

            auto result = encoder.encode();
            do_not_optimize(result.public_view().data());
        }));

        // With buffer pool
        loc::buffer_pool pool(4096);
        print_result(run_benchmark("stream_encoder (with pool)", iterations / 10, [&]() {
            loc::stream_encoder encoder(&pool);
            encoder.timestamp(loc::media_time::from_90khz(90000))
                   .frame_marking({.independent = true, .base_layer_sync = true})
                   .set_payload(loc::byte_span{payload_data.data(), payload_data.size()});

            auto result = encoder.encode();
            do_not_optimize(result.public_view().data());
        }));

        // Encoder reuse with reset
        loc::stream_encoder reusable_encoder(&pool);
        print_result(run_benchmark("stream_encoder (reuse + pool)", iterations / 10, [&]() {
            reusable_encoder.reset()
                   .timestamp(loc::media_time::from_90khz(90000))
                   .frame_marking({.independent = true, .base_layer_sync = true})
                   .set_payload(loc::byte_span{payload_data.data(), payload_data.size()});

            auto result = reusable_encoder.encode();
            do_not_optimize(result.public_view().data());
        }));

        // With group info
        print_result(run_benchmark("stream_encoder (with group)", iterations / 10, [&]() {
            reusable_encoder.reset()
                   .timestamp(loc::media_time::from_90khz(90000))
                   .frame_marking({.independent = true})
                   .set_group({.group_id = 1, .subgroup_id = 0, .sequence = 100, .priority = 0})
                   .set_payload(loc::byte_span{payload_data.data(), payload_data.size()});

            auto result = reusable_encoder.encode();
            do_not_optimize(result.public_view().data());
        }));

        std::cout << "\n";
    }

    // Stream decoder benchmarks (NEW)
    {
        std::cout << "Stream Decoder Operations\n";
        std::cout << std::string(75, '-') << "\n";

        // Prepare encoded data
        loc::loc_object obj;
        obj.timestamp(90000)
           .timescale(90000)
           .frame_marking({.independent = true, .spatial_id = 1});

        std::array<loc::byte, 1024> payload{};
        obj.set_payload(loc::byte_span{payload.data(), payload.size()});
        auto encoded = obj.encode();

        print_result(run_benchmark("stream_decoder::parse_public", iterations, [&]() {
            loc::stream_decoder decoder;
            auto result = decoder.parse_public(encoded.public_view());
            do_not_optimize(result.has_value());
        }));

        print_result(run_benchmark("stream_decoder full decode", iterations, [&]() {
            loc::stream_decoder decoder;
            decoder.parse_public(encoded.public_view());
            decoder.parse_payload(encoded.payload_view(), 0);
            do_not_optimize(decoder.payload().data());
        }));

        print_result(run_benchmark("stream_decoder + get metadata", iterations, [&]() {
            loc::stream_decoder decoder;
            decoder.parse_public(encoded.public_view());
            decoder.parse_payload(encoded.payload_view(), 0);
            auto ts = decoder.get_timestamp();
            auto marking = decoder.get_frame_marking();
            do_not_optimize(ts.value_or(0));
            do_not_optimize(marking.has_value());
        }));

        std::cout << "\n";
    }

    // Media frame benchmarks (NEW)
    {
        std::cout << "Media Frame Operations\n";
        std::cout << std::string(75, '-') << "\n";

        std::array<loc::byte, 1024> payload_data{};

        print_result(run_benchmark("media_frame::video creation", iterations, [&]() {
            auto frame = loc::media_frame::video(
                loc::media_time::from_90khz(90000),
                {.independent = true, .base_layer_sync = true}
            );
            frame.set_payload(loc::byte_span{payload_data.data(), payload_data.size()});
            do_not_optimize(frame.is_keyframe());
        }));

        print_result(run_benchmark("media_frame::to_loc_object", iterations / 10, [&]() {
            auto frame = loc::media_frame::video(
                loc::media_time::from_90khz(90000),
                {.independent = true}
            );
            frame.set_group({.group_id = 1, .sequence = 0, .priority = 0});
            frame.set_payload(loc::byte_span{payload_data.data(), payload_data.size()});

            auto obj = frame.to_loc_object();
            auto encoded = obj.encode();
            do_not_optimize(encoded.public_view().data());
        }));

        std::cout << "\n";
    }

    // Timestamp conversion benchmarks (NEW)
    {
        std::cout << "Timestamp Operations\n";
        std::cout << std::string(75, '-') << "\n";

        print_result(run_benchmark("media_time::from_us", iterations, []() {
            auto time = loc::media_time::from_us(33333, 90000);
            do_not_optimize(time.ticks);
        }));

        print_result(run_benchmark("media_time::convert_to", iterations, []() {
            auto time = loc::media_time::from_90khz(90000);
            auto converted = time.convert_to(48000);
            do_not_optimize(converted.ticks);
        }));

        print_result(run_benchmark("media_time::to_us", iterations, []() {
            auto time = loc::media_time::from_90khz(90000);
            auto us = time.to_us();
            do_not_optimize(us);
        }));

        std::cout << "\n";
    }

    // Utility benchmarks
    {
        std::cout << "Utility Operations\n";
        std::cout << std::string(75, '-') << "\n";

        std::array<loc::byte, 32> data{};
        for (std::size_t i = 0; i < data.size(); ++i) {
            data[i] = static_cast<loc::byte>(i);
        }

        print_result(run_benchmark("to_hex(32 bytes)", iterations, [&]() {
            auto hex = loc::to_hex(loc::byte_span{data.data(), data.size()});
            do_not_optimize(hex.data());
        }));

        std::string hex_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        print_result(run_benchmark("from_hex(64 chars)", iterations, [&]() {
            auto bytes = loc::from_hex(hex_str);
            do_not_optimize(bytes->data());
        }));

        std::cout << "\n";
    }

    // Buffer pool benchmarks (NEW)
    {
        std::cout << "Buffer Pool Operations\n";
        std::cout << std::string(75, '-') << "\n";

        loc::buffer_pool pool(4096);
        // Pre-populate pool
        for (int i = 0; i < 8; ++i) {
            pool.release(pool.acquire());
        }

        print_result(run_benchmark("buffer_pool acquire+release", iterations, [&]() {
            auto buf = pool.acquire();
            pool.release(std::move(buf));
        }));

        print_result(run_benchmark("vector<byte> allocation (4KB)", iterations, []() {
            std::vector<loc::byte> buf;
            buf.reserve(4096);
            do_not_optimize(buf.data());
        }));

        std::cout << "\n";
    }

    std::cout << std::string(75, '=') << "\n";
    std::cout << "Benchmark complete.\n";

    return 0;
}
