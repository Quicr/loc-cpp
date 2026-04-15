// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// LOC Benchmarks
// Build with: clang++ -O3 -std=c++20 benchmark.cpp -I../../include -o benchmark

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
    std::cout << std::left << std::setw(40) << r.name
              << std::right << std::setw(12) << std::fixed << std::setprecision(1) << r.ns_per_op << " ns/op"
              << std::setw(15) << std::fixed << std::setprecision(0) << r.ops_per_sec << " ops/sec"
              << "\n";
}

}  // namespace

int main() {
    constexpr std::size_t iterations = 1'000'000;

    std::cout << "\nLOC Benchmark Results\n";
    std::cout << std::string(70, '=') << "\n\n";

    // Varint encoding benchmarks
    {
        std::cout << "Varint Encoding\n";
        std::cout << std::string(70, '-') << "\n";

        print_result(run_benchmark("quic_varint::encode(42)", iterations, []() {
            auto result = loc::encode_varint<loc::quic_varint>(42);
            asm volatile("" : : "r"(result.data()) : "memory");
        }));

        print_result(run_benchmark("quic_varint::encode(16383)", iterations, []() {
            auto result = loc::encode_varint<loc::quic_varint>(16383);
            asm volatile("" : : "r"(result.data()) : "memory");
        }));

        print_result(run_benchmark("quic_varint::encode(1073741823)", iterations, []() {
            auto result = loc::encode_varint<loc::quic_varint>(1073741823);
            asm volatile("" : : "r"(result.data()) : "memory");
        }));

        print_result(run_benchmark("moq_varint::encode(42)", iterations, []() {
            auto result = loc::encode_varint<loc::moq_varint>(42);
            asm volatile("" : : "r"(result.data()) : "memory");
        }));

        print_result(run_benchmark("moq_varint::encode(16383)", iterations, []() {
            auto result = loc::encode_varint<loc::moq_varint>(16383);
            asm volatile("" : : "r"(result.data()) : "memory");
        }));

        std::cout << "\n";
    }

    // Varint decoding benchmarks
    {
        std::cout << "Varint Decoding\n";
        std::cout << std::string(70, '-') << "\n";

        auto quic_1byte = loc::encode_varint<loc::quic_varint>(42);
        auto quic_2byte = loc::encode_varint<loc::quic_varint>(16383);
        auto quic_4byte = loc::encode_varint<loc::quic_varint>(1073741823);

        print_result(run_benchmark("quic_varint::decode(1 byte)", iterations, [&]() {
            loc::byte_span span{quic_1byte.data(), quic_1byte.size()};
            auto result = loc::decode_varint<loc::quic_varint>(span);
            asm volatile("" : : "r"(*result) : "memory");
        }));

        print_result(run_benchmark("quic_varint::decode(2 bytes)", iterations, [&]() {
            loc::byte_span span{quic_2byte.data(), quic_2byte.size()};
            auto result = loc::decode_varint<loc::quic_varint>(span);
            asm volatile("" : : "r"(*result) : "memory");
        }));

        print_result(run_benchmark("quic_varint::decode(4 bytes)", iterations, [&]() {
            loc::byte_span span{quic_4byte.data(), quic_4byte.size()};
            auto result = loc::decode_varint<loc::quic_varint>(span);
            asm volatile("" : : "r"(*result) : "memory");
        }));

        auto moq_1byte = loc::encode_varint<loc::moq_varint>(42);
        auto moq_2byte = loc::encode_varint<loc::moq_varint>(16383);

        print_result(run_benchmark("moq_varint::decode(1 byte)", iterations, [&]() {
            loc::byte_span span{moq_1byte.data(), moq_1byte.size()};
            auto result = loc::decode_varint<loc::moq_varint>(span);
            asm volatile("" : : "r"(*result) : "memory");
        }));

        print_result(run_benchmark("moq_varint::decode(2 bytes)", iterations, [&]() {
            loc::byte_span span{moq_2byte.data(), moq_2byte.size()};
            auto result = loc::decode_varint<loc::moq_varint>(span);
            asm volatile("" : : "r"(*result) : "memory");
        }));

        std::cout << "\n";
    }

    // Property benchmarks
    {
        std::cout << "Property Operations\n";
        std::cout << std::string(70, '-') << "\n";

        print_result(run_benchmark("property::from_varint", iterations, []() {
            auto prop = loc::property::from_varint(loc::property_id::timestamp, 1716123456ULL);
            asm volatile("" : : "r"(prop.data().data()) : "memory");
        }));

        std::array<loc::byte, 64> bytes{};
        print_result(run_benchmark("property::from_bytes(64)", iterations, [&]() {
            auto prop = loc::property::from_bytes(loc::property_id::video_config,
                                                   loc::byte_span{bytes.data(), bytes.size()});
            asm volatile("" : : "r"(prop.data().data()) : "memory");
        }));

        auto props = std::array{
            loc::property::from_varint(loc::property_id::timestamp, 1716123456ULL),
            loc::property::from_varint(loc::property_id::timescale, 90000ULL),
            loc::property::from_varint(loc::property_id::video_frame_marking, 7ULL),
        };

        print_result(run_benchmark("encode_properties(3 props)", iterations, [&]() {
            auto encoded = loc::encode_properties(std::span{props});
            asm volatile("" : : "r"(encoded.data()) : "memory");
        }));

        auto encoded_props = loc::encode_properties(std::span{props});
        print_result(run_benchmark("collect_properties(3 props)", iterations, [&]() {
            auto decoded = loc::collect_properties(loc::byte_span{encoded_props.data(), encoded_props.size()});
            asm volatile("" : : "r"(decoded->data()) : "memory");
        }));

        std::cout << "\n";
    }

    // LOC object benchmarks
    {
        std::cout << "LOC Object Operations\n";
        std::cout << std::string(70, '-') << "\n";

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
            asm volatile("" : : "r"(encoded.public_view().data()) : "memory");
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
            asm volatile("" : : "r"(decoded->payload.data()) : "memory");
        }));

        std::cout << "\n";
    }

    // Utility benchmarks
    {
        std::cout << "Utility Operations\n";
        std::cout << std::string(70, '-') << "\n";

        std::array<loc::byte, 32> data{};
        for (std::size_t i = 0; i < data.size(); ++i) {
            data[i] = static_cast<loc::byte>(i);
        }

        print_result(run_benchmark("to_hex(32 bytes)", iterations, [&]() {
            auto hex = loc::to_hex(loc::byte_span{data.data(), data.size()});
            asm volatile("" : : "r"(hex.data()) : "memory");
        }));

        std::string hex_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        print_result(run_benchmark("from_hex(64 chars)", iterations, [&]() {
            auto bytes = loc::from_hex(hex_str);
            asm volatile("" : : "r"(bytes->data()) : "memory");
        }));

        std::cout << "\n";
    }

    std::cout << std::string(70, '=') << "\n";
    std::cout << "Benchmark complete.\n";

    return 0;
}
