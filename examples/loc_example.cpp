// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "loc/loc.hpp"

int main() {
    std::cout << "=== Video Frame ===\n";
    {
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
        std::cout << "payload: " << loc::to_hex(encoded.payload_view()) << "\n";

        auto props = loc::collect_properties(encoded.public_view());
        if (props) {
            for (const auto& p : *props) {
                std::cout << "  id=" << p.id;
                if (p.is_varint()) {
                    if (auto v = p.as_varint()) std::cout << " value=" << *v;
                }
                std::cout << "\n";
            }
        }
    }

    std::cout << "\n=== Audio Frame ===\n";
    {
        loc::loc_object frame;
        frame.timescale(48'000ULL)
             .audio_level_info({.level = 42, .voice_activity = true});

        const std::array payload{
            std::byte{0xf1}, std::byte{0x50}, std::byte{0x80}, std::byte{0x00},
        };
        frame.set_payload(loc::byte_span{payload.data(), payload.size()});

        auto encoded = frame.encode();
        std::cout << "public:  " << loc::to_hex(encoded.public_view()) << "\n";
        std::cout << "payload: " << loc::to_hex(encoded.payload_view()) << "\n";

        auto props = loc::collect_properties(encoded.public_view());
        if (props) {
            for (const auto& p : *props) {
                std::cout << "  id=" << p.id;
                if (p.is_varint()) {
                    if (auto v = p.as_varint()) std::cout << " value=" << *v;
                }
                std::cout << "\n";
            }
        }
    }

    return 0;
}
