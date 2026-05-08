<p align="center">
  <img src="docs/loc-logo.svg" alt="LOC++ Logo" width="280">
  <br><br>
  <a href="https://github.com/Quicr/loc-cpp/actions/workflows/ci.yml"><img src="https://github.com/Quicr/loc-cpp/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
</p>

Header-only C++20 implementation of [LOC (Low Overhead Container)](https://github.com/moq-wg/loc) for Media over QUIC.

## Features

- Zero-copy decoding with `byte_span` views
- High-performance streaming API with buffer pooling
- QUIC and MOQ varint encoding support
- Timestamp utilities for media timescales (90kHz, 48kHz, etc.)
- Comprehensive error handling with `expected<T>`

## Quick Start

```cpp
#include "loc/loc.hpp"

// Build a video frame with metadata
loc::loc_object frame;
frame.timestamp(1716123456ULL)
     .timescale(90000ULL)
     .frame_marking({.independent = true, .base_layer_sync = true});

frame.set_payload(your_payload_data);

// Encode to wire format
auto encoded = frame.encode();
// encoded.public_view()  -> public properties (visible to relays)
// encoded.payload_view() -> private properties + payload
```

## High-Performance Streaming API

For media pipelines requiring maximum throughput, use the streaming encoder with buffer pooling:

```cpp
// Create a buffer pool (reuses allocations)
loc::buffer_pool pool(4096);
loc::stream_encoder encoder(&pool);

// Encode frames with automatic buffer reuse
encoder.timestamp(loc::media_time::from_90khz(pts))
       .frame_marking({.independent = is_keyframe})
       .set_group({.group_id = gop_id, .sequence = seq})
       .set_payload(nal_units);

auto result = encoder.encode();
send_to_quic(result.public_view(), result.payload_view());

// Reuse encoder for next frame (15M+ ops/sec)
encoder.reset();
```

### Stream Decoder

```cpp
loc::stream_decoder decoder;

// Parse incrementally
decoder.parse_public(public_data);
decoder.parse_payload(payload_data, private_length);

// Access metadata with convenient getters
if (auto time = decoder.get_media_time()) {
    std::cout << "PTS: " << time->to_ms() << " ms\n";
}
if (auto marking = decoder.get_frame_marking()) {
    std::cout << "Keyframe: " << marking->independent << "\n";
}
```

### Media Frame Helper

```cpp
// High-level video frame construction
auto frame = loc::media_frame::video(
    loc::media_time::from_90khz(pts),
    {.independent = true, .base_layer_sync = true}
);
frame.set_group({.group_id = 1, .sequence = 0, .priority = 0});
frame.set_payload(h264_nal_units);

auto obj = frame.to_loc_object();
auto encoded = obj.encode();
```

## Building

```bash
cmake -B build -DLOC_BUILD_TESTS=ON -DLOC_BUILD_EXAMPLES=ON
cmake --build build
ctest --test-dir build
```

Or with just: `just build && just test`

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `LOC_BUILD_TESTS` | OFF | Build unit and integration tests |
| `LOC_BUILD_EXAMPLES` | OFF | Build examples |
| `LOC_BUILD_BENCHMARKS` | OFF | Build performance benchmarks |
| `LOC_USE_MOQ_VARINT` | OFF | Use MOQ varint instead of QUIC varint |

## API Reference

### Timestamp Utilities

```cpp
// Create from various timescales
auto video_time = loc::media_time::from_90khz(90000);    // 1 second at 90kHz
auto audio_time = loc::media_time::from_48khz(48000);    // 1 second at 48kHz
auto from_us = loc::media_time::from_us(33333, 90000);   // 33.3ms in 90kHz ticks

// Convert between timescales
auto converted = video_time.convert_to(48000);  // 90kHz -> 48kHz

// Convert to common units
auto microseconds = video_time.to_us();
auto milliseconds = video_time.to_ms();
```

### Varint Encoding

```cpp
// QUIC varint (default, 62-bit max) or MOQ varint (64-bit, LEB128)
auto encoded = loc::encode_varint(12345);
auto quic = loc::encode_varint<loc::quic_varint>(12345);
auto moq = loc::encode_varint<loc::moq_varint>(12345);
```

### Properties

```cpp
// Varint property (even IDs) / Bytes property (odd IDs)
auto ts = loc::property::from_varint(loc::property_id::timestamp, 90000);
auto cfg = loc::property::from_bytes(loc::property_id::video_config, config_span);

// Decode properties
auto props = loc::collect_properties(encoded_data);
for (const auto& p : *props) {
    if (p.is_varint()) {
        auto val = p.as_varint();
    }
}
```

### Media Metadata

```cpp
// Video frame marking (SVC layers, dependencies)
loc::video_frame_marking fm{
    .independent = true,      // Keyframe
    .discardable = false,
    .base_layer_sync = true,
    .temporal_id = 0,
    .spatial_id = 0
};

// Audio level (RFC 6464)
loc::audio_level level{.level = 42, .voice_activity = true};

// Group/sequence info (for selective forwarding)
loc::group_info group{
    .group_id = 1,
    .subgroup_id = 0,
    .sequence = 100,
    .priority = 0,
    .delivery_timeout_ms = 200
};
```

### Property IDs

| ID | Name | Type | Description |
|----|------|------|-------------|
| 4 | `video_frame_marking` | varint | SVC layer info |
| 6 | `timestamp` | varint | Presentation timestamp |
| 8 | `timescale` | varint | Ticks per second |
| 10 | `audio_level` | varint | Audio level + VAD |
| 12 | `sequence_number` | varint | Frame sequence |
| 13 | `video_config` | bytes | Codec configuration |
| 14 | `group_id` | varint | Group identifier |
| 16 | `subgroup_id` | varint | Subgroup identifier |
| 18 | `priority` | varint | Delivery priority |
| 20 | `delivery_timeout` | varint | Timeout in ms |

## Performance

Benchmark results (Apple M1):

| Operation | Throughput |
|-----------|------------|
| `stream_encoder` (reuse + pool) | 15.4M ops/sec |
| `stream_decoder` full decode | 17.5M ops/sec |
| `buffer_pool` acquire/release | 403M ops/sec |
| `quic_varint::decode` (1 byte) | 4.0B ops/sec |
| `collect_properties` (3 props) | 17.8M ops/sec |

Run benchmarks: `cmake -B build -DLOC_BUILD_BENCHMARKS=ON && cmake --build build && ./build/loc_benchmark`

## Configuration

Use MOQ varint encoding instead of QUIC varint:

```cpp
#define LOC_USE_MOQ_VARINT
#include "loc/loc.hpp"
```

Or via CMake: `-DLOC_USE_MOQ_VARINT=ON`

## License

BSD-2-Clause. See [LICENSE](LICENSE).
