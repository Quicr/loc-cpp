# loc++

Header-only C++20 implementation of [LOC (Low Overhead Container)](https://github.com/moq-wg/loc) for Media over QUIC.

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

## Building

```bash
cmake -B build -DLOC_BUILD_TESTS=ON -DLOC_BUILD_EXAMPLES=ON
cmake --build build
ctest --test-dir build
```

Or with just: `just build && just test`

## API

### Varint Encoding

```cpp
// QUIC varint (default) or MOQ varint
auto encoded = loc::encode_varint(12345);
auto quic = loc::encode_varint<loc::quic_varint>(12345);
auto moq = loc::encode_varint<loc::moq_varint>(12345);
```

### Properties

```cpp
// Varint property (even IDs) / Bytes property (odd IDs)
auto ts = loc::property::from_varint(loc::property_id::timestamp, 90000);
auto cfg = loc::property::from_bytes(loc::property_id::video_config, config_span);

// Decode
auto props = loc::collect_properties(encoded_data);
```

### Media Metadata

```cpp
loc::video_frame_marking fm{.independent = true, .discardable = false};
loc::audio_level level{.level = 42, .voice_activity = true};
```

## Configuration

Use MOQ varint encoding instead of QUIC varint:

```cpp
#define LOC_USE_MOQ_VARINT
#include "loc/loc.hpp"
```

## License

BSD-2-Clause. See [LICENSE](LICENSE).
