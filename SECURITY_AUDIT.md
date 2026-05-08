# Security Audit Report: LOC C++ Library

**Date:** 2026-05-08  
**Auditor:** Security Review  
**Scope:** All source files in `include/loc/`, `tests/`, and `examples/`  
**Version:** Post-streaming API additions

---

## Executive Summary

This audit examines the LOC (Low Overhead Container) C++ library for memory corruption, information disclosure, and other security vulnerabilities. The library is a header-only C++20 implementation for encoding/decoding media metadata containers used in Media over QUIC (MoQ) applications.

**Overall Assessment:** The codebase demonstrates strong security practices including proper bounds checking, overflow protection, and defensive assertions. The library uses modern C++ features (`std::span`, `std::byte`, RAII) that inherently reduce common vulnerability classes. No critical vulnerabilities were identified.

---

## CRITICAL

*No critical vulnerabilities identified.*

---

## HIGH

### H-1: `stream_decoder` Stores Dangling References to Input Buffer

**Location:** `include/loc/loc.hpp:1063-1178`

**Description:** The `stream_decoder` class stores `property_view` objects that contain `byte_span` references pointing into the input buffer passed to `parse_public()` and `parse_payload()`. If the caller frees or modifies the input buffer while the decoder is still in use, all stored property views become dangling references.

```cpp
expected<void> parse_public(byte_span public_data) noexcept {
    auto result = decode_properties<Policy>(public_data, [this](const property_view& p) {
        public_props_.push_back(p);  // Stores span pointing into public_data
        return true;
    });
    // ...
}
```

**Impact:** Use-after-free if the input buffer is freed before the decoder. Could lead to information disclosure (reading freed memory) or crashes.

**Recommendation:** 
1. Document the lifetime requirement prominently in the class documentation
2. Consider adding a mode that copies property data into owned storage
3. Consider using `std::shared_ptr` or similar to ensure buffer lifetime

---

### H-2: `buffer_pool` Is Not Thread-Safe

**Location:** `include/loc/loc.hpp:827-856`

**Description:** The `buffer_pool` class uses a `std::vector` for storage without any synchronization primitives. If multiple threads call `acquire()` or `release()` concurrently, data races will occur.

```cpp
[[nodiscard]] std::vector<byte> acquire() {
    if (!pool_.empty()) {
        auto buf = std::move(pool_.back());  // Data race if concurrent access
        pool_.pop_back();
        // ...
    }
}
```

**Impact:** Data races leading to undefined behavior, potential memory corruption, or double-free vulnerabilities in multi-threaded media pipelines.

**Recommendation:**
1. Add mutex protection for thread-safe operation
2. Or document clearly that each thread must have its own pool instance
3. Consider providing both thread-safe and single-threaded variants

---

### H-3: Integer Overflow in `media_time` Arithmetic Operations

**Location:** `include/loc/loc.hpp:790-821`

**Description:** The `media_time` conversion functions perform multiplication before division without overflow checking:

```cpp
[[nodiscard]] static constexpr media_time from_us(std::uint64_t microseconds, std::uint64_t scale = 1'000'000) noexcept {
    return {microseconds * scale / 1'000'000, scale};  // Overflow if microseconds * scale > 2^64
}

[[nodiscard]] constexpr std::uint64_t to_us() const noexcept {
    return ticks * 1'000'000 / timescale;  // Overflow possible
}

[[nodiscard]] constexpr media_time convert_to(std::uint64_t new_scale) const noexcept {
    return {ticks * new_scale / timescale, new_scale};  // Overflow possible
}
```

**Impact:** With large timestamp values (common in long-running streams), multiplication overflow causes incorrect timestamps. For a 90kHz video at ~5.7 hours, `ticks * 1'000'000` overflows uint64.

**Recommendation:** Use 128-bit intermediate arithmetic or reorder operations:
```cpp
return {microseconds / 1'000'000 * scale + (microseconds % 1'000'000) * scale / 1'000'000, scale};
```

---

## MEDIUM

### M-1: Assertions Used for Runtime Validation in Release Builds

**Location:** Multiple locations including `loc.hpp:72-105`, `300-302`, `375`, `534`, `1048`

**Description:** The code uses `assert()` for validation that should occur at runtime. In release builds (with `NDEBUG` defined), these checks are removed, potentially allowing undefined behavior.

```cpp
constexpr void advance(std::size_t n) noexcept {
    assert(n <= data_.size() && "advance beyond end of cursor");  // Gone in release
    data_ = data_.subspan(n);  // UB if n > size in release
}
```

**Impact:** Security checks are bypassed in release builds. Malicious input could trigger undefined behavior that was protected in debug builds.

**Recommendation:** Replace security-critical assertions with runtime checks that remain in release builds:
```cpp
if (n > data_.size()) std::terminate();  // Or throw, or return error
```

---

### M-2: Potential Memory Exhaustion via Large Property Length

**Location:** `include/loc/loc.hpp:556-559`

**Description:** When decoding byte properties, the length is read as a varint and then used to read that many bytes:

```cpp
auto len_result = c.read_varint<Policy>();
if (!len_result) return len_result.error();
auto bytes_result = c.read_bytes(*len_result);  // len_result could be huge
```

While `read_bytes` checks bounds against the input buffer, a malicious encoder could craft input that causes `collect_properties` to allocate a large vector of `property_view` objects by including many small properties.

**Impact:** Memory exhaustion denial of service by crafting input with millions of tiny properties.

**Recommendation:** Add configurable limits on:
1. Maximum number of properties per decode operation
2. Maximum total decoded size

---

### M-3: `encoded_result` Destructor May Access Invalid Pool Pointer

**Location:** `include/loc/loc.hpp:948-989`

**Description:** The `encoded_result` stores a raw pointer to a `buffer_pool`. If the pool is destroyed before the `encoded_result`, the destructor will call methods on a dangling pointer.

```cpp
~encoded_result() { release(); }

void release() {
    if (pool) {
        pool->release(std::move(public_properties));  // pool may be dangling
        // ...
    }
}
```

**Impact:** Use-after-free when pool is destroyed before encoded results. Could cause crashes or memory corruption.

**Recommendation:** Use `std::weak_ptr` or document lifetime requirements clearly. Consider having `encoded_result` not automatically release to pool on destruction.

---

### M-4: No Maximum Recursion/Nesting Depth for Property Parsing

**Location:** `include/loc/loc.hpp:540-568`

**Description:** The property decoding doesn't limit the complexity of input. While not directly recursive, deeply nested or malformed data structures could consume excessive stack or heap.

**Impact:** Stack exhaustion or excessive memory use with crafted input.

**Recommendation:** Add depth/count limits to parsing operations.

---

### M-5: Potential Division by Zero in `media_time`

**Location:** `include/loc/loc.hpp:810-819`

**Description:** The `media_time` struct initializes `timescale` to 1, but there's no enforcement preventing it from being set to 0:

```cpp
struct media_time {
    std::uint64_t ticks{0};
    std::uint64_t timescale{1};
    
    [[nodiscard]] constexpr std::uint64_t to_us() const noexcept {
        return ticks * 1'000'000 / timescale;  // Division by zero if timescale == 0
    }
```

**Impact:** Undefined behavior (typically crash) if timescale is 0.

**Recommendation:** Add validation or use a safe division helper that handles zero.

---

## LOW

### L-1: `to_hex` and `from_hex` Allocate Without Size Limits

**Location:** `include/loc/loc.hpp:752-784`

**Description:** These utility functions allocate based on input size without limits. `to_hex` doubles the size, `from_hex` allocates half.

**Impact:** Large inputs could cause allocation failure. Low severity as these are utility functions.

**Recommendation:** Document maximum expected sizes or add optional limits.

---

### L-2: Missing `[[nodiscard]]` on Some Error-Returning Functions

**Location:** Various

**Description:** Some functions that return `expected<void>` or error indicators should have `[[nodiscard]]` to prevent silently ignored errors.

**Impact:** Errors might be silently ignored, leading to incorrect program state.

**Recommendation:** Add `[[nodiscard]]` consistently to all error-returning functions.

---

### L-3: Property ID Convention Not Enforced at Construction

**Location:** `include/loc/loc.hpp:368-398`

**Description:** The even/odd ID convention for varint/bytes properties is only checked at encoding time, not at property construction:

```cpp
// This silently creates an invalid property (odd ID for varint)
auto bad = loc::property::from_varint(13, 42);  // ID 13 is odd (bytes type)
// Error only detected at encode time
```

**Impact:** Runtime errors that could be caught earlier at construction.

**Recommendation:** Consider validating ID/type consistency at construction time.

---

### L-4: Fuzz Test Coverage Could Be Expanded

**Location:** `tests/fuzz/`

**Description:** The fuzzing targets cover varint, properties, and LOC objects, but don't cover:
- `stream_encoder` / `stream_decoder`
- `media_time` operations
- `buffer_pool` operations
- `media_frame` construction

**Impact:** Potential bugs in newer components not discovered by fuzzing.

**Recommendation:** Add fuzz targets for new streaming API components.

---

### L-5: No Constant-Time Comparison for Sensitive Data

**Location:** N/A

**Description:** The library doesn't handle secrets, but if used in contexts where property values are sensitive, the lack of constant-time comparison could leak information.

**Impact:** Timing side-channels if used with sensitive data. Low severity as this is a media container library.

**Recommendation:** Document that the library is not designed for cryptographic or secret data handling.

---

### L-6: Bitfield Layout Is Implementation-Defined

**Location:** `include/loc/loc.hpp:585-590`, `617-619`

**Description:** The `video_frame_marking` and `audio_level` structs use bitfields:

```cpp
struct video_frame_marking {
    bool independent : 1 {false};
    bool discardable : 1 {false};
    // ...
};
```

Bitfield layout is implementation-defined in C++. While the encode/decode functions don't rely on the memory layout, the struct size might vary.

**Impact:** No direct security impact as serialization is explicit. Minor portability concern.

**Recommendation:** No action needed; the explicit encode/decode functions handle serialization correctly.

---

## Positive Security Observations

1. **Proper bounds checking**: All buffer accesses use `std::span` with bounds-checked operations
2. **Overflow protection**: Varint decoders properly check for integer overflow before shifting
3. **Non-minimal encoding rejection**: Both QUIC and MOQ varint decoders reject non-canonical encodings
4. **RAII memory management**: `property` class properly manages heap allocations
5. **Defensive assertions**: Debug builds catch common programming errors
6. **Fuzzing infrastructure**: Project includes fuzz targets for critical parsing code
7. **No raw pointer arithmetic**: Modern C++ containers and spans used throughout
8. **Explicit error handling**: `expected<T>` type forces callers to handle errors

---

## Recommendations Summary

### Immediate Actions (Before Production Use)
1. Document `stream_decoder` lifetime requirements prominently
2. Document `buffer_pool` thread-safety limitations
3. Fix integer overflow in `media_time` arithmetic

### Short-Term Improvements
1. Add runtime checks (not just assertions) for security-critical validations
2. Add limits to property parsing to prevent resource exhaustion
3. Fix potential division by zero in `media_time`

### Long-Term Improvements
1. Add thread-safe `buffer_pool` variant
2. Expand fuzz testing to cover streaming API
3. Consider `std::expected` (C++23) migration for better error handling

---

*End of Security Audit Report*
