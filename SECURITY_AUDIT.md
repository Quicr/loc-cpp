# Security Audit Report: LOC C++ Library

**Date:** 2026-05-08 (Updated: 2026-05-08)  
**Auditor:** Security Review  
**Scope:** All source files in `include/loc/`, `tests/`, and `examples/`

---

## Executive Summary

This audit examines the LOC (Low Overhead Container) C++ library for memory corruption, information disclosure, and other security vulnerabilities. The library is a header-only implementation for encoding/decoding media metadata containers.

Overall, the code demonstrates good security practices with proper bounds checking and error handling.

**Update:** The HIGH and several MEDIUM findings have been addressed. See "Fixed Issues" section below.

---

## CRITICAL

*No critical vulnerabilities identified.*

---

## HIGH

*All HIGH issues have been fixed. See "Fixed Issues" section.*

---

## MEDIUM

### M-1: Potential Memory Leak on Exception in `property` Copy Constructor

**Status:** Open (Low Risk)

**Location:** `include/loc/loc.hpp:396-403`

**Description:** The copy constructor allocates memory before copying:

```cpp
property(const property& other) : id_(other.id_), is_varint_(other.is_varint_), size_(other.size_) {
    if (size_ <= sbo_size) {
        storage_.inline_data = other.storage_.inline_data;
    } else {
        storage_.heap_data = new byte[size_];  // May throw
        std::copy_n(other.storage_.heap_data, size_, storage_.heap_data);
    }
}
```

If `new` throws `std::bad_alloc`, the object is left in a partially constructed state. While the destructor won't run for a failed constructor, the member initializers have already executed.

**Impact:** In low-memory conditions, could lead to unexpected behavior. The `noexcept` specification is not present, so callers expecting exceptions should be prepared.

**Recommendation:** Consider using `std::make_unique` or a two-phase initialization to ensure exception safety, or mark as `noexcept` with appropriate handling.

---

### M-5: Union with Non-Trivial Member Risks

**Status:** Open (Low Risk)

**Location:** `include/loc/loc.hpp:465-468`

**Description:** The `Storage` union contains both an array and a raw pointer. The pattern is error-prone but currently correctly implemented. The move constructor copies the raw union bytes and properly tracks ownership via `size_`.

**Impact:** Future maintenance risk. If `size_` is not properly maintained, the destructor could attempt to delete inline data or read uninitialized pointer.

**Recommendation:** Consider using `std::variant` or a tagged union pattern with explicit active member tracking for future refactoring.

---

## LOW

### L-1: Missing `noexcept` Verification

**Status:** Open

Move operations are marked `noexcept` which is correct and verified by inspection. No action needed.

---

### L-2: `to_hex` and `from_hex` Use Heap Allocation

**Status:** Open

These utility functions allocate memory and could throw `std::bad_alloc`. They're not marked `noexcept` (correctly), but callers processing untrusted input should be aware of potential allocation failures with large input.

---

### L-3: `errc` Enum Switch Coverage

**Status:** Open

The `to_string(errc)` function has all cases covered plus a fallback. This is defensive and correct.

---

### L-4: Fuzz Test Distribution Bias

**Status:** Open

The fuzzer uses modulo to determine split points, which biases toward smaller values. Consider alternative distributions for better coverage.

---

### L-5: Benchmark Uses Compiler-Specific Features

**Status:** Improved

The benchmark now uses a portable `do_not_optimize()` helper with fallback for non-GCC/Clang compilers.

---

### L-6: Property ID Convention Documentation

**Status:** Open

The even/odd convention for varint vs bytes properties is implicit. Consider documenting prominently.

---

## Fixed Issues

### H-1: Undefined Behavior in `expected<T>` When Accessing Error State ✓ FIXED

**Fix:** Added `assert()` calls to all accessor methods (`operator*`, `operator->`, `value()`) that verify `has_value()` before returning. In debug builds, accessing an error state now triggers an assertion failure with a descriptive message.

---

### H-2: Integer Overflow in `moq_varint::decode` Shift Operation ✓ FIXED

**Fix:** Tightened the overflow check to prevent undefined behavior:
```cpp
// Check for overflow before shifting: at shift=63, only bit 0 can be set
if (shift >= 63 && payload > 1) return errc::overflow;
```
Also changed the loop termination to check `i >= 9` instead of `shift > 63` for clarity.

---

### H-3: Unchecked Result in `property::from_varint` ✓ FIXED

**Fix:** Added assertion before dereferencing:
```cpp
auto result = default_varint::encode(value, buf);
assert(result.has_value() && "varint encoding failed");
p.size_ = *result;
```

---

### M-2: `cursor::advance()` Has No Bounds Check ✓ FIXED

**Fix:** Added bounds check assertion:
```cpp
constexpr void advance(std::size_t n) noexcept {
    assert(n <= data_.size() && "advance beyond end of cursor");
    data_ = data_.subspan(n);
}
```

---

### M-3: `encode_properties` Unconditionally Dereferences Result ✓ FIXED

**Fix:** Added assertion in the encoding loop:
```cpp
auto result = encode_property<Policy>(p, mutable_byte_span{out}.subspan(offset));
assert(result.has_value() && "property encoding failed");
offset += *result;
```

---

### M-4: No Validation of Bitfield Values in Decode Functions ✓ FIXED

**Fix:** Changed `video_frame_marking::decode` and `audio_level::decode` to return `std::optional` and validate that unused bits are zero:
```cpp
[[nodiscard]] static constexpr std::optional<video_frame_marking> decode(std::uint64_t v) noexcept {
    if (v & ~0x1FFULL) return std::nullopt;  // Invalid bits set
    // ...
}
```

---

## New Components Security Notes

The following components were added after the initial audit:

### `buffer_pool`
- Thread safety: NOT thread-safe. Document that each thread should have its own pool, or add external synchronization.
- No memory limits: Pool can grow unbounded if buffers aren't released. The `max_pool_size_` setting only limits reuse, not total allocation.

### `stream_encoder` / `stream_decoder`
- Uses the same bounds-checked primitives as the core library.
- `stream_decoder` stores `property_view` references into the input buffer - callers must ensure the input buffer outlives the decoder.

### `media_frame`
- High-level wrapper that delegates to safe primitives.
- No additional security concerns.

### `group_info`
- Simple POD structure with no security implications.

---

## Positive Security Observations

1. **Good bounds checking**: The varint decoders properly check for truncated input and overflow
2. **Non-minimal encoding rejection**: Both QUIC and MOQ varint decoders reject non-minimal encodings, preventing length-extension attacks
3. **Fuzzing infrastructure**: The project includes fuzzing targets for critical parsing code
4. **No raw pointer arithmetic**: The code uses `std::span` throughout, reducing pointer arithmetic errors
5. **Constexpr where possible**: Many functions are constexpr, enabling compile-time verification
6. **RAII for memory management**: The `property` class properly manages heap memory with copy/move semantics
7. **Defensive assertions**: Debug builds now catch common misuse patterns

---

## Recommendations for Future Development

1. **Add static analysis**: Integrate clang-tidy or similar tools into CI
2. **Add sanitizer runs**: Ensure ASan/UBSan/MSan are run in CI, not just for fuzzing
3. **Consider std::expected**: C++23's `std::expected` provides a more robust error-handling type
4. **Document thread safety**: Clarify which components are thread-safe
5. **Add integer overflow tests**: Explicitly test boundary conditions for all varint sizes
6. **Document lifetime requirements**: `stream_decoder` holds views into input buffers

---

*End of Security Audit Report*
