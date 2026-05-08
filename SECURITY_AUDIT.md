# Security Audit Report: LOC C++ Library

**Date:** 2026-05-08  
**Auditor:** Security Review  
**Scope:** All source files in `include/loc/`, `tests/`, and `examples/`

---

## Executive Summary

This audit examines the LOC (Low Overhead Container) C++ library for memory corruption, information disclosure, and other security vulnerabilities. The library is a header-only implementation for encoding/decoding media metadata containers.

Overall, the code demonstrates good security practices with proper bounds checking and error handling. However, several issues were identified that warrant attention.

---

## CRITICAL

*No critical vulnerabilities identified.*

---

## HIGH

### H-1: Undefined Behavior in `expected<T>` When Accessing Error State

**Location:** `include/loc/loc.hpp:71-80`

**Description:** The `expected<T>` class allows dereferencing (`operator*`, `operator->`, `value()`) when the object is in an error state. This returns a reference to a default-constructed `T`, but the caller has no indication this is invalid data.

```cpp
[[nodiscard]] constexpr T& operator*() & noexcept { return value_; }
[[nodiscard]] constexpr T& value() & noexcept { return value_; }
```

**Impact:** If a caller fails to check `has_value()` before accessing the value, they will silently receive a default-constructed value (e.g., `0` for integers). In security-sensitive contexts, this could lead to logic errors where error conditions are masked as valid zero/empty values.

**Recommendation:** Either:
1. Add runtime assertions in debug builds when accessing error state
2. Document this behavior prominently
3. Consider throwing or terminating when value is accessed in error state (breaking API change)

---

### H-2: Integer Overflow Potential in `moq_varint::decode` Shift Operation

**Location:** `include/loc/loc.hpp:195-196`

**Description:** The shift overflow check occurs after the potentially-overflowing shift:

```cpp
if (shift >= 64 && (b & 0x7F) != 0) return errc::overflow;
v |= static_cast<std::uint64_t>(b & 0x7F) << shift;
```

When `shift == 63` and `b & 0x7F` has its high bit set (e.g., `0x40`), the left shift `0x40 << 63` overflows because the result would require 70 bits. While the current check at `shift >= 64` catches bytes 10+, the 10th byte (when shift=63) can still cause undefined behavior for certain bit patterns.

**Impact:** Potential undefined behavior when parsing maliciously crafted varint data with specific bit patterns in the 10th byte.

**Recommendation:** Tighten the overflow check:
```cpp
if (shift >= 63 && (b & 0x7F) > 1) return errc::overflow;
```

---

### H-3: Unchecked Result in `property::from_varint`

**Location:** `include/loc/loc.hpp:336-337`

**Description:** The result of `encode()` is dereferenced without checking for success:

```cpp
auto result = default_varint::encode(value, buf);
p.size_ = *result;  // No check if result.has_value()
```

While `encode` should always succeed for valid uint64 values with QUIC varint (within max_value), using MOQ varint mode (which supports full uint64 range) should be safe. However, the unconditional dereference is a code smell.

**Impact:** If the varint policy changes or edge cases exist, this could dereference an error state.

**Recommendation:** Add an assertion or explicit check:
```cpp
auto result = default_varint::encode(value, buf);
assert(result.has_value());  // Always succeeds for valid input
p.size_ = *result;
```

---

## MEDIUM

### M-1: Potential Memory Leak on Exception in `property` Copy Constructor

**Location:** `include/loc/loc.hpp:362-369`

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

### M-2: `cursor::advance()` Has No Bounds Check

**Location:** `include/loc/loc.hpp:270`

**Description:** The `advance()` method directly calls `subspan(n)` without checking if `n > size()`:

```cpp
constexpr void advance(std::size_t n) noexcept { data_ = data_.subspan(n); }
```

Per the C++ standard, calling `subspan(n)` where `n > size()` is undefined behavior.

**Impact:** If a caller passes an invalid value to `advance()`, undefined behavior occurs. While internal uses appear safe, this is a public API that could be misused.

**Recommendation:** Add bounds checking or document the precondition:
```cpp
constexpr void advance(std::size_t n) noexcept {
    assert(n <= data_.size());
    data_ = data_.subspan(n);
}
```

---

### M-3: `encode_properties` Unconditionally Dereferences Result

**Location:** `include/loc/loc.hpp:494-495`

**Description:** The encoding loop dereferences without checking:

```cpp
for (const auto& p : props) {
    auto result = encode_property<Policy>(p, mutable_byte_span{out}.subspan(offset));
    offset += *result;  // Assumes success
}
```

**Impact:** If `encode_property` fails (e.g., type mismatch), this would dereference an error state. While the size calculation should ensure sufficient space, a type mismatch could still occur.

**Recommendation:** Propagate errors or assert:
```cpp
auto result = encode_property<Policy>(p, ...);
if (!result) return {};  // Or handle error
offset += *result;
```

---

### M-4: No Validation of Bitfield Values in `video_frame_marking::decode`

**Location:** `include/loc/loc.hpp:560-568`

**Description:** The `decode` function accepts any uint64_t and extracts bitfields without validating that unused bits are zero:

```cpp
static constexpr video_frame_marking decode(std::uint64_t v) noexcept {
    return {
        .independent = (v & 1) != 0,
        // ... upper bits silently ignored
    };
}
```

**Impact:** Data with garbage in upper bits will decode without error, potentially masking data corruption or malicious manipulation.

**Recommendation:** Consider validating that bits 9+ are zero:
```cpp
if (v & ~0x1FFULL) return std::nullopt;  // Invalid bits set
```

---

### M-5: Union with Non-Trivial Member Risks

**Location:** `include/loc/loc.hpp:431-434`

**Description:** The `Storage` union contains both an array and a raw pointer:

```cpp
union Storage {
    std::array<byte, sbo_size> inline_data{};
    byte* heap_data;
} storage_;
```

The union is initialized with `inline_data{}`, but when switching to heap storage, the code directly assigns to `heap_data`. This is technically valid in C++, but the pattern is error-prone and the move constructor copies the raw union bytes:

```cpp
property(property&& other) noexcept
    : id_(other.id_), is_varint_(other.is_varint_), size_(other.size_), storage_(other.storage_) {
    other.size_ = 0;
}
```

**Impact:** If `size_` is not properly maintained, the destructor could attempt to delete inline data or read uninitialized pointer.

**Recommendation:** Consider using `std::variant` or a tagged union pattern with explicit active member tracking.

---

## LOW

### L-1: Missing `noexcept` on Move Operations That Cannot Throw

**Location:** `include/loc/loc.hpp:371-374, 384-392`

**Description:** While the move constructor and move assignment are marked `noexcept`, verifying they truly cannot throw requires analysis. The copy-swap idiom in copy assignment (`property tmp(other)`) can throw, but that's expected.

**Impact:** Move operations being non-throwing is important for STL container efficiency. Current marking appears correct.

**Recommendation:** No change needed, but consider adding a static_assert to verify noexcept status.

---

### L-2: `to_hex` and `from_hex` Use Heap Allocation

**Location:** `include/loc/loc.hpp:708-740`

**Description:** These utility functions allocate memory and could throw `std::bad_alloc`. They're not marked `noexcept` (correctly), but callers processing untrusted input should be aware.

**Impact:** A malicious input with large size could trigger allocation failures.

**Recommendation:** Consider adding size limits or documenting maximum expected sizes.

---

### L-3: `errc` Enum Switch Missing Default in Production

**Location:** `include/loc/loc.hpp:48-58`

**Description:** The `to_string(errc)` function has a switch with all cases covered plus a fallback `return "unknown error"`. This is good, but if new error codes are added and the switch isn't updated, the compiler may not warn (depending on settings).

**Impact:** Future maintenance risk only.

**Recommendation:** Consider `[[unlikely]]` attribute on the unreachable path or static_assert on enum completeness.

---

### L-4: Fuzz Test Truncation May Miss Edge Cases

**Location:** `tests/fuzz/loc_object_fuzz.cpp:17-18`

**Description:** The fuzzer uses modulo to determine split points:

```cpp
std::size_t public_len = data[0] % (size - 2);
std::size_t private_len = data[1] % (size - 2 - public_len);
```

This biases toward smaller values and may not effectively test large property/payload combinations.

**Impact:** Reduced fuzz coverage for certain edge cases.

**Recommendation:** Consider alternative distributions or multiple fuzzing strategies.

---

### L-5: Benchmark Uses `asm volatile` Which Is Compiler-Specific

**Location:** `tests/bench/benchmark.cpp:74, 79, etc.`

**Description:** The benchmark uses GCC/Clang-specific inline assembly:

```cpp
asm volatile("" : : "r"(result.data()) : "memory");
```

**Impact:** Benchmark won't compile on MSVC or other compilers.

**Recommendation:** Use `std::atomic_signal_fence` or compiler-specific macros for portability.

---

### L-6: Property ID Validation Relies on Convention Only

**Location:** `include/loc/loc.hpp:303-305`

**Description:** The even/odd convention for varint vs bytes properties is implicit:

```cpp
[[nodiscard]] constexpr bool is_varint_property(std::uint64_t id) noexcept {
    return (id & 1) == 0;
}
```

**Impact:** Users creating custom property IDs could accidentally violate this convention with no warning until encoding fails.

**Recommendation:** Consider documenting this prominently or providing factory functions that enforce the convention.

---

## Positive Security Observations

1. **Good bounds checking**: The varint decoders properly check for truncated input and overflow
2. **Non-minimal encoding rejection**: Both QUIC and MOQ varint decoders reject non-minimal encodings, preventing length-extension attacks
3. **Fuzzing infrastructure**: The project includes fuzzing targets for critical parsing code
4. **No raw pointer arithmetic**: The code uses `std::span` throughout, reducing pointer arithmetic errors
5. **Constexpr where possible**: Many functions are constexpr, enabling compile-time verification
6. **RAII for memory management**: The `property` class properly manages heap memory with copy/move semantics

---

## Recommendations for Future Development

1. **Add static analysis**: Integrate clang-tidy or similar tools into CI
2. **Add sanitizer runs**: Ensure ASan/UBSan/MSan are run in CI, not just for fuzzing
3. **Consider std::expected**: C++23's `std::expected` provides a more robust error-handling type
4. **Document threat model**: Clarify what inputs are trusted vs untrusted
5. **Add integer overflow tests**: Explicitly test boundary conditions for all varint sizes

---

*End of Security Audit Report*
