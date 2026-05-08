# Security Audit Report: LOC C++ Library

**Date:** 2026-05-08  
**Auditor:** Security Review  
**Scope:** All source files in `include/loc/`, `tests/`, and `examples/`  
**Version:** Post-security remediation

---

## Executive Summary

This audit examines the LOC (Low Overhead Container) C++ library for memory corruption, information disclosure, and other security vulnerabilities. The library is a header-only C++20 implementation for encoding/decoding media metadata containers used in Media over QUIC (MoQ) applications.

**Overall Assessment:** The codebase demonstrates strong security practices including proper bounds checking, overflow protection, and defensive runtime checks. The library uses modern C++ features (`std::span`, `std::byte`, RAII) that inherently reduce common vulnerability classes. All HIGH and MEDIUM severity issues from the previous audit have been remediated.

---

## CRITICAL

*No critical vulnerabilities identified.*

---

## HIGH

*All HIGH severity issues have been remediated.*

### H-1: ~~`stream_decoder` Stores Dangling References to Input Buffer~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** The `stream_decoder` class now uses `owned_property` objects that copy all property data into owned storage. The decoder no longer holds references to input buffers, eliminating the use-after-free risk.

---

### H-2: ~~`buffer_pool` Is Not Thread-Safe~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** 
- The `buffer_pool` class is now thread-safe with mutex protection
- A single-threaded variant `buffer_pool_st` is provided for performance-critical single-threaded code
- Documentation clearly indicates thread-safety guarantees

---

### H-3: ~~Integer Overflow in `media_time` Arithmetic Operations~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** All `media_time` conversion functions now use `safe_scale()` which employs 128-bit intermediate arithmetic (via `__int128` on supported platforms or manual 64x64→128 multiplication) to prevent overflow. Division by zero is also guarded.

---

## MEDIUM

*All MEDIUM severity issues have been remediated.*

### M-1: ~~Assertions Used for Runtime Validation in Release Builds~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** Security-critical operations like `cursor::advance()` now return `bool` to indicate success/failure rather than using assertions. Callers handle errors appropriately in release builds.

---

### M-2: ~~Potential Memory Exhaustion via Large Property Length~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** Added `decode_limits` struct with configurable limits:
- `max_properties`: Maximum number of properties (default: 1000)
- `max_total_bytes`: Maximum total decoded bytes (default: 1MB)

Both `decode_properties()` and `collect_properties()` accept optional limits and return `errc::limit_exceeded` when exceeded.

---

### M-3: ~~`encoded_result` Destructor May Access Invalid Pool Pointer~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** The `encoded_result` no longer stores a pool pointer or auto-releases on destruction. Callers must explicitly call `release_to(pool)` to return buffers to a pool. This eliminates the dangling pointer risk entirely.

---

### M-4: ~~No Maximum Recursion/Nesting Depth for Property Parsing~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** The `decode_limits` mechanism (see M-2) limits the number of properties that can be parsed, preventing resource exhaustion attacks.

---

### M-5: ~~Potential Division by Zero in `media_time`~~ **[FIXED]**

**Status:** Remediated

**Fix Applied:** The `safe_scale()` function returns 0 when timescale is 0, avoiding undefined behavior. This is documented as a degenerate case.

---

## LOW

### L-1: `to_hex` and `from_hex` Allocate Without Size Limits

**Location:** `include/loc/loc.hpp`

**Description:** These utility functions allocate based on input size without limits.

**Status:** Open (Low Priority)

**Recommendation:** Document maximum expected sizes or add optional limits in future versions.

---

### L-2: Missing `[[nodiscard]]` on Some Error-Returning Functions

**Location:** Various

**Status:** Partially addressed — most critical functions now have `[[nodiscard]]`.

---

### L-3: Property ID Convention Not Enforced at Construction

**Location:** `include/loc/loc.hpp`

**Description:** The even/odd ID convention for varint/bytes properties is only checked at encoding time.

**Status:** Open (Low Priority) — Runtime error at encode time is acceptable.

---

### L-4: Fuzz Test Coverage Could Be Expanded

**Location:** `tests/fuzz/`

**Description:** Fuzzing targets don't yet cover streaming API components.

**Status:** Open (Low Priority) — Recommend adding fuzz targets for `stream_encoder`, `stream_decoder`, `media_time`, and `buffer_pool`.

---

### L-5: No Constant-Time Comparison for Sensitive Data

**Status:** Accepted Risk — This is a media container library not designed for cryptographic operations.

---

### L-6: Bitfield Layout Is Implementation-Defined

**Status:** No Action Needed — Explicit encode/decode functions handle serialization correctly.

---

## Positive Security Observations

1. **Proper bounds checking**: All buffer accesses use `std::span` with bounds-checked operations
2. **Overflow protection**: Varint decoders properly check for integer overflow before shifting
3. **128-bit arithmetic**: `media_time` uses 128-bit intermediate arithmetic to prevent overflow
4. **Non-minimal encoding rejection**: Both QUIC and MOQ varint decoders reject non-canonical encodings
5. **RAII memory management**: `property` and `owned_property` classes properly manage heap allocations
6. **Thread-safe buffer pool**: `buffer_pool` uses mutex for concurrent access
7. **Configurable limits**: `decode_limits` prevents resource exhaustion attacks
8. **Owned property storage**: `stream_decoder` copies data to owned storage, preventing dangling references
9. **Explicit buffer lifecycle**: `encoded_result::release_to()` makes buffer management explicit
10. **Fuzzing infrastructure**: Project includes fuzz targets for critical parsing code
11. **No raw pointer arithmetic**: Modern C++ containers and spans used throughout
12. **Explicit error handling**: `expected<T>` type forces callers to handle errors

---

## Remediation Summary

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| H-1 | High | stream_decoder dangling references | **Fixed** |
| H-2 | High | buffer_pool thread safety | **Fixed** |
| H-3 | High | media_time integer overflow | **Fixed** |
| M-1 | Medium | Assertions in release builds | **Fixed** |
| M-2 | Medium | Memory exhaustion via properties | **Fixed** |
| M-3 | Medium | encoded_result pool pointer | **Fixed** |
| M-4 | Medium | No parsing limits | **Fixed** |
| M-5 | Medium | Division by zero in media_time | **Fixed** |
| L-1 | Low | hex functions unlimited alloc | Open |
| L-2 | Low | Missing [[nodiscard]] | Partial |
| L-3 | Low | Property ID validation | Open |
| L-4 | Low | Fuzz test coverage | Open |
| L-5 | Low | No constant-time comparison | Accepted |
| L-6 | Low | Bitfield layout | N/A |

---

*End of Security Audit Report*
