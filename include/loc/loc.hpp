// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

// LOC (Low Overhead Container) for Media over QUIC
// https://github.com/moq-wg/loc

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace loc {

// ============================================================================
// Core Types
// ============================================================================

using byte = std::byte;
using byte_span = std::span<const byte>;
using mutable_byte_span = std::span<byte>;

// ============================================================================
// Error Handling
// ============================================================================

enum class errc : std::uint8_t {
    ok = 0,
    truncated,
    overflow,
    invalid_encoding,
    non_minimal,
    type_mismatch,
    limit_exceeded,
    invalid_argument
};

[[nodiscard]] constexpr std::string_view to_string(errc e) noexcept {
    switch (e) {
        case errc::ok: return "ok";
        case errc::truncated: return "truncated input";
        case errc::overflow: return "value overflow";
        case errc::invalid_encoding: return "invalid encoding";
        case errc::non_minimal: return "non-minimal encoding";
        case errc::type_mismatch: return "property type mismatch";
        case errc::limit_exceeded: return "limit exceeded";
        case errc::invalid_argument: return "invalid argument";
    }
    return "unknown error";
}

// ============================================================================
// Configuration Limits
// ============================================================================

struct decode_limits {
    std::size_t max_properties{10000};
    std::size_t max_property_size{16 * 1024 * 1024};  // 16 MB
    std::size_t max_total_size{64 * 1024 * 1024};     // 64 MB

    static constexpr decode_limits none() noexcept {
        return {std::numeric_limits<std::size_t>::max(),
                std::numeric_limits<std::size_t>::max(),
                std::numeric_limits<std::size_t>::max()};
    }

    static constexpr decode_limits strict() noexcept {
        return {1000, 1024 * 1024, 4 * 1024 * 1024};
    }
};

template <typename T>
class [[nodiscard]] expected {
public:
    constexpr expected(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
        : value_(std::move(value)), error_(errc::ok) {}

    constexpr expected(errc e) noexcept : value_{}, error_(e) {}

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return error_ == errc::ok; }
    [[nodiscard]] constexpr bool has_value() const noexcept { return error_ == errc::ok; }

    [[nodiscard]] constexpr T& operator*() & noexcept {
        assert(has_value() && "dereferencing expected in error state");
        return value_;
    }
    [[nodiscard]] constexpr const T& operator*() const& noexcept {
        assert(has_value() && "dereferencing expected in error state");
        return value_;
    }
    [[nodiscard]] constexpr T&& operator*() && noexcept {
        assert(has_value() && "dereferencing expected in error state");
        return std::move(value_);
    }

    [[nodiscard]] constexpr T* operator->() noexcept {
        assert(has_value() && "dereferencing expected in error state");
        return &value_;
    }
    [[nodiscard]] constexpr const T* operator->() const noexcept {
        assert(has_value() && "dereferencing expected in error state");
        return &value_;
    }

    [[nodiscard]] constexpr T& value() & noexcept {
        assert(has_value() && "accessing value of expected in error state");
        return value_;
    }
    [[nodiscard]] constexpr const T& value() const& noexcept {
        assert(has_value() && "accessing value of expected in error state");
        return value_;
    }
    [[nodiscard]] constexpr T&& value() && noexcept {
        assert(has_value() && "accessing value of expected in error state");
        return std::move(value_);
    }

    [[nodiscard]] constexpr errc error() const noexcept { return error_; }

    template <typename F>
    [[nodiscard]] constexpr auto and_then(F&& f) const& -> std::invoke_result_t<F, const T&> {
        if (has_value()) return std::forward<F>(f)(value_);
        return error_;
    }

    template <typename F>
    [[nodiscard]] constexpr auto map(F&& f) const& -> expected<std::invoke_result_t<F, const T&>> {
        if (has_value()) return std::forward<F>(f)(value_);
        return error_;
    }

    [[nodiscard]] constexpr T value_or(T fallback) const& noexcept {
        return has_value() ? value_ : fallback;
    }

private:
    T value_;
    errc error_;
};

template <>
class [[nodiscard]] expected<void> {
public:
    constexpr expected() noexcept : error_(errc::ok) {}
    constexpr expected(errc e) noexcept : error_(e) {}

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return error_ == errc::ok; }
    [[nodiscard]] constexpr bool has_value() const noexcept { return error_ == errc::ok; }
    [[nodiscard]] constexpr errc error() const noexcept { return error_; }

private:
    errc error_;
};

// ============================================================================
// Varint Encoding Policies
// ============================================================================

struct quic_varint {
    static constexpr std::uint64_t max_value = 4'611'686'018'427'387'903ULL;
    static constexpr std::size_t max_size = 8;

    [[nodiscard]] static constexpr std::size_t encoded_size(std::uint64_t v) noexcept {
        if (v <= 63) return 1;
        if (v <= 16'383) return 2;
        if (v <= 1'073'741'823) return 4;
        if (v <= max_value) return 8;
        return 0;
    }

    [[nodiscard]] static constexpr expected<std::size_t> encode(std::uint64_t v, mutable_byte_span out) noexcept {
        const auto size = encoded_size(v);
        if (size == 0) return errc::overflow;
        if (out.size() < size) return errc::truncated;

        for (std::size_t i = 0; i < size; ++i) {
            out[i] = static_cast<byte>((v >> ((size - 1 - i) * 8)) & 0xFF);
        }

        constexpr std::array<std::uint8_t, 9> prefix = {0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0xC0};
        out[0] = static_cast<byte>(std::to_integer<std::uint8_t>(out[0]) | prefix[size]);
        return size;
    }

    [[nodiscard]] static constexpr expected<std::pair<std::uint64_t, std::size_t>> decode(byte_span in) noexcept {
        if (in.empty()) return errc::truncated;

        const auto first = std::to_integer<std::uint8_t>(in[0]);
        const std::size_t size = std::size_t{1} << (first >> 6);
        if (in.size() < size) return errc::truncated;

        std::uint64_t v = first & 0x3F;
        for (std::size_t i = 1; i < size; ++i) {
            v = (v << 8) | std::to_integer<std::uint8_t>(in[i]);
        }

        if (encoded_size(v) != size) return errc::non_minimal;
        return std::pair{v, size};
    }
};

struct moq_varint {
    static constexpr std::uint64_t max_value = std::numeric_limits<std::uint64_t>::max();
    static constexpr std::size_t max_size = 10;

    [[nodiscard]] static constexpr std::size_t encoded_size(std::uint64_t v) noexcept {
        std::size_t size = 1;
        while (v >= 0x80) { v >>= 7; ++size; }
        return size;
    }

    [[nodiscard]] static constexpr expected<std::size_t> encode(std::uint64_t v, mutable_byte_span out) noexcept {
        const auto size = encoded_size(v);
        if (out.size() < size) return errc::truncated;

        for (std::size_t i = 0; i < size; ++i) {
            auto b = static_cast<std::uint8_t>(v & 0x7F);
            v >>= 7;
            if (i + 1 < size) b |= 0x80;
            out[i] = static_cast<byte>(b);
        }
        return size;
    }

    [[nodiscard]] static constexpr expected<std::pair<std::uint64_t, std::size_t>> decode(byte_span in) noexcept {
        std::uint64_t v = 0;
        std::size_t shift = 0;

        for (std::size_t i = 0; i < in.size(); ++i) {
            const auto b = std::to_integer<std::uint8_t>(in[i]);
            const auto payload = static_cast<std::uint64_t>(b & 0x7F);

            // Check for overflow before shifting: at shift=63, only bit 0 can be set
            if (shift >= 63 && payload > 1) return errc::overflow;

            v |= payload << shift;

            if ((b & 0x80) == 0) {
                if (encoded_size(v) != i + 1) return errc::non_minimal;
                return std::pair{v, i + 1};
            }
            shift += 7;
            // 10 bytes max for 64-bit value (ceil(64/7) = 10)
            if (i >= 9) return errc::invalid_encoding;
        }
        return errc::truncated;
    }
};

// Default varint policy
#ifdef LOC_USE_MOQ_VARINT
using default_varint = moq_varint;
#else
using default_varint = quic_varint;
#endif

// ============================================================================
// Varint Operations
// ============================================================================

template <typename Policy = default_varint>
struct varint {
    std::uint64_t value{0};

    constexpr varint() = default;
    constexpr explicit varint(std::uint64_t v) noexcept : value(v) {}

    [[nodiscard]] constexpr std::size_t encoded_size() const noexcept {
        return Policy::encoded_size(value);
    }

    [[nodiscard]] constexpr expected<std::size_t> encode_to(mutable_byte_span out) const noexcept {
        return Policy::encode(value, out);
    }

    [[nodiscard]] static constexpr expected<std::pair<varint, std::size_t>> decode_from(byte_span in) noexcept {
        auto result = Policy::decode(in);
        if (!result) return result.error();
        return std::pair{varint{result->first}, result->second};
    }
};

// Convenience encode/decode functions
template <typename Policy = default_varint>
[[nodiscard]] inline std::vector<byte> encode_varint(std::uint64_t v) {
    std::vector<byte> out(Policy::encoded_size(v));
    (void)Policy::encode(v, out);
    return out;
}

template <typename Policy = default_varint>
[[nodiscard]] inline expected<std::uint64_t> decode_varint(byte_span& in) noexcept {
    auto result = Policy::decode(in);
    if (!result) return result.error();
    in = in.subspan(result->second);
    return result->first;
}

// ============================================================================
// Cursor for Sequential Decoding
// ============================================================================

class cursor {
public:
    constexpr explicit cursor(byte_span data) noexcept : data_(data) {}

    [[nodiscard]] constexpr byte_span remaining() const noexcept { return data_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] constexpr bool empty() const noexcept { return data_.empty(); }

    constexpr bool advance(std::size_t n) noexcept {
        if (n > data_.size()) return false;
        data_ = data_.subspan(n);
        return true;
    }

    template <typename Policy = default_varint>
    [[nodiscard]] constexpr expected<std::uint64_t> read_varint() noexcept {
        auto result = Policy::decode(data_);
        if (!result) return result.error();
        data_ = data_.subspan(result->second);
        return result->first;
    }

    [[nodiscard]] constexpr expected<byte_span> read_bytes(std::size_t n) noexcept {
        if (data_.size() < n) return errc::truncated;
        auto result = data_.first(n);
        data_ = data_.subspan(n);
        return result;
    }

private:
    byte_span data_;
};

// ============================================================================
// Property Types
// ============================================================================

namespace property_id {
    inline constexpr std::uint64_t video_frame_marking = 4;
    inline constexpr std::uint64_t timestamp = 6;
    inline constexpr std::uint64_t timescale = 8;
    inline constexpr std::uint64_t audio_level = 10;
    inline constexpr std::uint64_t sequence_number = 12;
    inline constexpr std::uint64_t video_config = 13;
    inline constexpr std::uint64_t group_id = 14;
    inline constexpr std::uint64_t subgroup_id = 16;
    inline constexpr std::uint64_t priority = 18;
    inline constexpr std::uint64_t delivery_timeout = 20;
}

[[nodiscard]] constexpr bool is_varint_property(std::uint64_t id) noexcept {
    return (id & 1) == 0;
}

// Property view - non-owning
struct property_view {
    std::uint64_t id{0};
    byte_span data{};

    [[nodiscard]] constexpr bool is_varint() const noexcept { return is_varint_property(id); }

    template <typename Policy = default_varint>
    [[nodiscard]] constexpr expected<std::uint64_t> as_varint() const noexcept {
        if (!is_varint()) return errc::type_mismatch;
        auto result = Policy::decode(data);
        if (!result) return result.error();
        return result->first;
    }
};

// Owning property with small buffer optimization
class property {
    static constexpr std::size_t sbo_size = 16;

public:
    property() = default;

    [[nodiscard]] static property from_varint(std::uint64_t id, std::uint64_t value) {
        property p;
        p.id_ = id;
        p.is_varint_ = true;

        std::array<byte, default_varint::max_size> buf{};
        auto result = default_varint::encode(value, buf);
        assert(result.has_value() && "varint encoding failed");
        p.size_ = *result;
        if (p.size_ <= sbo_size) {
            std::copy_n(buf.begin(), p.size_, p.storage_.inline_data.begin());
        } else {
            p.storage_.heap_data = new byte[p.size_];
            std::copy_n(buf.begin(), p.size_, p.storage_.heap_data);
        }
        return p;
    }

    [[nodiscard]] static property from_bytes(std::uint64_t id, byte_span value) {
        property p;
        p.id_ = id;
        p.is_varint_ = false;
        p.size_ = value.size();

        if (p.size_ <= sbo_size) {
            std::copy(value.begin(), value.end(), p.storage_.inline_data.begin());
        } else {
            p.storage_.heap_data = new byte[p.size_];
            std::copy(value.begin(), value.end(), p.storage_.heap_data);
        }
        return p;
    }

    property(const property& other) : id_(other.id_), is_varint_(other.is_varint_), size_(other.size_) {
        if (size_ <= sbo_size) {
            storage_.inline_data = other.storage_.inline_data;
        } else {
            storage_.heap_data = new byte[size_];
            std::copy_n(other.storage_.heap_data, size_, storage_.heap_data);
        }
    }

    property(property&& other) noexcept
        : id_(other.id_), is_varint_(other.is_varint_), size_(other.size_), storage_(other.storage_) {
        other.size_ = 0;
    }

    property& operator=(const property& other) {
        if (this != &other) {
            property tmp(other);
            swap(tmp);
        }
        return *this;
    }

    property& operator=(property&& other) noexcept {
        if (this != &other) {
            clear();
            id_ = other.id_;
            is_varint_ = other.is_varint_;
            size_ = other.size_;
            storage_ = other.storage_;
            other.size_ = 0;
        }
        return *this;
    }

    ~property() { clear(); }

    void swap(property& other) noexcept {
        std::swap(id_, other.id_);
        std::swap(is_varint_, other.is_varint_);
        std::swap(size_, other.size_);
        std::swap(storage_, other.storage_);
    }

    [[nodiscard]] std::uint64_t id() const noexcept { return id_; }
    [[nodiscard]] bool is_varint() const noexcept { return is_varint_; }

    [[nodiscard]] byte_span data() const noexcept {
        if (size_ == 0) return {};
        return {size_ <= sbo_size ? storage_.inline_data.data() : storage_.heap_data, size_};
    }

    [[nodiscard]] property_view view() const noexcept { return {id_, data()}; }

    template <typename Policy = default_varint>
    [[nodiscard]] expected<std::uint64_t> as_varint() const noexcept {
        return view().template as_varint<Policy>();
    }

private:
    void clear() noexcept {
        if (size_ > sbo_size) {
            delete[] storage_.heap_data;
        }
        size_ = 0;
    }

    std::uint64_t id_{0};
    bool is_varint_{false};
    std::size_t size_{0};
    union Storage {
        std::array<byte, sbo_size> inline_data{};
        byte* heap_data;
    } storage_;
};

// ============================================================================
// Property Encoding/Decoding
// ============================================================================

template <typename Policy = default_varint>
[[nodiscard]] inline std::size_t encoded_property_size(const property& p) noexcept {
    auto id_size = Policy::encoded_size(p.id());
    if (p.is_varint()) {
        return id_size + p.data().size();
    }
    return id_size + Policy::encoded_size(p.data().size()) + p.data().size();
}

template <typename Policy = default_varint>
[[nodiscard]] inline expected<std::size_t> encode_property(const property& p, mutable_byte_span out) noexcept {
    if (is_varint_property(p.id()) != p.is_varint()) {
        return errc::type_mismatch;
    }

    std::size_t offset = 0;

    // Encode ID
    auto id_result = Policy::encode(p.id(), out.subspan(offset));
    if (!id_result) return id_result.error();
    offset += *id_result;

    if (p.is_varint()) {
        // Varint value: copy raw encoded bytes
        auto data = p.data();
        if (out.size() - offset < data.size()) return errc::truncated;
        std::copy(data.begin(), data.end(), out.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += data.size();
    } else {
        // Bytes value: length + data
        auto data = p.data();
        auto len_result = Policy::encode(data.size(), out.subspan(offset));
        if (!len_result) return len_result.error();
        offset += *len_result;

        if (out.size() - offset < data.size()) return errc::truncated;
        std::copy(data.begin(), data.end(), out.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += data.size();
    }

    return offset;
}

template <typename Policy = default_varint>
[[nodiscard]] inline std::vector<byte> encode_properties(std::span<const property> props) {
    std::size_t total = 0;
    for (const auto& p : props) {
        total += encoded_property_size<Policy>(p);
    }

    std::vector<byte> out(total);
    std::size_t offset = 0;
    for (const auto& p : props) {
        auto result = encode_property<Policy>(p, mutable_byte_span{out}.subspan(offset));
        assert(result.has_value() && "property encoding failed");
        offset += *result;
    }
    return out;
}

template <typename Policy = default_varint, typename Visitor>
[[nodiscard]] inline expected<void> decode_properties(
    byte_span in,
    Visitor&& visitor,
    const decode_limits& limits = {}) noexcept {

    cursor c(in);
    std::size_t property_count = 0;

    while (!c.empty()) {
        if (++property_count > limits.max_properties) {
            return errc::limit_exceeded;
        }

        auto id_result = c.read_varint<Policy>();
        if (!id_result) return id_result.error();
        auto id = *id_result;

        byte_span value_data;
        if (is_varint_property(id)) {
            const auto start = c.remaining();
            auto val_result = c.read_varint<Policy>();
            if (!val_result) return val_result.error();
            value_data = byte_span{start.data(), start.size() - c.size()};
        } else {
            auto len_result = c.read_varint<Policy>();
            if (!len_result) return len_result.error();

            if (*len_result > limits.max_property_size) {
                return errc::limit_exceeded;
            }

            auto bytes_result = c.read_bytes(*len_result);
            if (!bytes_result) return bytes_result.error();
            value_data = *bytes_result;
        }

        if (!visitor(property_view{id, value_data})) {
            break;
        }
    }
    return {};
}

template <typename Policy = default_varint>
[[nodiscard]] inline expected<std::vector<property_view>> collect_properties(
    byte_span in,
    const decode_limits& limits = {}) noexcept {

    std::vector<property_view> props;
    auto result = decode_properties<Policy>(in, [&](const property_view& p) {
        props.push_back(p);
        return true;
    }, limits);
    if (!result) return result.error();
    return props;
}

// ============================================================================
// Media Metadata Types
// ============================================================================

struct video_frame_marking {
    bool independent : 1 {false};
    bool discardable : 1 {false};
    bool base_layer_sync : 1 {false};
    std::uint8_t temporal_id : 3 {0};
    std::uint8_t spatial_id : 3 {0};

    [[nodiscard]] constexpr std::uint64_t encode() const noexcept {
        return (independent ? 1ULL : 0) |
               (discardable ? 2ULL : 0) |
               (base_layer_sync ? 4ULL : 0) |
               (static_cast<std::uint64_t>(temporal_id & 7) << 3) |
               (static_cast<std::uint64_t>(spatial_id & 7) << 6);
    }

    [[nodiscard]] static constexpr std::optional<video_frame_marking> decode(std::uint64_t v) noexcept {
        // Only bits 0-8 are valid (3 flags + 3-bit temporal_id + 3-bit spatial_id)
        if (v & ~0x1FFULL) return std::nullopt;
        return video_frame_marking{
            .independent = (v & 1) != 0,
            .discardable = (v & 2) != 0,
            .base_layer_sync = (v & 4) != 0,
            .temporal_id = static_cast<std::uint8_t>((v >> 3) & 7),
            .spatial_id = static_cast<std::uint8_t>((v >> 6) & 7)
        };
    }

    [[nodiscard]] property to_property() const {
        return property::from_varint(property_id::video_frame_marking, encode());
    }
};

struct audio_level {
    std::uint8_t level : 7 {0};
    bool voice_activity : 1 {false};

    [[nodiscard]] constexpr std::uint64_t encode() const noexcept {
        return static_cast<std::uint64_t>(level & 0x7F) |
               (voice_activity ? 0x80ULL : 0);
    }

    [[nodiscard]] static constexpr std::optional<audio_level> decode(std::uint64_t v) noexcept {
        // Only bits 0-7 are valid (7-bit level + 1-bit voice_activity)
        if (v & ~0xFFULL) return std::nullopt;
        return audio_level{
            .level = static_cast<std::uint8_t>(v & 0x7F),
            .voice_activity = (v & 0x80) != 0
        };
    }

    [[nodiscard]] property to_property() const {
        return property::from_varint(property_id::audio_level, encode());
    }
};

// ============================================================================
// LOC Object
// ============================================================================

struct loc_object_view {
    byte_span public_properties{};
    byte_span private_properties{};
    byte_span payload{};
};

class loc_object {
public:
    loc_object() = default;

    // Builder-style API
    loc_object& add_public(property p) {
        public_props_.push_back(std::move(p));
        return *this;
    }

    loc_object& add_private(property p) {
        private_props_.push_back(std::move(p));
        return *this;
    }

    loc_object& set_payload(byte_span data) {
        payload_.assign(data.begin(), data.end());
        return *this;
    }

    loc_object& set_payload(std::vector<byte> data) {
        payload_ = std::move(data);
        return *this;
    }

    // Convenience methods for common properties
    loc_object& timestamp(std::uint64_t ts) {
        return add_public(property::from_varint(property_id::timestamp, ts));
    }

    loc_object& timescale(std::uint64_t scale) {
        return add_public(property::from_varint(property_id::timescale, scale));
    }

    loc_object& frame_marking(video_frame_marking fm) {
        return add_public(fm.to_property());
    }

    loc_object& audio_level_info(audio_level al) {
        return add_public(al.to_property());
    }

    // Encode to wire format
    struct encoded {
        std::vector<byte> public_properties;
        std::vector<byte> payload;  // private_properties + payload

        [[nodiscard]] byte_span public_view() const noexcept {
            return {public_properties.data(), public_properties.size()};
        }

        [[nodiscard]] byte_span payload_view() const noexcept {
            return {payload.data(), payload.size()};
        }
    };

    template <typename Policy = default_varint>
    [[nodiscard]] encoded encode() const {
        encoded result;
        result.public_properties = encode_properties<Policy>(public_props_);

        auto private_encoded = encode_properties<Policy>(private_props_);
        result.payload.reserve(private_encoded.size() + payload_.size());
        result.payload.insert(result.payload.end(), private_encoded.begin(), private_encoded.end());
        result.payload.insert(result.payload.end(), payload_.begin(), payload_.end());

        return result;
    }

    // Accessors
    [[nodiscard]] std::span<const property> public_properties() const noexcept { return public_props_; }
    [[nodiscard]] std::span<const property> private_properties() const noexcept { return private_props_; }
    [[nodiscard]] byte_span payload() const noexcept { return {payload_.data(), payload_.size()}; }

private:
    std::vector<property> public_props_;
    std::vector<property> private_props_;
    std::vector<byte> payload_;
};

// Decode LOC object from wire format
template <typename Policy = default_varint>
[[nodiscard]] inline expected<loc_object_view> decode_loc_object(
    byte_span public_properties,
    byte_span payload_with_private,
    std::size_t private_length) noexcept {

    if (payload_with_private.size() < private_length) {
        return errc::truncated;
    }

    return loc_object_view{
        .public_properties = public_properties,
        .private_properties = payload_with_private.first(private_length),
        .payload = payload_with_private.subspan(private_length)
    };
}

// ============================================================================
// Utility Functions
// ============================================================================

[[nodiscard]] inline std::string to_hex(byte_span data) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (auto b : data) {
        auto v = std::to_integer<std::uint8_t>(b);
        result.push_back(hex_chars[v >> 4]);
        result.push_back(hex_chars[v & 0xF]);
    }
    return result;
}

[[nodiscard]] inline std::optional<std::vector<byte>> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;

    auto hex_digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::vector<byte> result;
    result.reserve(hex.size() / 2);

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int high = hex_digit(hex[i]);
        int low = hex_digit(hex[i + 1]);
        if (high < 0 || low < 0) return std::nullopt;
        result.push_back(static_cast<byte>((high << 4) | low));
    }
    return result;
}

// ============================================================================
// Timestamp Utilities
// ============================================================================

struct media_time {
    std::uint64_t ticks{0};
    std::uint64_t timescale{1};

    // Overflow-safe multiplication: (a * b) / c without overflow
    [[nodiscard]] static constexpr std::uint64_t safe_scale(std::uint64_t value, std::uint64_t mul, std::uint64_t div) noexcept {
        if (div == 0) return 0;
        // Use 128-bit arithmetic via compiler builtins or split multiplication
        #if defined(__SIZEOF_INT128__)
        __uint128_t result = static_cast<__uint128_t>(value) * mul / div;
        return static_cast<std::uint64_t>(result);
        #else
        // Fallback: split into high and low parts to avoid overflow
        std::uint64_t high = value / div;
        std::uint64_t low = value % div;
        return high * mul + (low * mul) / div;
        #endif
    }

    [[nodiscard]] static constexpr media_time from_us(std::uint64_t microseconds, std::uint64_t scale = 1'000'000) noexcept {
        return {safe_scale(microseconds, scale, 1'000'000), scale};
    }

    [[nodiscard]] static constexpr media_time from_ms(std::uint64_t milliseconds, std::uint64_t scale = 1'000) noexcept {
        return {safe_scale(milliseconds, scale, 1'000), scale};
    }

    [[nodiscard]] static constexpr media_time from_90khz(std::uint64_t ticks_90k) noexcept {
        return {ticks_90k, 90'000};
    }

    [[nodiscard]] static constexpr media_time from_48khz(std::uint64_t samples) noexcept {
        return {samples, 48'000};
    }

    [[nodiscard]] constexpr std::uint64_t to_us() const noexcept {
        if (timescale == 0) return 0;
        return safe_scale(ticks, 1'000'000, timescale);
    }

    [[nodiscard]] constexpr std::uint64_t to_ms() const noexcept {
        if (timescale == 0) return 0;
        return safe_scale(ticks, 1'000, timescale);
    }

    [[nodiscard]] constexpr media_time convert_to(std::uint64_t new_scale) const noexcept {
        if (timescale == 0) return {0, new_scale};
        return {safe_scale(ticks, new_scale, timescale), new_scale};
    }

    [[nodiscard]] constexpr bool is_valid() const noexcept {
        return timescale > 0;
    }
};

// ============================================================================
// Buffer Pool for High-Throughput Encoding
// ============================================================================

// Thread-safe buffer pool for high-throughput encoding
class buffer_pool {
public:
    explicit buffer_pool(std::size_t initial_capacity = 4096) : default_capacity_(initial_capacity) {}

    // Non-copyable, non-movable (due to mutex)
    buffer_pool(const buffer_pool&) = delete;
    buffer_pool& operator=(const buffer_pool&) = delete;
    buffer_pool(buffer_pool&&) = delete;
    buffer_pool& operator=(buffer_pool&&) = delete;

    [[nodiscard]] std::vector<byte> acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!pool_.empty()) {
            auto buf = std::move(pool_.back());
            pool_.pop_back();
            buf.clear();
            return buf;
        }
        std::vector<byte> buf;
        buf.reserve(default_capacity_);
        return buf;
    }

    void release(std::vector<byte> buf) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pool_.size() < max_pool_size_) {
            pool_.push_back(std::move(buf));
        }
    }

    void set_max_pool_size(std::size_t max_size) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        max_pool_size_ = max_size;
    }

    [[nodiscard]] std::size_t pool_size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return pool_.size();
    }

private:
    mutable std::mutex mutex_;
    std::vector<std::vector<byte>> pool_;
    std::size_t default_capacity_;
    std::size_t max_pool_size_{32};
};

// Single-threaded buffer pool (no locking overhead)
class buffer_pool_st {
public:
    explicit buffer_pool_st(std::size_t initial_capacity = 4096) : default_capacity_(initial_capacity) {}

    [[nodiscard]] std::vector<byte> acquire() {
        if (!pool_.empty()) {
            auto buf = std::move(pool_.back());
            pool_.pop_back();
            buf.clear();
            return buf;
        }
        std::vector<byte> buf;
        buf.reserve(default_capacity_);
        return buf;
    }

    void release(std::vector<byte> buf) {
        if (pool_.size() < max_pool_size_) {
            pool_.push_back(std::move(buf));
        }
    }

    void set_max_pool_size(std::size_t max_size) noexcept { max_pool_size_ = max_size; }
    [[nodiscard]] std::size_t pool_size() const noexcept { return pool_.size(); }

private:
    std::vector<std::vector<byte>> pool_;
    std::size_t default_capacity_;
    std::size_t max_pool_size_{32};
};

// ============================================================================
// Group/Sequence Metadata (LOC draft concepts)
// ============================================================================

struct group_info {
    std::uint64_t group_id{0};
    std::uint64_t subgroup_id{0};
    std::uint64_t sequence{0};
    std::uint8_t priority{0};
    std::optional<std::uint64_t> delivery_timeout_ms{};
};

// ============================================================================
// Streaming Encoder (Reuses Buffers)
// ============================================================================

template <typename Policy = default_varint>
class stream_encoder {
public:
    explicit stream_encoder(buffer_pool* pool = nullptr) : pool_(pool) {}

    stream_encoder& reset() {
        public_props_.clear();
        private_props_.clear();
        payload_.clear();
        return *this;
    }

    stream_encoder& timestamp(std::uint64_t ts) {
        add_varint_property(property_id::timestamp, ts);
        return *this;
    }

    stream_encoder& timestamp(media_time time) {
        add_varint_property(property_id::timestamp, time.ticks);
        add_varint_property(property_id::timescale, time.timescale);
        return *this;
    }

    stream_encoder& timescale(std::uint64_t scale) {
        add_varint_property(property_id::timescale, scale);
        return *this;
    }

    stream_encoder& frame_marking(video_frame_marking fm) {
        add_varint_property(property_id::video_frame_marking, fm.encode());
        return *this;
    }

    stream_encoder& audio_level_info(audio_level al) {
        add_varint_property(property_id::audio_level, al.encode());
        return *this;
    }

    stream_encoder& add_public_varint(std::uint64_t id, std::uint64_t value) {
        add_varint_property(id, value);
        return *this;
    }

    stream_encoder& add_public_bytes(std::uint64_t id, byte_span data) {
        public_props_.push_back(property::from_bytes(id, data));
        return *this;
    }

    stream_encoder& add_private(property p) {
        private_props_.push_back(std::move(p));
        return *this;
    }

    stream_encoder& set_group(const group_info& info) {
        add_varint_property(property_id::group_id, info.group_id);
        add_varint_property(property_id::subgroup_id, info.subgroup_id);
        add_varint_property(property_id::sequence_number, info.sequence);
        add_varint_property(property_id::priority, info.priority);
        if (info.delivery_timeout_ms) {
            add_varint_property(property_id::delivery_timeout, *info.delivery_timeout_ms);
        }
        return *this;
    }

    stream_encoder& set_payload(byte_span data) {
        payload_.assign(data.begin(), data.end());
        return *this;
    }

    stream_encoder& set_payload(std::vector<byte> data) {
        payload_ = std::move(data);
        return *this;
    }

    struct encoded_result {
        std::vector<byte> public_properties;
        std::vector<byte> payload;

        [[nodiscard]] byte_span public_view() const noexcept {
            return {public_properties.data(), public_properties.size()};
        }

        [[nodiscard]] byte_span payload_view() const noexcept {
            return {payload.data(), payload.size()};
        }

        // Manually release buffers back to a pool
        void release_to(buffer_pool& pool) {
            pool.release(std::move(public_properties));
            pool.release(std::move(payload));
            public_properties = {};
            payload = {};
        }

        void release_to(buffer_pool_st& pool) {
            pool.release(std::move(public_properties));
            pool.release(std::move(payload));
            public_properties = {};
            payload = {};
        }
    };

    [[nodiscard]] encoded_result encode() {
        encoded_result result;

        result.public_properties = pool_ ? pool_->acquire() : std::vector<byte>{};
        result.payload = pool_ ? pool_->acquire() : std::vector<byte>{};

        encode_props_into(public_props_, result.public_properties);
        encode_props_into(private_props_, result.payload);
        result.payload.insert(result.payload.end(), payload_.begin(), payload_.end());

        return result;
    }

    // Get pool pointer for manual release
    [[nodiscard]] buffer_pool* pool() const noexcept { return pool_; }

    [[nodiscard]] expected<std::size_t> encode_public_into(mutable_byte_span out) const noexcept {
        std::size_t offset = 0;
        for (const auto& p : public_props_) {
            auto result = encode_property<Policy>(p, out.subspan(offset));
            if (!result) return result.error();
            offset += *result;
        }
        return offset;
    }

    [[nodiscard]] std::size_t public_encoded_size() const noexcept {
        std::size_t total = 0;
        for (const auto& p : public_props_) {
            total += encoded_property_size<Policy>(p);
        }
        return total;
    }

    [[nodiscard]] std::size_t payload_encoded_size() const noexcept {
        std::size_t total = 0;
        for (const auto& p : private_props_) {
            total += encoded_property_size<Policy>(p);
        }
        return total + payload_.size();
    }

private:
    void add_varint_property(std::uint64_t id, std::uint64_t value) {
        public_props_.push_back(property::from_varint(id, value));
    }

    void encode_props_into(const std::vector<property>& props, std::vector<byte>& out) {
        std::size_t total = 0;
        for (const auto& p : props) {
            total += encoded_property_size<Policy>(p);
        }

        auto start = out.size();
        out.resize(start + total);

        std::size_t offset = 0;
        for (const auto& p : props) {
            auto result = encode_property<Policy>(p, mutable_byte_span{out}.subspan(start + offset));
            assert(result.has_value());
            offset += *result;
        }
    }

    std::vector<property> public_props_;
    std::vector<property> private_props_;
    std::vector<byte> payload_;
    buffer_pool* pool_{nullptr};
};

// ============================================================================
// Streaming Decoder (Incremental Parsing)
// ============================================================================

// Owning property - stores a copy of property data
struct owned_property {
    std::uint64_t id{0};
    std::vector<byte> data{};

    [[nodiscard]] bool is_varint() const noexcept { return is_varint_property(id); }

    [[nodiscard]] property_view view() const noexcept {
        return {id, byte_span{data.data(), data.size()}};
    }

    template <typename Policy = default_varint>
    [[nodiscard]] expected<std::uint64_t> as_varint() const noexcept {
        return view().template as_varint<Policy>();
    }
};

template <typename Policy = default_varint>
class stream_decoder {
public:
    enum class state { need_header, have_header, complete, error };

    explicit stream_decoder(const decode_limits& limits = {}) : limits_(limits) {}

    void reset() noexcept {
        state_ = state::need_header;
        error_ = errc::ok;
        public_props_.clear();
        private_props_.clear();
        payload_data_.clear();
    }

    [[nodiscard]] state current_state() const noexcept { return state_; }
    [[nodiscard]] errc last_error() const noexcept { return error_; }

    // Parse public properties - copies data internally
    [[nodiscard]] expected<void> parse_public(byte_span public_data) noexcept {
        auto result = decode_properties<Policy>(public_data, [this](const property_view& p) {
            owned_property owned;
            owned.id = p.id;
            owned.data.assign(p.data.begin(), p.data.end());
            public_props_.push_back(std::move(owned));
            return true;
        }, limits_);
        if (!result) {
            state_ = state::error;
            error_ = result.error();
            return error_;
        }
        state_ = state::have_header;
        return {};
    }

    // Parse payload - copies data internally
    [[nodiscard]] expected<void> parse_payload(byte_span payload_with_private, std::size_t private_length) noexcept {
        if (payload_with_private.size() < private_length) {
            state_ = state::error;
            error_ = errc::truncated;
            return error_;
        }

        auto private_data = payload_with_private.first(private_length);
        auto payload_span = payload_with_private.subspan(private_length);

        // Copy payload data
        payload_data_.assign(payload_span.begin(), payload_span.end());

        auto result = decode_properties<Policy>(private_data, [this](const property_view& p) {
            owned_property owned;
            owned.id = p.id;
            owned.data.assign(p.data.begin(), p.data.end());
            private_props_.push_back(std::move(owned));
            return true;
        }, limits_);
        if (!result) {
            state_ = state::error;
            error_ = result.error();
            return error_;
        }

        state_ = state::complete;
        return {};
    }

    [[nodiscard]] std::span<const owned_property> public_properties() const noexcept {
        return public_props_;
    }

    [[nodiscard]] std::span<const owned_property> private_properties() const noexcept {
        return private_props_;
    }

    [[nodiscard]] byte_span payload() const noexcept {
        return {payload_data_.data(), payload_data_.size()};
    }

    [[nodiscard]] std::optional<std::uint64_t> get_timestamp() const noexcept {
        return get_varint_property(property_id::timestamp);
    }

    [[nodiscard]] std::optional<std::uint64_t> get_timescale() const noexcept {
        return get_varint_property(property_id::timescale);
    }

    [[nodiscard]] std::optional<media_time> get_media_time() const noexcept {
        auto ts = get_timestamp();
        auto scale = get_timescale();
        if (!ts) return std::nullopt;
        return media_time{*ts, scale.value_or(1)};
    }

    [[nodiscard]] std::optional<video_frame_marking> get_frame_marking() const noexcept {
        auto val = get_varint_property(property_id::video_frame_marking);
        if (!val) return std::nullopt;
        return video_frame_marking::decode(*val);
    }

    [[nodiscard]] std::optional<audio_level> get_audio_level() const noexcept {
        auto val = get_varint_property(property_id::audio_level);
        if (!val) return std::nullopt;
        return audio_level::decode(*val);
    }

private:
    [[nodiscard]] std::optional<std::uint64_t> get_varint_property(std::uint64_t id) const noexcept {
        for (const auto& p : public_props_) {
            if (p.id == id && p.is_varint()) {
                if (auto val = p.template as_varint<Policy>(); val) {
                    return *val;
                }
            }
        }
        return std::nullopt;
    }

    decode_limits limits_;
    state state_{state::need_header};
    errc error_{errc::ok};
    std::vector<owned_property> public_props_;
    std::vector<owned_property> private_props_;
    std::vector<byte> payload_data_;
};

// ============================================================================
// Media Frame Helper
// ============================================================================

class media_frame {
public:
    enum class type { unknown, video, audio };

    media_frame() = default;

    static media_frame video(media_time time, video_frame_marking marking) {
        media_frame f;
        f.type_ = type::video;
        f.time_ = time;
        f.frame_marking_ = marking;
        return f;
    }

    static media_frame audio(media_time time, audio_level level) {
        media_frame f;
        f.type_ = type::audio;
        f.time_ = time;
        f.audio_level_ = level;
        return f;
    }

    media_frame& set_group(group_info info) {
        group_ = info;
        return *this;
    }

    media_frame& set_payload(byte_span data) {
        payload_.assign(data.begin(), data.end());
        return *this;
    }

    media_frame& set_payload(std::vector<byte> data) {
        payload_ = std::move(data);
        return *this;
    }

    [[nodiscard]] type frame_type() const noexcept { return type_; }
    [[nodiscard]] media_time time() const noexcept { return time_; }
    [[nodiscard]] std::optional<video_frame_marking> frame_marking() const noexcept { return frame_marking_; }
    [[nodiscard]] std::optional<audio_level> audio_level_info() const noexcept { return audio_level_; }
    [[nodiscard]] std::optional<group_info> group() const noexcept { return group_; }
    [[nodiscard]] byte_span payload() const noexcept { return {payload_.data(), payload_.size()}; }

    [[nodiscard]] bool is_keyframe() const noexcept {
        return frame_marking_ && frame_marking_->independent;
    }

    template <typename Policy = default_varint>
    [[nodiscard]] loc_object to_loc_object() const {
        loc_object obj;

        obj.timestamp(time_.ticks);
        obj.timescale(time_.timescale);

        if (frame_marking_) {
            obj.frame_marking(*frame_marking_);
        }
        if (audio_level_) {
            obj.audio_level_info(*audio_level_);
        }

        if (group_) {
            obj.add_public(property::from_varint(property_id::group_id, group_->group_id));
            obj.add_public(property::from_varint(property_id::subgroup_id, group_->subgroup_id));
            obj.add_public(property::from_varint(property_id::sequence_number, group_->sequence));
            obj.add_public(property::from_varint(property_id::priority, group_->priority));
            if (group_->delivery_timeout_ms) {
                obj.add_public(property::from_varint(property_id::delivery_timeout, *group_->delivery_timeout_ms));
            }
        }

        obj.set_payload(byte_span{payload_.data(), payload_.size()});
        return obj;
    }

private:
    type type_{type::unknown};
    media_time time_;
    std::optional<video_frame_marking> frame_marking_;
    std::optional<audio_level> audio_level_;
    std::optional<group_info> group_;
    std::vector<byte> payload_;
};

}  // namespace loc
