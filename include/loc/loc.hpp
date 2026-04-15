// SPDX-FileCopyrightText: Copyright (c) 2026 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

// LOC (Low Overhead Container) for Media over QUIC
// https://github.com/moq-wg/loc

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
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
    type_mismatch
};

[[nodiscard]] constexpr std::string_view to_string(errc e) noexcept {
    switch (e) {
        case errc::ok: return "ok";
        case errc::truncated: return "truncated input";
        case errc::overflow: return "value overflow";
        case errc::invalid_encoding: return "invalid encoding";
        case errc::non_minimal: return "non-minimal encoding";
        case errc::type_mismatch: return "property type mismatch";
    }
    return "unknown error";
}

template <typename T>
class [[nodiscard]] expected {
public:
    constexpr expected(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
        : value_(std::move(value)), error_(errc::ok) {}

    constexpr expected(errc e) noexcept : value_{}, error_(e) {}

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return error_ == errc::ok; }
    [[nodiscard]] constexpr bool has_value() const noexcept { return error_ == errc::ok; }

    [[nodiscard]] constexpr T& operator*() & noexcept { return value_; }
    [[nodiscard]] constexpr const T& operator*() const& noexcept { return value_; }
    [[nodiscard]] constexpr T&& operator*() && noexcept { return std::move(value_); }

    [[nodiscard]] constexpr T* operator->() noexcept { return &value_; }
    [[nodiscard]] constexpr const T* operator->() const noexcept { return &value_; }

    [[nodiscard]] constexpr T& value() & noexcept { return value_; }
    [[nodiscard]] constexpr const T& value() const& noexcept { return value_; }
    [[nodiscard]] constexpr T&& value() && noexcept { return std::move(value_); }

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
            if (shift >= 64 && (b & 0x7F) != 0) return errc::overflow;
            v |= static_cast<std::uint64_t>(b & 0x7F) << shift;

            if ((b & 0x80) == 0) {
                if (encoded_size(v) != i + 1) return errc::non_minimal;
                return std::pair{v, i + 1};
            }
            shift += 7;
            if (shift > 63) return errc::invalid_encoding;
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

    constexpr void advance(std::size_t n) noexcept { data_ = data_.subspan(n); }

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
    inline constexpr std::uint64_t video_config = 13;
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
        offset += *result;
    }
    return out;
}

template <typename Policy = default_varint, typename Visitor>
[[nodiscard]] inline expected<void> decode_properties(byte_span in, Visitor&& visitor) noexcept {
    cursor c(in);

    while (!c.empty()) {
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
[[nodiscard]] inline expected<std::vector<property_view>> collect_properties(byte_span in) noexcept {
    std::vector<property_view> props;
    auto result = decode_properties<Policy>(in, [&](const property_view& p) {
        props.push_back(p);
        return true;
    });
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

    [[nodiscard]] static constexpr video_frame_marking decode(std::uint64_t v) noexcept {
        return {
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

    [[nodiscard]] static constexpr audio_level decode(std::uint64_t v) noexcept {
        return {
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

}  // namespace loc
