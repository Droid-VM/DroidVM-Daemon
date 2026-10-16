// SPDX-License-Identifier: GPL-3.0-or-later
#include "usb/java.h"
#include "store/network_config.h"
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace droidvm::usb {
namespace {
int saturate(double value) {
    if (std::isnan(value)) return 0;
    if (value >= 2147483647.0) return std::numeric_limits<int>::max();
    if (value <= -2147483648.0) return std::numeric_limits<int>::min();
    return static_cast<int>(value);
}
// JSONStringer.string
void quote(std::string& out, const std::string& text) {
    out += '"';
    for (size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        switch (c) {
        case '"': case '\\': case '/': out += '\\'; out += static_cast<char>(c); continue;
        case '\t': out += "\\t"; continue;
        case '\b': out += "\\b"; continue;
        case '\n': out += "\\n"; continue;
        case '\r': out += "\\r"; continue;
        case '\f': out += "\\f"; continue;
        default: break;
        }
        if (c < 0x20) {
            char buffer[8];
            std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
            out += buffer;
        } else if (c == 0xe2 && i + 2 < text.size() && static_cast<unsigned char>(text[i + 1]) == 0x80 &&
                   (static_cast<unsigned char>(text[i + 2]) == 0xa8 || static_cast<unsigned char>(text[i + 2]) == 0xa9)) {
            out += static_cast<unsigned char>(text[i + 2]) == 0xa8 ? "\\u2028" : "\\u2029";
            i += 2;
        } else {
            out += static_cast<char>(c);
        }
    }
    out += '"';
}
// JSONObject.numberToString
std::string number(const Json::Value& value) {
    if (value.type() != Json::realValue && value.isInt64()) return std::to_string(value.asInt64());
    const double d = value.asDouble();
    if (d == std::floor(d) && std::fabs(d) < 9.2233720368547758e18 && !(d == 0 && std::signbit(d)))
        return std::to_string(static_cast<int64_t>(d));
    return java_double(d);
}
void json(std::string& out, const Json::Value& value) {
    if (value.isNull()) out += "null";
    else if (value.isString()) quote(out, value.asString());
    else if (value.isBool()) out += value.asBool() ? "true" : "false";
    else if (value.isNumeric()) out += number(value);
    else if (value.isArray()) {
        out += '[';
        for (Json::ArrayIndex i = 0; i < value.size(); ++i) { if (i) out += ','; json(out, value[i]); }
        out += ']';
    } else {
        out += '{';
        bool first = true;
        for (const auto& name : value.getMemberNames()) {
            if (!first) out += ',';
            first = false;
            quote(out, name);
            out += ':';
            json(out, value[name]);
        }
        out += '}';
    }
}
}
std::string trim(std::string_view text) {
    size_t first = 0, last = text.size();
    while (first < last && static_cast<unsigned char>(text[first]) <= 0x20) ++first;
    while (last > first && static_cast<unsigned char>(text[last - 1]) <= 0x20) --last;
    return std::string(text.substr(first, last - first));
}
std::string lower(std::string text) {
    for (auto& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return text;
}
std::string utf8_lossy(std::string_view bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (size_t i = 0; i < bytes.size();) {
        const auto c = static_cast<unsigned char>(bytes[i]);
        size_t length = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        bool valid = length && i + length <= bytes.size();
        for (size_t k = 1; valid && k < length; ++k) valid = (static_cast<unsigned char>(bytes[i + k]) >> 6) == 2;
        if (valid && length > 1) {
            uint32_t code = c & (0xff >> (length + 1));
            for (size_t k = 1; k < length; ++k) code = code << 6 | (static_cast<unsigned char>(bytes[i + k]) & 0x3f);
            valid = code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) &&
                code >= (length == 2 ? 0x80u : length == 3 ? 0x800u : 0x10000u);
        }
        if (!valid) { out += "\xef\xbf\xbd"; ++i; continue; }
        out.append(bytes.substr(i, length));
        i += length;
    }
    return out;
}
std::optional<int> parse_int(std::string_view text) {
    try {
        const auto value = config::java_long(text);
        if (value < std::numeric_limits<int>::min() || value > std::numeric_limits<int>::max()) return std::nullopt;
        return static_cast<int>(value);
    } catch (const std::exception&) { return std::nullopt; }
}
std::string java_double(double value) {
    if (std::isnan(value)) return "NaN";
    if (std::isinf(value)) return value > 0 ? "Infinity" : "-Infinity";
    if (value == 0) return std::signbit(value) ? "-0.0" : "0.0";
    char buffer[64];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value, std::chars_format::scientific);
    std::string text(buffer, result.ptr);
    std::string sign;
    if (text.front() == '-') { sign = "-"; text.erase(0, 1); }
    const auto e = text.find('e');
    int exponent = std::atoi(text.c_str() + e + 1);
    std::string digits;
    for (size_t i = 0; i < e; ++i) if (text[i] != '.') digits += text[i];
    while (digits.size() > 1 && digits.back() == '0') digits.pop_back();
    const double magnitude = std::fabs(value);
    if (magnitude >= 1e-3 && magnitude < 1e7) {
        std::string whole, fraction;
        if (exponent >= 0) {
            const auto point = static_cast<size_t>(exponent) + 1;
            whole = digits.size() > point ? digits.substr(0, point) : digits + std::string(point - digits.size(), '0');
            fraction = digits.size() > point ? digits.substr(point) : "";
        } else {
            whole = "0";
            fraction = std::string(static_cast<size_t>(-exponent - 1), '0') + digits;
        }
        if (fraction.empty()) fraction = "0";
        return sign + whole + "." + fraction;
    }
    const std::string fraction = digits.size() > 1 ? digits.substr(1) : "0";
    return sign + digits.substr(0, 1) + "." + fraction + "E" + std::to_string(exponent);
}
std::string java_string(const Json::Value& value) {
    if (value.isNull()) return "null";
    if (value.isString()) return value.asString();
    if (value.isBool()) return value.asBool() ? "true" : "false";
    // org.json boxes an integer literal beyond long, and every real, as a Double.
    if (value.type() != Json::realValue && value.isInt64()) return std::to_string(value.asInt64());
    if (value.isNumeric()) return java_double(value.asDouble());
    std::string out;
    json(out, value);
    return out;
}
std::string opt_string(const Json::Value& object, const char* key, const std::string& fallback) {
    if (!object.isObject() || !object.isMember(key)) return fallback;
    return java_string(object[key]);
}
int int_value(const Json::Value& number) {
    // Integer/Long.intValue keep the low 32 bits; Double.intValue saturates.
    if (number.type() != Json::realValue && number.isInt64())
        return static_cast<int>(static_cast<uint32_t>(static_cast<uint64_t>(number.asInt64())));
    return saturate(number.asDouble());
}
int opt_int(const Json::Value& object, const char* key, int fallback) {
    if (!object.isObject() || !object.isMember(key)) return fallback;
    const auto& value = object[key];
    if (value.isNumeric()) return int_value(value);
    if (!value.isString()) return fallback;
    // Double.parseDouble: trimmed, Java's literal names only.
    auto text = trim(value.asString());
    if (!text.empty() && (text.back() == 'd' || text.back() == 'D' || text.back() == 'f' || text.back() == 'F')) text.pop_back();
    if (text.empty()) return fallback;
    const auto body = text.front() == '+' || text.front() == '-' ? text.substr(1) : text;
    if (body == "NaN") return 0;
    if (body == "Infinity") return text.front() == '-' ? std::numeric_limits<int>::min() : std::numeric_limits<int>::max();
    for (char c : body) if (!(std::isxdigit(static_cast<unsigned char>(c)) || c == '.' || c == 'x' || c == 'X' || c == 'p' || c == 'P' || c == '+' || c == '-')) return fallback;
    char* end = nullptr;
    const double parsed = std::strtod(text.c_str(), &end);
    if (end != text.c_str() + text.size()) return fallback;
    return saturate(parsed);
}
bool present(const Json::Value& object, const char* key) {
    return object.isObject() && object.isMember(key) && !object[key].isNull();
}
}
