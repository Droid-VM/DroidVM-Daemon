// SPDX-License-Identifier: GPL-3.0-or-later
// Port of the hackintosh app's lib/gnss/Nmea.java, GnssFix.fromJson and
// GnssSatellite.fromJson.
#include "vm/nmea.h"
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <map>
#include <set>

namespace droidvm::vm::gnss {
namespace {
// NMEA 4.11 system ids: GSA's last field, and what keys a GSV group with its talker.
constexpr int system_gps = 1, system_glonass = 2, system_galileo = 3, system_beidou = 4, system_qzss = 5, system_navic = 6;
constexpr const char* talkers[] = {nullptr, "GP", "GL", "GA", "GB", "GQ", "GI"};
constexpr double knots_per_mps = 3600.0 / 1852.0;
// Android's accuracies are 68% radii; GST wants standard deviations. For a
// circular normal the radius holding 68% is sqrt(-2 ln 0.32) = 1.5096 sigmas.
constexpr double sigmas_per_horizontal_68 = 1.5096;
// NMEA's own limits: GSV's two-digit count and nine-message sequence, 4 signals each.
constexpr int gsv_per_message = 4, gsv_max_messages = 9, gsa_ids = 12;
constexpr double gps_l1_hz = 1575.42e6;
constexpr double pi = 3.14159265358979323846;

int quality(FixKind kind) { return kind == FixKind::gnss ? 1 : kind == FixKind::estimated ? 6 : 8; }
char mode(FixKind kind) { return kind == FixKind::gnss ? 'A' : kind == FixKind::estimated ? 'E' : 'S'; }
// Java's Math.round.
int64_t round_half_up(double value) { return static_cast<int64_t>(std::floor(value + 0.5)); }
std::string format(const char* pattern, ...) {
    char buffer[128];
    va_list args;
    va_start(args, pattern);
    const int written = std::vsnprintf(buffer, sizeof(buffer), pattern, args);
    va_end(args);
    return written < 0 ? std::string() : std::string(buffer, std::min<size_t>(static_cast<size_t>(written), sizeof(buffer) - 1));
}
std::tm utc_time(int64_t utc_ms, int& centiseconds) {
    auto seconds = utc_ms / 1000;
    auto millis = utc_ms % 1000;
    if (millis < 0) { millis += 1000; --seconds; }
    centiseconds = static_cast<int>(millis / 10);
    const auto stamp = static_cast<std::time_t>(seconds);
    std::tm out{};
    gmtime_r(&stamp, &out);
    return out;
}
std::string clock(int64_t utc_ms) {
    int centi = 0;
    const auto t = utc_time(utc_ms, centi);
    return format("%02d%02d%02d.%02d", t.tm_hour, t.tm_min, t.tm_sec, centi);
}
std::string date(int64_t utc_ms) {
    int centi = 0;
    const auto t = utc_time(utc_ms, centi);
    return format("%02d%02d%02d", t.tm_mday, t.tm_mon + 1, (t.tm_year + 1900) % 100);
}
std::string dop_field(const std::optional<Fix>& fix, double value) {
    return !fix || std::isnan(value) ? std::string() : format("%.2f", value);
}
void sentence(std::string& out, const std::string& fields) {
    unsigned sum = 0;
    for (const char c : fields) sum ^= static_cast<unsigned char>(c);
    out += '$';
    out += fields;
    out += format("*%02X\r\n", sum);
}
void position(std::string& f, const std::optional<Fix>& fix) {
    if (!fix) { f += ",,,"; return; }
    f += angle(fix->latitude, 2) + ',' + (fix->latitude < 0 ? 'S' : 'N') + ',';
    f += angle(fix->longitude, 3) + ',' + (fix->longitude < 0 ? 'W' : 'E');
}
void rmc(std::string& out, const std::optional<Fix>& fix, int64_t time, FixKind kind) {
    std::string f = "GNRMC," + clock(time) + ',';
    f += fix ? 'A' : 'V';
    f += ',';
    position(f, fix);
    f += ',';
    if (fix && !std::isnan(fix->speed_mps)) f += format("%.3f", fix->speed_mps * knots_per_mps);
    f += ',';
    if (fix && !std::isnan(fix->bearing_deg)) f += format("%.2f", fix->bearing_deg);
    f += ',' + date(time) + ",,,";
    // Mode, then 4.10's navigational status, which receivers leave "not valid".
    f += fix ? mode(kind) : 'N';
    f += ",V";
    sentence(out, f);
}
void gga(std::string& out, const std::optional<Fix>& fix, int64_t time, FixKind kind, int used, double hdop) {
    std::string f = "GNGGA," + clock(time) + ',';
    position(f, fix);
    f += ',' + std::to_string(fix ? quality(kind) : 0);
    f += ',' + format("%02d", std::min(used, 99)) + ',';
    if (fix && !std::isnan(hdop)) f += format("%.2f", hdop);
    f += ',';
    // Above sea level with the geoid's height beside it; without the sea-level
    // figure the field stays empty rather than holding the ellipsoid height,
    // which a reader would correct by its own geoid table and get wrong.
    if (fix && !std::isnan(fix->altitude_msl)) {
        f += format("%.1f", fix->altitude_msl) + ",M,";
        if (!std::isnan(fix->altitude_hae)) f += format("%.1f", fix->altitude_hae - fix->altitude_msl) + ",M";
        else f += ',';
    } else f += ",,,";
    f += ",,";
    sentence(out, f);
}
void gsa(std::string& out, const std::optional<Fix>& fix, bool three_d, const std::vector<Satellite>& used, const std::array<double, 3>& dop) {
    const int fix_mode = !fix ? 1 : three_d ? 3 : 2;
    std::map<int, std::vector<int>> by_system;
    for (const auto& s : used) {
        auto& ids = by_system[system_of(s.constellation)];
        const int id = nmea_id(s);
        // A dual-frequency satellite is in the solution once, whatever its signals.
        if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
    }
    if (by_system.empty()) by_system[system_gps];
    for (auto& [system, ids] : by_system) {
        std::sort(ids.begin(), ids.end());
        size_t at = 0;
        do {
            std::string f = "GNGSA,A," + std::to_string(fix_mode);
            for (size_t i = 0; i < gsa_ids; ++i) {
                f += ',';
                if (at + i < ids.size()) f += format("%02d", ids[at + i]);
            }
            f += ',' + dop_field(fix, dop[0]) + ',' + dop_field(fix, dop[1]) + ',' + dop_field(fix, dop[2]);
            f += ',' + std::to_string(system);
            sentence(out, f);
            at += gsa_ids;
        } while (at < ids.size());
    }
}
void gsv(std::string& out, const std::vector<Satellite>& satellites) {
    // Keyed system first, then signal: GPS L1, GPS L5, GLONASS G1...
    std::map<int, std::vector<Satellite>> groups;
    for (const auto& s : satellites) {
        if (nmea_id(s) <= 0) continue;
        groups[system_of(s.constellation) * 16 + signal_id(s)].push_back(s);
    }
    if (groups.empty()) {
        // A receiver that sees nothing says so.
        sentence(out, "GPGSV,1,1,00,1");
        return;
    }
    for (auto& [key, list] : groups) {
        std::stable_sort(list.begin(), list.end(), [](const Satellite& a, const Satellite& b) { return nmea_id(a) < nmea_id(b); });
        const int count = std::min(static_cast<int>(list.size()), gsv_per_message * gsv_max_messages);
        const int messages = (count + gsv_per_message - 1) / gsv_per_message;
        const char* talker = talkers[key / 16];
        const int signal = key % 16;
        for (int m = 0; m < messages; ++m) {
            std::string f = std::string(talker) + "GSV," + std::to_string(messages) + ',' + std::to_string(m + 1) + ',' + format("%02d", count);
            for (int i = m * gsv_per_message; i < std::min(count, (m + 1) * gsv_per_message); ++i) {
                const auto& s = list[static_cast<size_t>(i)];
                f += ',' + format("%02d", nmea_id(s)) + ',';
                if (s.has_position()) {
                    f += format("%02lld", static_cast<long long>(round_half_up(s.elevation_deg))) + ',';
                    f += format("%03lld", static_cast<long long>(round_half_up(s.azimuth_deg) % 360));
                } else f += ',';
                f += ',';
                if (s.cn0_dbhz > 0) f += format("%02lld", static_cast<long long>(std::min<int64_t>(99, round_half_up(s.cn0_dbhz))));
            }
            f += ',' + format("%X", signal);
            sentence(out, f);
        }
    }
}
void gst(std::string& out, const Fix& fix, int64_t time) {
    const double sigma = fix.horizontal_accuracy / sigmas_per_horizontal_68;
    std::string f = "GNGST," + clock(time) + ",,";
    f += format("%.1f,%.1f,0.0,%.1f,%.1f,", sigma, sigma, sigma, sigma);
    // The vertical accuracy is already one-dimensional: its 68% half-interval is one sigma.
    if (!std::isnan(fix.vertical_accuracy)) f += format("%.1f", fix.vertical_accuracy);
    sentence(out, f);
}
int count_satellites(const std::vector<Satellite>& used) {
    std::set<int> seen;
    for (const auto& s : used) seen.insert(system_of(s.constellation) * 1000 + nmea_id(s));
    return static_cast<int>(seen.size());
}
bool near(double mhz, double band) { return std::abs(mhz - band) < 3; }
// JSONObject.optDouble: a number, else NaN.
double number(const Json::Value& value, double fallback = nan) {
    return value.isNumeric() && !value.isBool() ? value.asDouble() : fallback;
}
int integer_at(const Json::Value& value) {
    if (!value.isNumeric() || value.isBool()) return 0;
    const double d = value.asDouble();
    if (std::isnan(d)) return 0;
    return static_cast<int>(std::clamp(d, -2147483648.0, 2147483647.0));
}
}

std::string epoch(const std::optional<Fix>& fix, const std::vector<Satellite>& satellites, FixKind kind, int64_t now_utc_ms) {
    const int64_t time = fix ? fix->utc_ms : now_utc_ms;
    std::vector<Satellite> used;
    for (const auto& s : satellites) if (s.used_in_fix && nmea_id(s) > 0) used.push_back(s);
    const auto dop = dilution(used);
    const bool three_d = fix && !std::isnan(fix->altitude_msl);
    std::string out;
    rmc(out, fix, time, kind);
    gga(out, fix, time, kind, count_satellites(used), dop[1]);
    gsa(out, fix, three_d, used, dop);
    gsv(out, satellites);
    if (fix && !std::isnan(fix->horizontal_accuracy)) gst(out, *fix, time);
    return out;
}
std::vector<Satellite> synthetic_sky() {
    // svid, elevation, azimuth, C/N0
    static constexpr int sky[][4] = {
        {2, 68, 40, 44}, {5, 52, 110, 42}, {7, 41, 175, 40}, {12, 33, 230, 39},
        {15, 27, 290, 38}, {19, 20, 330, 36}, {24, 15, 15, 34}, {29, 45, 260, 41},
    };
    std::vector<Satellite> list;
    for (const auto& s : sky) list.push_back({constellation_gps, s[0], double(s[3]), double(s[1]), double(s[2]), true, gps_l1_hz});
    return list;
}
std::string angle(double degrees, int degree_digits) {
    const int64_t units = round_half_up(std::abs(degrees) * 60 * 100000);
    const int64_t whole = units / (60 * 100000);
    const int64_t minute_units = units % (60 * 100000);
    return format("%0*lld%02lld.%05lld", degree_digits, static_cast<long long>(whole),
        static_cast<long long>(minute_units / 100000), static_cast<long long>(minute_units % 100000));
}
int system_of(int constellation) {
    switch (constellation) {
    case constellation_gps: case constellation_sbas: return system_gps;
    case constellation_glonass: return system_glonass;
    case constellation_galileo: return system_galileo;
    case constellation_beidou: return system_beidou;
    case constellation_qzss: return system_qzss;
    case constellation_irnss: return system_navic;
    default: return 0;
    }
}
// Android numbers SBAS by PRN (120-158), GLONASS by orbital slot (1-24) or by
// frequency channel (93-106) when the slot is unknown, QZSS by PRN (193-202).
int nmea_id(const Satellite& s) {
    const int svid = s.svid;
    switch (s.constellation) {
    case constellation_gps: return svid >= 1 && svid <= 32 ? svid : 0;
    case constellation_sbas: return svid >= 120 && svid <= 151 ? svid - 87 : 0; // under GP as 33-64
    case constellation_glonass: return svid >= 1 && svid <= 32 ? svid + 64 : 0; // a channel names no satellite
    case constellation_galileo: return svid >= 1 && svid <= 36 ? svid : 0;
    case constellation_beidou: return svid >= 1 && svid <= 63 ? svid : 0;
    case constellation_qzss: return svid >= 193 && svid <= 202 ? svid - 192 : 0;
    case constellation_irnss: return svid >= 1 && svid <= 14 ? svid : 0;
    default: return 0;
    }
}
int signal_id(const Satellite& s) {
    const double mhz = s.carrier_hz / 1e6;
    if (std::isnan(mhz)) return 1;
    const bool l1 = near(mhz, 1575.42), l2 = near(mhz, 1227.60), l5 = near(mhz, 1176.45);
    const bool e5b = near(mhz, 1207.14), e6 = near(mhz, 1278.75);
    switch (s.constellation) {
    case constellation_gps: case constellation_sbas: return l5 ? 8 : l2 ? 6 : 1; // L1 C/A, L2C-L, L5-Q
    case constellation_glonass: return mhz < 1400 ? 3 : 1; // G2 C/A, G1 C/A
    case constellation_galileo: return l1 ? 7 : l5 ? 1 : e5b ? 2 : e6 ? 5 : 7; // E1-BC, E5a, E5b, E6-BC
    case constellation_beidou:
        if (near(mhz, 1561.098)) return 1; // B1I
        if (near(mhz, 1268.52)) return 8; // B3I
        return l1 ? 3 : l5 ? 5 : e5b ? 11 : 1; // B1C, B2a, B2I
    case constellation_qzss: return l5 ? 8 : l2 ? 6 : e6 ? 9 : 1; // L1 C/A, L2C-L, L5-Q, L6D
    default: return 1;
    }
}
// One receiver clock for every system: the per-system offsets a multi-system
// solution also estimates move these figures little.
std::array<double, 3> dilution(const std::vector<Satellite>& used) {
    const std::array<double, 3> none{nan, nan, nan};
    std::vector<std::array<double, 4>> rows;
    std::set<int> seen;
    for (const auto& s : used) {
        if (!s.has_position()) continue;
        if (!seen.insert(system_of(s.constellation) * 1000 + nmea_id(s)).second) continue;
        const double el = s.elevation_deg * pi / 180, az = s.azimuth_deg * pi / 180;
        rows.push_back({std::cos(el) * std::sin(az), std::cos(el) * std::cos(az), std::sin(el), 1});
    }
    if (rows.size() < 4) return none;
    double n[4][8] = {};
    for (const auto& g : rows)
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j) n[i][j] += g[i] * g[j];
    for (int i = 0; i < 4; ++i) n[i][4 + i] = 1;
    // Gauss-Jordan on [N | I]: the right half becomes N's inverse.
    for (int col = 0; col < 4; ++col) {
        int pivot = col;
        for (int r = col + 1; r < 4; ++r) if (std::abs(n[r][col]) > std::abs(n[pivot][col])) pivot = r;
        if (std::abs(n[pivot][col]) < 1e-9) return none;
        for (int j = 0; j < 8; ++j) std::swap(n[col][j], n[pivot][j]);
        const double p = n[col][col];
        for (int j = 0; j < 8; ++j) n[col][j] /= p;
        for (int r = 0; r < 4; ++r) {
            if (r == col) continue;
            const double factor = n[r][col];
            for (int j = 0; j < 8; ++j) n[r][j] -= factor * n[col][j];
        }
    }
    const double east = n[0][4], north = n[1][5], up = n[2][6];
    return {std::sqrt(east + north + up), std::sqrt(east + north), std::sqrt(up)};
}
std::optional<Fix> fix_from_json(const Json::Value& json) {
    if (!json.isObject() || !json.isMember("lat") || !json.isMember("lon")) return std::nullopt;
    Fix fix;
    fix.latitude = number(json["lat"]);
    fix.longitude = number(json["lon"]);
    if (!(std::abs(fix.latitude) <= 90) || !(std::abs(fix.longitude) <= 180)) return std::nullopt;
    const double t = number(json["t"], 0);
    fix.utc_ms = std::isnan(t) ? 0 : static_cast<int64_t>(std::clamp(t, -9.2e18, 9.2e18));
    fix.altitude_hae = number(json["hae"]);
    fix.altitude_msl = number(json["msl"]);
    fix.speed_mps = number(json["spd"]);
    fix.bearing_deg = number(json["brg"]);
    fix.horizontal_accuracy = number(json["hacc"]);
    fix.vertical_accuracy = number(json["vacc"]);
    return fix;
}
std::vector<Satellite> sky_from_json(const Json::Value& json) {
    std::vector<Satellite> list;
    if (!json.isArray()) return list;
    for (const auto& row : json) {
        if (!row.isArray() || row.size() < 7) continue;
        const double carrier = number(row[6], 0);
        list.push_back({integer_at(row[0]), integer_at(row[1]), number(row[2], 0), number(row[3], 0), number(row[4], 0),
            integer_at(row[5]) != 0, carrier > 0 ? carrier : nan});
    }
    return list;
}
}
