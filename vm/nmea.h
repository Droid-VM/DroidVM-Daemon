// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <json/json.h>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

// The virtual GNSS receiver's output: NMEA 0183 4.11, one epoch of sentences
// per fix (a port of the hackintosh app's lib/gnss/Nmea.java).
//
// One stream carries every system, the way a real multi-system receiver's one
// UART does: the position is the one solution the phone's receiver computed
// from all of them (RMC, GGA, GST with the GN talker), and the satellites are
// told apart by talker (GP GL GA GB GQ GI) in GSV and by system id in GSA.
// GSV's signal id separates the bands of a dual-frequency receiver.
//
// Pure: a fix and a satellite list in, text out. GnssHub decides what to feed
// it (the phone's receiver, or the location-only synthetic sky) and when.
namespace droidvm::vm::gnss {
inline constexpr double nan = std::numeric_limits<double>::quiet_NaN();
// One position (GnssFix). A field the source did not give is NaN, never 0.
// Accuracies are Android's 68% radius (horizontal) / half-interval (vertical).
struct Fix {
    int64_t utc_ms = 0; // GNSS time for the receiver, the fix's own for the rest
    double latitude = 0, longitude = 0;
    double altitude_hae = nan; // above the WGS 84 ellipsoid, metres
    double altitude_msl = nan; // above mean sea level, metres
    double speed_mps = nan;
    double bearing_deg = nan; // course over ground from true north
    double horizontal_accuracy = nan, vertical_accuracy = nan;
    // The same fix at another time: a location-only receiver repeats its last fix.
    Fix at(int64_t utc) const { auto copy = *this; copy.utc_ms = utc; return copy; }
    // Motion dropped, for a fix too old for its speed to be true.
    Fix without_motion() const { auto copy = *this; copy.speed_mps = nan; copy.bearing_deg = nan; return copy; }
};
// One tracked signal (GnssSatellite), constellation in GnssStatus numbering.
struct Satellite {
    int constellation = 0, svid = 0;
    double cn0_dbhz = 0; // 0 when not tracked
    double elevation_deg = 0, azimuth_deg = 0;
    bool used_in_fix = false;
    double carrier_hz = nan; // NaN when the receiver did not say
    // The receiver knows where it is in the sky (no almanac reads as 0, 0).
    bool has_position() const {
        return (elevation_deg != 0 || azimuth_deg != 0) && elevation_deg >= -90 && elevation_deg <= 90;
    }
};
// android.location.GnssStatus.CONSTELLATION_*
inline constexpr int constellation_gps = 1, constellation_sbas = 2, constellation_glonass = 3,
    constellation_qzss = 4, constellation_beidou = 5, constellation_galileo = 6, constellation_irnss = 7;
// What a fix says it is: GGA quality and RMC mode. An autonomous GNSS fix
// (1, A), a position the receiver did not solve (6, E: estimated) or a
// simulated one (8, S).
enum class FixKind { gnss, estimated, simulated };

// One second's sentences: RMC, GGA, a GSA per system in the solution, the GSV
// groups, and GST when the fix has an accuracy. Without a fix the receiver
// still reports its satellites and now_utc_ms.
std::string epoch(const std::optional<Fix>& fix, const std::vector<Satellite>& satellites, FixKind kind, int64_t now_utc_ms);
// Eight GPS L1 satellites spread over the sky, all in the solution: what a
// location-only fix is carried by.
std::vector<Satellite> synthetic_sky();
// Degrees as dddmm.mmmmm, rounded once so 59.999999' carries into the degree.
std::string angle(double degrees, int degree_digits);
// PDOP, HDOP, VDOP of the satellites in the solution; NaN without geometry.
std::array<double, 3> dilution(const std::vector<Satellite>& used);
int system_of(int constellation);
int nmea_id(const Satellite& satellite);
int signal_id(const Satellite& satellite);

// The app feeder's JSON (GnssFix.toJson / GnssSatellite.toJson): nullopt for
// a fix without a valid latitude and longitude.
std::optional<Fix> fix_from_json(const Json::Value& json);
std::vector<Satellite> sky_from_json(const Json::Value& json);
}
