// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "common/fd.h"
#include "vm/nmea.h"
#include <json/json.h>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

// The VM's GNSS receiver (a VIRTIO_GNSS row): one more virtio-console port,
// named gnss_port_name so the guest can tell it apart, whose input is a pipe
// the daemon writes NMEA into. A Linux guest finds it as
// /dev/virtio-ports/org.droidvm.gnss.0 and hands it to gpsd.
//
// Who does what: Android's location is Java-only and gated on the caller's
// uid, so the app's PeripheralForegroundService runs a feeder while a running
// VM has the row (the daemon raises it with the location type and the
// sources in "gnss_sources") and reports the phone's receiver and location
// over the gnss_feed IPC as they arrive. GnssHub does the timing and writes
// every running VM's port.
namespace droidvm::vm {
// The port's name in the guest. A contract with guest-side setup: do not rename.
inline constexpr const char* gnss_port_name = "org.droidvm.gnss.0";
// GnssSource: both (the receiver first, the location in the seconds it has no
// fix), the phone's receiver only, or its location only.
enum class GnssSource { automatic, receiver, location };
// Bits of the foreground service's "gnss_sources" extra (Gnss.SOURCE_*).
inline constexpr int gnss_source_receiver = 1, gnss_source_location = 2;
// Gnss.rowOf: the VM's first VIRTIO_GNSS row, or null; the VM has one receiver.
const Json::Value* gnss_row(const Json::Value& config);
// The row's stored source (gnss_source; absent or unknown is AUTO).
GnssSource gnss_source(const Json::Value& row);
// GnssSource.resolve: AUTO needs a receiver on this phone (FEATURE_LOCATION_GPS).
GnssSource resolve_gnss_source(GnssSource source, bool host_has_receiver);
// Gnss.sourceBitsOf for an already resolved source.
int gnss_source_bits(GnssSource resolved);

// One VM's port, daemon side: the pipe whose read end crosvm takes as the
// port's input. The write end is non-blocking and an epoch that does not fit
// is dropped: crosvm drains the pipe continuously, so a full pipe means a
// crosvm that has stopped, and a second-old fix is worthless anyway.
class GnssPort {
public:
    // source must already be resolved: AUTO here means the phone has a receiver.
    // Throws std::system_error when the pipe cannot be made.
    GnssPort(std::string vm, GnssSource source, bool mark_simulated);
    int read_fd() const { return read_.get(); }
    // The daemon's copy of the read end, closed once crosvm has its own.
    void close_read_fd() { read_ = Fd(); }
    const std::string& vm() const { return vm_; }
    GnssSource source() const { return source_; }
    bool mark_simulated() const { return mark_simulated_; }
    // Whether the epoch went out whole. Writer: the hub, under its write lock.
    bool write(const std::string& epoch, int64_t now);
    // Hub state, under the hub's write lock.
    int64_t last_epoch_at = INT64_MIN / 2; // steady ms of the last epoch written
    int64_t last_fix_utc = INT64_MIN; // UTC of the last receiver fix, not reported twice
    int64_t last_receiver_fix_at = INT64_MIN / 2; // AUTO's choice between it and the location
private:
    std::string vm_;
    GnssSource source_;
    bool mark_simulated_;
    Fd read_, write_;
    bool broken_ = false;
};

// Turns what the app's feeder reports into every running VM's NMEA, once a
// second (the hackintosh daemon's GnssHub).
//
// The receiver's fixes are written as they arrive, stamped with their own GNSS
// time; a second without one is filled with a no-fix epoch carrying whatever
// satellites are in view, so the guest sees a receiver even while the app is
// not feeding. The location is reported every second as of now, from the
// newest location for as long as it is location_hold_ms old (fused updates
// come when there is something new, and every 10 minutes at most to an app
// with approximate location only). An AUTO port takes the receiver's fixes
// while they come and the location in the seconds between, marked estimated
// and carried by the synthetic sky (gpsd reads a GGA with no satellites in
// the solution as no fix, whatever its quality).
//
// A feeder silent for feeder_lost_ms is gone (its process was killed): the
// reraise hook brings the service back, then again at twice the interval each
// time up to reraise_max_ms, until it speaks again.
class GnssHub {
public:
    static constexpr int64_t tick_ms = 1000;
    static constexpr int64_t gap_ms = 1500; // a receiver second with no epoch gets a no-fix one
    static constexpr int64_t sky_stale_ms = 3000;
    static constexpr int64_t location_hold_ms = 15 * 60000;
    static constexpr int64_t motion_hold_ms = 3000;
    static constexpr int64_t feeder_lost_ms = 15000; // the feeder beats every 5 s
    static constexpr int64_t reraise_max_ms = 300000;
    struct Hooks {
        std::function<int64_t()> now_ms; // steady clock; default std::chrono::steady_clock
        std::function<int64_t()> utc_ms; // default std::chrono::system_clock
        std::function<void()> reraise; // the foreground service, raised again
        std::function<void(const char* level, const std::string& text)> log;
        bool thread = true; // false: the caller drives tick() (tests)
    };
    GnssHub();
    explicit GnssHub(Hooks hooks);
    ~GnssHub();
    GnssHub(const GnssHub&) = delete;
    GnssHub& operator=(const GnssHub&) = delete;
    void add(std::shared_ptr<GnssPort> port);
    void remove(const std::shared_ptr<GnssPort>& port);
    // gnss_feed: any word from the feeder (a heartbeat included), then its
    // parts. Returns {"receiver_ports":n,"location_ports":n}.
    Json::Value feed(const Json::Value& params);
    void on_receiver(const std::optional<gnss::Fix>& fix, const std::optional<std::vector<gnss::Satellite>>& sky, int64_t sky_age_ms);
    void on_location(const gnss::Fix& fix, int64_t age_ms);
    int ports_for(GnssSource source) const;
    // One second's work: gap filling, the location ports, the lost feeder.
    void tick();
private:
    gnss::FixKind kind_of(const GnssPort& port) const;
    std::vector<gnss::Satellite> fresh_sky(int64_t now) const; // mutex_ held
    void write_receiver_fix(GnssPort& port, const gnss::Fix& fix, const std::vector<gnss::Satellite>& sky, int64_t now, int64_t utc);
    void run();
    Hooks hooks_;
    mutable std::mutex mutex_; // ports and the feeder's newest data
    std::mutex write_mutex_; // port writes and their per-port state
    std::condition_variable wake_;
    std::vector<std::shared_ptr<GnssPort>> ports_;
    std::vector<gnss::Satellite> receiver_sky_;
    int64_t receiver_sky_at_ = INT64_MIN / 2;
    std::optional<gnss::Fix> location_;
    int64_t location_at_ = 0;
    int64_t last_feed_at_ = 0, last_reraise_at_ = INT64_MIN / 2, reraise_interval_ = feeder_lost_ms;
    bool closing_ = false;
    std::thread thread_;
};
}
