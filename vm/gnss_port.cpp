// SPDX-License-Identifier: GPL-3.0-or-later
// Port of the hackintosh daemon's gnss/GnssHub.java and gnss/GnssPort.java,
// and of Gnss/GnssSource's row rules.
#include "vm/gnss_port.h"
#include "vm/command_common.h"
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <system_error>
#include <unistd.h>

namespace droidvm::vm {
using namespace command;

const Json::Value* gnss_row(const Json::Value& config) {
    const auto& list = member(config, "peripherals");
    if (!list.isArray()) return nullptr;
    for (const auto& peripheral : list)
        if (java_enum(peripheral, "type", "VIRTIO_SOUND", peripheral_types) == "VIRTIO_GNSS") return &peripheral;
    return nullptr;
}
GnssSource gnss_source(const Json::Value& row) {
    const auto name = java_enum(row, "gnss_source", "AUTO", {"AUTO", "RECEIVER", "LOCATION"});
    return name == "RECEIVER" ? GnssSource::receiver : name == "LOCATION" ? GnssSource::location : GnssSource::automatic;
}
GnssSource resolve_gnss_source(GnssSource source, bool host_has_receiver) {
    if (source != GnssSource::automatic) return source;
    return host_has_receiver ? GnssSource::automatic : GnssSource::location;
}
int gnss_source_bits(GnssSource resolved) {
    switch (resolved) {
    case GnssSource::receiver: return gnss_source_receiver;
    case GnssSource::automatic: return gnss_source_receiver | gnss_source_location;
    default: return gnss_source_location;
    }
}

GnssPort::GnssPort(std::string vm, GnssSource source, bool mark_simulated)
    : vm_(std::move(vm)), source_(source), mark_simulated_(mark_simulated) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) throw std::system_error(errno, std::generic_category(), "pipe");
    read_ = Fd(fds[0]);
    write_ = Fd(fds[1]);
    const int flags = fcntl(write_.get(), F_GETFL);
    if (flags < 0 || fcntl(write_.get(), F_SETFL, flags | O_NONBLOCK) != 0)
        throw std::system_error(errno, std::generic_category(), "O_NONBLOCK");
}
bool GnssPort::write(const std::string& epoch, int64_t now) {
    if (broken_ || write_.get() < 0) return false;
    ssize_t written;
    do written = ::write(write_.get(), epoch.data(), epoch.size());
    while (written < 0 && errno == EINTR);
    if (written < 0) {
        // EPIPE: crosvm is gone; the runtime's cleanup removes the port.
        if (errno != EAGAIN) broken_ = true;
        return false;
    }
    last_epoch_at = now;
    return static_cast<size_t>(written) == epoch.size();
}

GnssHub::GnssHub() : GnssHub(Hooks{}) {}
GnssHub::GnssHub(Hooks hooks) : hooks_(std::move(hooks)) {
    using namespace std::chrono;
    if (!hooks_.now_ms) hooks_.now_ms = [] { return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count(); };
    if (!hooks_.utc_ms) hooks_.utc_ms = [] { return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count(); };
    if (hooks_.thread) thread_ = std::thread(&GnssHub::run, this);
}
GnssHub::~GnssHub() {
    {
        std::lock_guard lock(mutex_);
        closing_ = true;
    }
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
}
void GnssHub::run() {
    std::unique_lock lock(mutex_);
    while (!closing_) {
        wake_.wait_for(lock, std::chrono::milliseconds(tick_ms), [this] { return closing_; });
        if (closing_) break;
        lock.unlock();
        try { tick(); } catch (...) {}
        lock.lock();
    }
}
void GnssHub::add(std::shared_ptr<GnssPort> port) {
    std::lock_guard lock(mutex_);
    ports_.push_back(std::move(port));
    // The service is being raised for it right now; give that its time before missing it.
    last_feed_at_ = hooks_.now_ms();
}
void GnssHub::remove(const std::shared_ptr<GnssPort>& port) {
    std::lock_guard lock(mutex_);
    std::erase(ports_, port);
}
int GnssHub::ports_for(GnssSource source) const {
    std::lock_guard lock(mutex_);
    int count = 0;
    for (const auto& port : ports_) count += port->source() == source;
    return count;
}
Json::Value GnssHub::feed(const Json::Value& params) {
    {
        std::lock_guard lock(mutex_);
        last_feed_at_ = hooks_.now_ms();
        reraise_interval_ = feeder_lost_ms;
    }
    if (params.isObject()) {
        if (const auto& receiver = params["receiver"]; receiver.isObject()) {
            std::optional<std::vector<gnss::Satellite>> sky;
            if (receiver.isMember("sky")) sky = gnss::sky_from_json(receiver["sky"]);
            const auto& age = receiver["sky_age"];
            on_receiver(gnss::fix_from_json(receiver["fix"]), sky, age.isNumeric() && !age.isBool() ? age.asInt64() : 0);
        }
        if (const auto& location = params["location"]; location.isObject()) {
            const auto& age = location["age"];
            if (const auto fix = gnss::fix_from_json(location["fix"]))
                on_location(*fix, age.isNumeric() && !age.isBool() ? age.asInt64() : 0);
        }
    }
    Json::Value result;
    result["receiver_ports"] = ports_for(GnssSource::receiver);
    result["location_ports"] = ports_for(GnssSource::location);
    return result;
}
void GnssHub::on_receiver(const std::optional<gnss::Fix>& fix, const std::optional<std::vector<gnss::Satellite>>& sky, int64_t sky_age_ms) {
    const auto now = hooks_.now_ms();
    std::vector<std::shared_ptr<GnssPort>> targets;
    std::vector<gnss::Satellite> fresh;
    {
        std::lock_guard lock(mutex_);
        if (sky) {
            receiver_sky_ = *sky;
            receiver_sky_at_ = now - sky_age_ms;
        }
        if (!fix) return;
        targets = ports_;
        fresh = fresh_sky(now);
    }
    const auto utc = hooks_.utc_ms();
    std::lock_guard write(write_mutex_);
    for (const auto& port : targets)
        if (port->source() != GnssSource::location) write_receiver_fix(*port, *fix, fresh, now, utc);
}
void GnssHub::on_location(const gnss::Fix& fix, int64_t age_ms) {
    std::lock_guard lock(mutex_);
    location_ = fix;
    location_at_ = hooks_.now_ms() - age_ms;
}
gnss::FixKind GnssHub::kind_of(const GnssPort& port) const {
    return port.mark_simulated() ? gnss::FixKind::simulated : gnss::FixKind::gnss;
}
std::vector<gnss::Satellite> GnssHub::fresh_sky(int64_t now) const {
    return now - receiver_sky_at_ <= sky_stale_ms ? receiver_sky_ : std::vector<gnss::Satellite>{};
}
void GnssHub::write_receiver_fix(GnssPort& port, const gnss::Fix& fix, const std::vector<gnss::Satellite>& sky, int64_t now, int64_t utc) {
    if (fix.utc_ms == port.last_fix_utc) return;
    port.last_fix_utc = fix.utc_ms;
    port.last_receiver_fix_at = now;
    port.write(gnss::epoch(fix, sky, kind_of(port), utc), now);
}
void GnssHub::tick() {
    const auto now = hooks_.now_ms();
    const auto utc = hooks_.utc_ms();
    std::vector<std::shared_ptr<GnssPort>> targets;
    std::optional<gnss::Fix> location;
    std::vector<gnss::Satellite> sky;
    bool reraise = false;
    {
        std::lock_guard lock(mutex_);
        if (ports_.empty()) return;
        targets = ports_;
        if (now - last_feed_at_ > feeder_lost_ms && now - last_reraise_at_ > reraise_interval_) {
            if (last_reraise_at_ > last_feed_at_) reraise_interval_ = std::min(reraise_interval_ * 2, reraise_max_ms);
            last_reraise_at_ = now;
            reraise = true;
        }
        if (location_ && now - location_at_ <= location_hold_ms) {
            location = location_->at(utc);
            if (now - location_at_ > motion_hold_ms) location = location->without_motion();
        }
        sky = fresh_sky(now);
    }
    if (reraise) {
        if (hooks_.log) hooks_.log("WARN", "GNSS: no word from the app's feeder; raising its service again");
        if (hooks_.reraise) hooks_.reraise();
    }
    std::lock_guard write(write_mutex_);
    for (const auto& port : targets) {
        switch (port->source()) {
        case GnssSource::receiver:
            if (now - port->last_epoch_at < gap_ms) continue;
            port->write(gnss::epoch(std::nullopt, sky, kind_of(*port), utc), now);
            break;
        case GnssSource::automatic:
            // The receiver's own epochs while it has a fix; the location only in between.
            if (now - port->last_receiver_fix_at < gap_ms) continue;
            port->write(gnss::epoch(location, location ? gnss::synthetic_sky() : sky,
                port->mark_simulated() ? gnss::FixKind::simulated : gnss::FixKind::estimated, utc), now);
            break;
        case GnssSource::location:
            port->write(gnss::epoch(location, location ? gnss::synthetic_sky() : std::vector<gnss::Satellite>{}, kind_of(*port), utc), now);
            break;
        }
    }
}
}
