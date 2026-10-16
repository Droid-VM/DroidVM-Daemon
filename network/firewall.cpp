// SPDX-License-Identifier: GPL-3.0-or-later
#include "firewall.h"
#include "links.h"
#include "common/identity.h"
#include "store/network_config.h"
#include "services/context.h"
#include <algorithm>
#include <fcntl.h>
#include <map>
#include <set>
#include <sys/file.h>
#include <system_error>

namespace droidvm::network {
namespace {
[[noreturn]] void invalid(const char* text) { throw ServiceError(ErrorCode::invalid_argument, text); }
[[noreturn]] void conflict(const char* text) { throw ServiceError(ErrorCode::conflict, text); }
void tag_valid(const std::string& tag) {
    if (!tag.starts_with("droidvm:") || tag.size() != 40 || tag.substr(8).find_first_not_of("0123456789abcdef") != std::string::npos)
        invalid("invalid firewall ownership tag");
}
void key_valid(const std::string& key) {
    if (key.empty() || key.size() > 128 || key.find('\0') != std::string::npos) invalid("invalid firewall owner or key");
}
std::string ports(uint16_t first, uint16_t last, char separator) {
    if (!first || last < first) invalid("invalid firewall port range");
    return std::to_string(first) + (last == first ? "" : std::string(1, separator) + std::to_string(last));
}
// Parse iptables -S quoting as data only. Never evaluate returned text in a
// shell. Quoted comments may contain whitespace, escapes or option-like text.
std::vector<std::string> words(std::string_view line) {
    std::vector<std::string> result;
    std::string word;
    char quote = 0;
    bool escape = false, started = false;
    for (const char ch : line) {
        if (escape) { word += ch; escape = false; }
        else if (ch == '\\') { escape = true; started = true; }
        else if (quote) { if (ch == quote) quote = 0; else word += ch; }
        else if (ch == '"' || ch == '\'') { quote = ch; started = true; }
        else if (ch == ' ' || ch == '\t' || ch == '\r') {
            if (started) { result.push_back(std::move(word)); word.clear(); started = false; }
        } else { word += ch; started = true; }
    }
    if (quote || escape) throw ServiceError(ErrorCode::io_error, "malformed firewall snapshot quoting");
    if (started) result.push_back(std::move(word));
    if (result.size() > 256) throw ServiceError(ErrorCode::resource_exhausted, "firewall snapshot rule exceeds budget");
    return result;
}
void completed(const ChildOutput& result) {
    if (result.timed_out || result.cancelled || result.truncated)
        throw ServiceError(ErrorCode::unavailable, "firewall command exceeded budget; effect may have occurred");
}
void success(const ChildOutput& result) {
    completed(result);
    if (result.exit_code != 0) throw ServiceError(ErrorCode::io_error, "firewall command failed: " + result.error.substr(0, 1024));
}
FirewallRule table_scope(bool ipv6, const std::string& table) {
    FirewallRule rule; rule.ipv6 = ipv6; rule.table = table; rule.input = "lo";
    if (table == "nat" || table == "raw") rule.chain = "PREROUTING";
    rule.arguments(); return rule;
}
bool same_table(const FirewallRule& first, const FirewallRule& second) {
    return first.ipv6 == second.ipv6 && first.table == second.table;
}
std::string restore_line(const char* operation, const Iptables::TaggedRule& row) {
    tag_valid(row.tag);
    auto args = row.rule.arguments();
    args.insert(args.begin(), {operation, row.rule.chain});
    args.insert(args.end(), {"-m", "comment", "--comment", row.tag});
    std::string line;
    for (const auto& arg : args) {
        // The typed grammar currently emits only these unquoted tokens. Fail
        // closed if future fields need quoting; never splice arbitrary text.
        if (arg.empty() || arg.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-:/,!=[]") != std::string::npos)
            invalid("firewall restore token requires unsupported quoting");
        if (!line.empty()) line += ' ';
        line += arg;
    }
    return line + '\n';
}
}
std::vector<std::string> FirewallRule::arguments() const {
    const std::set<std::string> all{"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"};
    const bool hook = all.contains(chain) &&
        ((table == "filter" && (chain == "INPUT" || chain == "OUTPUT" || chain == "FORWARD")) || table == "mangle" ||
         (table == "nat" && chain != "FORWARD") || (table == "raw" && (chain == "PREROUTING" || chain == "OUTPUT")));
    if (!hook) invalid("invalid firewall table or hook");
    if ((!input.empty() && (chain == "OUTPUT" || chain == "POSTROUTING")) ||
        (!output.empty() && (chain == "INPUT" || chain == "PREROUTING"))) invalid("invalid firewall interface selector for hook");
    if (input.empty() && output.empty() && source.empty() && destination.empty()) invalid("firewall rule requires a traffic scope");
    if (target != "ACCEPT" && target != "DROP" && target != "RETURN" && target != "MASQUERADE" && target != "DNAT")
        invalid("invalid firewall target");
    if ((target == "MASQUERADE" && (table != "nat" || chain != "POSTROUTING")) ||
        (target == "DNAT" && (table != "nat" || (chain != "PREROUTING" && chain != "OUTPUT")))) invalid("invalid NAT hook");
    if (negate_output && output.empty()) invalid("negated firewall output missing");
    std::vector<std::string> args;
    if (!input.empty()) { Netbox::interface_name(input); args.insert(args.end(), {"-i", input}); }
    if (!output.empty()) {
        Netbox::interface_name(output);
        if (negate_output) args.push_back("!");
        args.insert(args.end(), {"-o", output});
    }
    for (const auto& [flag, address] : {std::pair{"-s", source}, std::pair{"-d", destination}})
        if (!address.empty()) args.insert(args.end(), {flag, config::NetworkPrefix::parse(address, ipv6).network()});
    if (!protocol.empty()) {
        if (protocol != "tcp" && protocol != "udp") invalid("invalid firewall port protocol");
        args.insert(args.end(), {"-p", protocol, "-m", protocol});
    }
    if (port_first || port_last) {
        if (protocol.empty()) invalid("firewall ports require TCP or UDP");
        args.insert(args.end(), {"--dport", ports(port_first, port_last, ':')});
    }
    if (established) args.insert(args.end(), {"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"});
    args.insert(args.end(), {"-j", target});
    if (target == "DNAT") {
        if (translated_address.find('/') != std::string::npos) invalid("DNAT target must be a host address");
        auto address = config::NetworkPrefix::parse(translated_address + (ipv6 ? "/128" : "/32"), ipv6).address();
        if (translated_first || translated_last) {
            if (protocol.empty()) invalid("DNAT ports require TCP or UDP");
            if (ipv6) address = "[" + address + "]";
            address += ":" + ports(translated_first, translated_last, '-');
        }
        args.insert(args.end(), {"--to-destination", address});
    } else if (!translated_address.empty() || translated_first || translated_last) invalid("unexpected NAT translation");
    return args;
}
Json::Value FirewallRule::json() const {
    arguments();
    Json::Value result;
    result["ipv6"] = ipv6; result["negate_output"] = negate_output; result["established"] = established;
    result["table"] = table; result["chain"] = chain; result["input"] = input; result["output"] = output;
    result["source"] = source; result["destination"] = destination; result["protocol"] = protocol; result["target"] = target;
    result["port_first"] = port_first; result["port_last"] = port_last; result["translated_address"] = translated_address;
    result["translated_first"] = translated_first; result["translated_last"] = translated_last;
    return result;
}
FirewallRule FirewallRule::from(const Json::Value& value) {
    FirewallRule rule;
    for (const auto& [key, field] : {std::pair{"ipv6", &rule.ipv6}, {"negate_output", &rule.negate_output}, {"established", &rule.established}}) {
        if (!value[key].isBool()) invalid("invalid stored firewall boolean");
        *field = value[key].asBool();
    }
    for (const auto& [key, field] : {std::pair{"table", &rule.table}, {"chain", &rule.chain}, {"input", &rule.input}, {"output", &rule.output},
            {"source", &rule.source}, {"destination", &rule.destination}, {"protocol", &rule.protocol}, {"target", &rule.target}, {"translated_address", &rule.translated_address}}) {
        if (!value[key].isString()) invalid("invalid stored firewall text");
        *field = value[key].asString();
    }
    for (const auto& [key, field] : {std::pair{"port_first", &rule.port_first}, {"port_last", &rule.port_last},
            {"translated_first", &rule.translated_first}, {"translated_last", &rule.translated_last}}) {
        if (!value[key].isUInt() || value[key].asUInt() > 65535) invalid("invalid stored firewall port");
        *field = value[key].asUInt();
    }
    rule.arguments(); return rule;
}
Iptables::Iptables(std::string ipv4, std::string ipv6, std::string restore4, std::string restore6)
    : executable_{std::move(ipv4), std::move(ipv6)}, restore_{std::move(restore4), std::move(restore6)} {
    for (const auto& path : {executable_[0], executable_[1], restore_[0], restore_[1]})
        if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos)
        invalid("firewall executable must be absolute");
}
ChildOutput Iptables::run(const FirewallRule& rule, const std::string& operation, const std::string& tag, int barrier) const {
    const auto args = rule.arguments();
    ChildOptions options; options.argv = {executable_[rule.ipv6], "-w", "2", "-t", rule.table, operation};
    if (barrier >= 0) options.preserve_fds.push_back(barrier);
    if (operation != "-S") {
        tag_valid(tag);
        options.argv.push_back(rule.chain);
        options.argv.insert(options.argv.end(), args.begin(), args.end());
        options.argv.insert(options.argv.end(), {"-m", "comment", "--comment", tag});
    }
    return Child(options).communicate({}, std::chrono::seconds(3), 2u << 20);
}
std::vector<std::vector<std::string>> Iptables::snapshot(const FirewallRule& rule) const {
    const auto result = run(rule, "-S"); success(result);
    size_t lines = 0;
    std::vector<std::vector<std::string>> rows;
    for (size_t offset = 0; offset < result.output.size();) {
        auto end = result.output.find('\n', offset); if (end == std::string::npos) end = result.output.size();
        if (end - offset > (64u << 10) || ++lines > 8192) throw ServiceError(ErrorCode::resource_exhausted, "firewall snapshot exceeds budget");
        const auto tokens = words(std::string_view(result.output).substr(offset, end - offset)); offset = end + 1;
        if (tokens.empty()) continue;
        if (tokens.size() < 2 || (tokens[0] != "-A" && tokens[0] != "-P" && tokens[0] != "-N"))
            throw ServiceError(ErrorCode::io_error, "unexpected firewall snapshot line");
        rows.push_back(tokens);
    }
    return rows;
}
size_t Iptables::tagged(const FirewallRule& rule, const std::string& tag) const {
    tag_valid(tag);
    size_t count = 0;
    for (const auto& tokens : snapshot(rule)) {
        if (tokens[0] != "-A") continue;
        for (size_t i = 2; i + 1 < tokens.size(); ++i) if (tokens[i] == "--comment") {
            if (tokens[++i] == tag) ++count;
        }
    }
    return count;
}
bool Iptables::contains(const FirewallRule& rule, const std::string& tag) const {
    const auto result = run(rule, "-C", tag); completed(result);
    if (result.exit_code == 1) return false;
    success(result); return true;
}
void Iptables::insert(const FirewallRule& rule, const std::string& tag, int barrier) const { success(run(rule, "-I", tag, barrier)); }
void Iptables::erase(const FirewallRule& rule, const std::string& tag, int barrier) const { success(run(rule, "-D", tag, barrier)); }
void Iptables::replace(const std::vector<TaggedRule>& before, const std::vector<TaggedRule>& after, int barrier) const {
    if (before.empty() && after.empty()) return;
    if (before.size() + after.size() > 4096) throw ServiceError(ErrorCode::resource_exhausted, "firewall transaction exceeds rule budget");
    const auto& scope = before.empty() ? after.front().rule : before.front().rule;
    std::string input = "*" + scope.table + "\n";
    for (const auto& rows : {&before, &after}) {
        std::set<std::string> tags;
        for (const auto& row : *rows) {
            row.rule.arguments(); tag_valid(row.tag);
            if (!same_table(row.rule, scope)) invalid("firewall transaction crosses table or family");
            if (!tags.insert(row.tag).second) invalid("duplicate firewall transaction identity");
        }
    }
    for (const auto& row : before) input += restore_line("-D", row);
    for (auto it = after.rbegin(); it != after.rend(); ++it) input += restore_line("-I", *it);
    input += "COMMIT\n";
    if (input.size() > (2u << 20)) throw ServiceError(ErrorCode::resource_exhausted, "firewall transaction exceeds byte budget");
    ChildOptions options; options.argv = {restore_[scope.ipv6], "--noflush", "-w", "2"};
    if (barrier >= 0) options.preserve_fds.push_back(barrier);
    success(Child(options).communicate(input, std::chrono::seconds(3), 2u << 20));
}
bool Iptables::at_head(const std::vector<TaggedRule>& rules) const {
    if (rules.empty()) return true;
    std::map<std::string, std::vector<std::string>> wanted, actual;
    for (const auto& row : rules) {
        row.rule.arguments(); tag_valid(row.tag);
        if (!same_table(row.rule, rules.front().rule)) invalid("firewall order query crosses table or family");
        wanted[row.rule.chain].push_back(row.tag);
    }
    for (const auto& tokens : snapshot(rules.front().rule)) {
        if (tokens[0] != "-A" || !wanted.contains(tokens[1]) || actual[tokens[1]].size() >= wanted[tokens[1]].size()) continue;
        std::string tag;
        for (size_t i = 2; i + 1 < tokens.size(); ++i) if (tokens[i] == "--comment") tag = tokens[++i];
        actual[tokens[1]].push_back(tag);
    }
    return actual == wanted;
}
OwnedFirewall::OwnedFirewall(int directory, uid_t owner, const Iptables& iptables, Observer observer, config::JsonFile::Observer file_observer)
    : iptables_(iptables), directory_(fcntl(directory, F_DUPFD_CLOEXEC, 3)),
      file_(directory, "network-firewall.json", owner, std::move(file_observer)), observer_(std::move(observer)), scope_(network_scope()) {
    if (directory_.get() < 0) throw std::system_error(errno, std::generic_category(), "hold firewall directory");
    const auto loaded = file_.load();
    if (loaded && loaded->recovered) throw ServiceError(ErrorCode::io_error, "firewall primary is damaged; latest inventory required");
    document_ = loaded ? loaded->value : Json::Value(Json::objectValue);
    if (!loaded) { document_["schema"] = 1; document_["rules"] = Json::Value(Json::arrayValue); }
    if (document_["schema"] != 1 || !document_["rules"].isArray() || document_["rules"].size() > 4096)
        throw ServiceError(ErrorCode::io_error, "invalid firewall inventory");
    std::set<std::pair<std::string, std::string>> keys; std::set<std::string> tags;
    for (const auto& row : document_["rules"]) {
        if (!row["owner"].isString() || !row["key"].isString() || !row["tag"].isString() ||
            !row["scope"]["boot"].isString() || !row["scope"]["namespace_device"].isUInt64() || !row["scope"]["namespace_inode"].isUInt64() ||
            (row["stage"] != "pending" && row["stage"] != "owned")) throw ServiceError(ErrorCode::io_error, "invalid firewall record");
        key_valid(row["owner"].asString()); key_valid(row["key"].asString()); tag_valid(row["tag"].asString()); FirewallRule::from(row["rule"]);
        Json::Value boot; boot["id"] = row["scope"]["boot"];
        if (config::uuid(boot) != row["scope"]["boot"].asString() || !row["scope"]["namespace_device"].asUInt64() || !row["scope"]["namespace_inode"].asUInt64())
            throw ServiceError(ErrorCode::io_error, "invalid firewall namespace identity");
        if (!keys.emplace(row["owner"].asString(), row["key"].asString()).second || !tags.insert(row["tag"].asString()).second)
            throw ServiceError(ErrorCode::io_error, "duplicate firewall record");
    }
}
Fd OwnedFirewall::barrier() const {
    // New open description per operation; the mutator inherits this flock.
    // If its daemon dies mid-exec, recovery cannot retire intents before the
    // still-live tool exits. Do not explicitly unlock the shared description.
    Fd lock(openat(directory_.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (lock.get() >= 0 && lock.get() < 3) lock = Fd(fcntl(lock.get(), F_DUPFD_CLOEXEC, 3));
    if (lock.get() < 0) throw std::system_error(errno, std::generic_category(), "open firewall operation barrier");
    if (flock(lock.get(), LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) throw ServiceError(ErrorCode::unavailable, "previous firewall operation is still running");
        throw std::system_error(errno, std::generic_category(), "lock firewall operation barrier");
    }
    return lock;
}
void OwnedFirewall::save(Json::Value next) {
    try { file_.save(next); }
    catch (const config::CommitError& error) {
        if (error.installed) { document_ = std::move(next); uncertain_ = true; }
        throw;
    }
    document_ = std::move(next); uncertain_ = false;
}
void OwnedFirewall::put(const std::string& owner, const std::string& key, const FirewallRule& rule) {
    key_valid(owner); key_valid(key); const auto spec = rule.json();
    std::lock_guard lock(mutex_);
    const auto operation = barrier();
    if (!same_scope(scope_, network_scope())) conflict("firewall worker namespace changed");
    Json::ArrayIndex index = 0;
    for (; index < document_["rules"].size(); ++index) if (document_["rules"][index]["owner"] == owner && document_["rules"][index]["key"] == key) break;
    if (index == document_["rules"].size()) {
        if (index >= 4096) throw ServiceError(ErrorCode::resource_exhausted, "firewall inventory full");
        Json::Value row; row["owner"] = owner; row["key"] = key; row["rule"] = spec; row["scope"] = scope_;
        row["tag"] = "droidvm:" + random_id(false); row["stage"] = "pending";
        // Detect an unavailable table before persisting an intent
        // that could never have reached the kernel. Never adopt a preexisting
        // rule even if an independently generated ownership tag collides.
        if (iptables_.tagged(rule, row["tag"].asString())) conflict("new firewall ownership tag already exists");
        auto next = document_; next["rules"].append(row); save(std::move(next)); point("firewall_intent_saved");
    }
    const auto row = document_["rules"][index];
    if (!same_scope(row["scope"], scope_) || FirewallRule::from(row["rule"]).arguments() != rule.arguments() ||
        row["rule"]["table"] != rule.table || row["rule"]["chain"] != rule.chain || row["rule"]["ipv6"] != rule.ipv6)
        conflict("firewall key has a different rule or scope; remove it first");
    const auto tag = row["tag"].asString();
    const auto count = iptables_.tagged(rule, tag);
    if (count > 1 || (count == 1 && !iptables_.contains(rule, tag))) conflict("firewall ownership tag duplicated or rule replaced");
    if (!count) {
        iptables_.insert(rule, tag, operation.get()); point("firewall_rule_created");
        if (iptables_.tagged(rule, tag) != 1 || !iptables_.contains(rule, tag)) conflict("firewall insertion did not converge");
    }
    if (row["stage"] != "owned") {
        auto next = document_; next["rules"][index]["stage"] = "owned"; save(std::move(next)); point("firewall_identity_saved");
    } else if (uncertain_) save(document_);
}
void OwnedFirewall::replace_table(const std::string& owner, bool ipv6, const std::string& table, const std::vector<Rule>& desired) {
    key_valid(owner); const auto scope_rule = table_scope(ipv6, table);
    if (desired.size() > 4096) throw ServiceError(ErrorCode::resource_exhausted, "firewall table plan exceeds rule budget");
    std::set<std::string> keys;
    for (const auto& row : desired) {
        key_valid(row.key); row.rule.arguments();
        if (!same_table(scope_rule, row.rule) || !keys.insert(row.key).second) invalid("invalid firewall table plan");
    }
    std::lock_guard lock(mutex_);
    const auto operation = barrier();
    if (!same_scope(scope_, network_scope())) conflict("firewall worker namespace changed");
    auto selected = [&](const Json::Value& row) {
        return row["owner"] == owner && row["rule"]["ipv6"] == ipv6 && row["rule"]["table"] == table;
    };
    Json::Value retained(Json::arrayValue), present(Json::arrayValue);
    std::map<std::string, Json::Value> current;
    std::vector<Iptables::TaggedRule> before, ordered;
    bool unchanged = true;
    for (const auto& row : document_["rules"]) {
        if (!selected(row)) {
            if (row["owner"] == owner && keys.contains(row["key"].asString())) conflict("firewall key belongs to another table");
            retained.append(row); continue;
        }
        if (!same_scope(row["scope"], scope_)) conflict("firewall table plan has a different scope; recover it first");
        const auto rule = FirewallRule::from(row["rule"]); const auto tag = row["tag"].asString();
        const auto count = iptables_.tagged(rule, tag);
        if (count > 1 || (count == 1 && !iptables_.contains(rule, tag))) conflict("firewall ownership tag duplicated or rule replaced");
        if (count) { before.push_back({rule, tag}); present.append(row); }
        if (!count || row["stage"] != "owned") unchanged = false;
        current.emplace(row["key"].asString(), row);
    }
    unchanged = unchanged && current.size() == desired.size();
    for (const auto& row : desired) {
        const auto it = current.find(row.key);
        if (it == current.end() || FirewallRule::from(it->second["rule"]).arguments() != row.rule.arguments() ||
            it->second["rule"]["chain"] != row.rule.chain) { unchanged = false; continue; }
        ordered.push_back({row.rule, it->second["tag"].asString()});
    }
    if (unchanged && iptables_.at_head(ordered)) { if (uncertain_) save(document_); return; }
    if (retained.size() + present.size() + desired.size() > 4096)
        throw ServiceError(ErrorCode::resource_exhausted, "firewall update needs space for both generations");
    Json::Value pending = document_; pending["rules"] = retained;
    for (const auto& row : retained) if (row["owner"] == owner) keys.insert(row["key"].asString());
    for (auto row : present) {
        std::string retired;
        do { retired = "retired:" + random_id(false); } while (!keys.insert(retired).second);
        row["key"] = retired; pending["rules"].append(row);
    }
    Json::Value installed = document_; installed["rules"] = retained;
    std::vector<Iptables::TaggedRule> after;
    for (const auto& desired_row : desired) {
        Json::Value row; row["owner"] = owner; row["key"] = desired_row.key; row["rule"] = desired_row.rule.json(); row["scope"] = scope_;
        row["tag"] = "droidvm:" + random_id(false); row["stage"] = "pending";
        if (iptables_.tagged(desired_row.rule, row["tag"].asString())) conflict("new firewall ownership tag already exists");
        pending["rules"].append(row); after.push_back({desired_row.rule, row["tag"].asString()});
        row["stage"] = "owned"; installed["rules"].append(row);
    }
    save(std::move(pending)); point("firewall_batch_intent_saved");
    iptables_.replace(before, after, operation.get()); point("firewall_batch_committed");
    for (const auto& row : before) if (iptables_.tagged(row.rule, row.tag)) conflict("old firewall generation remains after update");
    for (const auto& row : after) if (iptables_.tagged(row.rule, row.tag) != 1 || !iptables_.contains(row.rule, row.tag))
        conflict("firewall table update did not converge");
    if (!iptables_.at_head(after)) conflict("firewall table update lost required ordering");
    save(std::move(installed)); point("firewall_batch_identity_saved");
}
void OwnedFirewall::remove_at(Json::ArrayIndex index, int barrier) {
    const auto row = document_["rules"][index];
    const auto rule = FirewallRule::from(row["rule"]); const auto tag = row["tag"].asString();
    if (row["scope"]["boot"] == scope_["boot"]) {
        if (!same_scope(scope_, network_scope())) conflict("firewall worker namespace changed");
        if (!same_scope(row["scope"], scope_)) conflict("firewall namespace changed");
        const auto count = iptables_.tagged(rule, tag);
        if (count > 1 || (count == 1 && !iptables_.contains(rule, tag))) conflict("firewall ownership tag duplicated or rule replaced");
        if (count) {
            point("before_firewall_delete"); iptables_.erase(rule, tag, barrier); point("firewall_rule_deleted");
            if (iptables_.tagged(rule, tag)) conflict("firewall removal did not converge");
        }
    }
    auto next = document_; next["rules"].removeIndex(index, nullptr); save(std::move(next)); point("firewall_record_removed");
}
void OwnedFirewall::remove(const std::string& owner, const std::string& key) {
    key_valid(owner); key_valid(key); std::lock_guard lock(mutex_);
    const auto operation = barrier();
    for (Json::ArrayIndex i = 0; i < document_["rules"].size(); ++i)
        if (document_["rules"][i]["owner"] == owner && document_["rules"][i]["key"] == key) { remove_at(i, operation.get()); return; }
    if (uncertain_) save(document_);
}
Json::Value OwnedFirewall::cleanup_locked(const std::string* owner) {
    const auto operation = barrier();
    Json::Value errors(Json::arrayValue);
    for (auto i = document_["rules"].size(); i > 0; --i) {
        const auto row = document_["rules"][i - 1];
        if (owner && row["owner"] != *owner) continue;
        try { remove_at(i - 1, operation.get()); }
        catch (const std::exception& error) { Json::Value value; value["owner"] = row["owner"]; value["key"] = row["key"]; value["error"] = error.what(); errors.append(value); }
    }
    if (errors.empty() && uncertain_) save(document_);
    return errors;
}
Json::Value OwnedFirewall::cleanup(const std::string& owner) { key_valid(owner); std::lock_guard lock(mutex_); return cleanup_locked(&owner); }
Json::Value OwnedFirewall::recover_all() { std::lock_guard lock(mutex_); return cleanup_locked(nullptr); }
Json::Value OwnedFirewall::inventory() const { std::lock_guard lock(mutex_); return document_; }
}
