#include "attack_log.h"
#include "config.h"
#include "storage.h"

#include <LittleFS.h>
#include <algorithm>
#include <unordered_map>

namespace honeyopus {

AttackLog g_attack_log;

static const char* LOG_PATH = "/attacks/log.jsonl";

namespace {
struct LogLock {
    SemaphoreHandle_t m;
    explicit LogLock(SemaphoreHandle_t s) : m(s) { if (m) xSemaphoreTakeRecursive(m, portMAX_DELAY); }
    ~LogLock() { if (m) xSemaphoreGiveRecursive(m); }
    LogLock(const LogLock&) = delete;
    LogLock& operator=(const LogLock&) = delete;
};
}

void AttackEntry::toJson(JsonObject o) const {
    o["id"]            = id;
    o["ts"]            = (uint32_t)ts;
    o["protocol"]      = protocol;
    o["ip"]            = ip;
    o["port"]          = port;
    o["user"]          = user;
    o["pass"]          = pass;
    o["pubkeys"]       = pubkeys;
    o["authenticated"] = authenticated;
    o["commands"]      = commands;
    o["duration_ms"]   = duration_ms;
    o["cast_path"]     = cast_path;
    o["profile"]       = profile;
    o["profile_conf"]  = profile_confidence;
    o["country"]       = country;
    o["country_code"]  = country_code;
    o["city"]          = city;
    o["region"]        = region;
    o["isp"]           = isp;
    o["asn"]           = asn;
    o["lat"]           = lat;
    o["lon"]           = lon;
    o["geo_resolved"]  = geo_resolved;
    o["reported_abuseipdb"] = reported_abuseipdb;
    o["reported_otx"]  = reported_otx;
}

AttackEntry AttackEntry::fromJson(JsonObjectConst o) {
    AttackEntry e;
    e.id            = o["id"]            | 0;
    e.ts            = (time_t)(o["ts"]   | 0);
    e.protocol      = (const char*)(o["protocol"]      | "");
    e.ip            = (const char*)(o["ip"]            | "");
    e.port          = o["port"]          | 0;
    e.user          = (const char*)(o["user"]          | "");
    e.pass          = (const char*)(o["pass"]          | "");
    e.pubkeys       = (const char*)(o["pubkeys"]       | "");
    e.authenticated = o["authenticated"] | false;
    e.commands      = o["commands"]      | 0;
    e.duration_ms   = o["duration_ms"]   | 0;
    e.cast_path     = (const char*)(o["cast_path"]     | "");
    e.profile       = (const char*)(o["profile"]       | "");
    e.profile_confidence = (uint8_t)(o["profile_conf"] | 0);
    e.country       = (const char*)(o["country"]       | "");
    e.country_code  = (const char*)(o["country_code"]  | "");
    e.city          = (const char*)(o["city"]          | "");
    e.region        = (const char*)(o["region"]        | "");
    e.isp           = (const char*)(o["isp"]           | "");
    e.asn           = (const char*)(o["asn"]           | "");
    e.lat           = o["lat"]           | 0.0f;
    e.lon           = o["lon"]           | 0.0f;
    e.geo_resolved  = o["geo_resolved"]  | false;
    e.reported_abuseipdb = o["reported_abuseipdb"] | false;
    e.reported_otx       = o["reported_otx"]       | false;
    return e;
}

bool AttackLog::begin() {
    if (!mtx_) mtx_ = xSemaphoreCreateRecursiveMutex();
    LogLock lk(mtx_);
    // Discover next id and line count by scanning the log. Silent probe first
    // so first boot doesn't spam vfs_api ERROR logs.
    next_id_ = 1;
    line_count_ = 0;
    if (!fs_exists_silent(LOG_PATH)) return true;
    File f = LittleFS.open(LOG_PATH, "r");
    if (!f) return true;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (!line.length()) continue;
        line_count_++;
        JsonDocument d;
        if (deserializeJson(d, line) == DeserializationError::Ok) {
            uint32_t id = d["id"] | 0;
            if (id >= next_id_) next_id_ = id + 1;
        }
    }
    f.close();
    return true;
}

uint32_t AttackLog::nextId() { LogLock lk(mtx_); return next_id_++; }

void AttackLog::append(const AttackEntry& e) {
    LogLock lk(mtx_);
    File f = LittleFS.open(LOG_PATH, "a");
    if (!f) {
        Serial.printf("[log] append open failed for %s\n", LOG_PATH);
        return;
    }
    JsonDocument d;
    JsonObject o = d.to<JsonObject>();
    e.toJson(o);
    serializeJson(d, f);
    f.println();
    f.close();
    line_count_++;

    // Trim only when actually over the cap. Avoids the costly recent(0) read on
    // every append — that O(N) scan inside the AsyncTCP callback was killing
    // the lwIP poll task at higher attack rates.
    size_t cap = g_config.get().max_attack_entries;
    if (line_count_ > cap + 16) {     // hysteresis to amortize the rewrite cost
        auto all = recent(0);
        if (all.size() > cap) {
            all.resize(cap);
            rewriteAll_(all);
            line_count_ = all.size();
        } else {
            line_count_ = all.size();
        }
    }
}

void AttackLog::update(const AttackEntry& e) {
    LogLock lk(mtx_);
    // Append-only update: we previously read the entire log, mutated the row
    // in memory, and rewrote the whole file. With a few hundred entries that
    // pinned the recursive mutex for hundreds of ms, which was long enough
    // to starve the AsyncTCP task (telnet acceptor + web handlers all call
    // into AttackLog) and fire the 5 s task watchdog under attack flood.
    //
    // Now we just append the new revision; recent() dedupes by id, keeping
    // the latest copy. The slower full rewrite happens lazily inside
    // append()'s cap-trim path, which only runs once per ~16 new entries.
    File f = LittleFS.open(LOG_PATH, "a");
    if (!f) {
        Serial.printf("[log] update open failed for %s\n", LOG_PATH);
        return;
    }
    JsonDocument d;
    JsonObject o = d.to<JsonObject>();
    e.toJson(o);
    serializeJson(d, f);
    f.println();
    f.close();
    line_count_++;
}

std::vector<AttackEntry> AttackLog::recent(size_t limit) {
    LogLock lk(mtx_);
    // Read every line in chronological order, deduping by id (the latest
    // occurrence wins — see update() above for why duplicates can exist).
    std::vector<AttackEntry> chrono;
    chrono.reserve(64);
    std::unordered_map<uint32_t, size_t> idx; // id -> index in chrono
    File f = LittleFS.open(LOG_PATH, "r");
    if (!f) return {};
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (!line.length()) continue;
        JsonDocument d;
        if (deserializeJson(d, line) != DeserializationError::Ok) continue;
        AttackEntry e = AttackEntry::fromJson(d.as<JsonObjectConst>());
        auto it = idx.find(e.id);
        if (it == idx.end()) {
            idx[e.id] = chrono.size();
            chrono.push_back(std::move(e));
        } else {
            chrono[it->second] = std::move(e); // overwrite, keep position
        }
    }
    f.close();
    // Newest first.
    std::vector<AttackEntry> out;
    out.reserve(chrono.size());
    for (auto it = chrono.rbegin(); it != chrono.rend(); ++it) {
        out.push_back(std::move(*it));
    }
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

bool AttackLog::getById(uint32_t id, AttackEntry& out) {
    LogLock lk(mtx_);
    auto all = recent(0);
    for (auto& e : all) if (e.id == id) { out = e; return true; }
    return false;
}

size_t AttackLog::count() {
    // Delegate to recent() so duplicates from append-only updates are
    // collapsed; otherwise the displayed total drifts above the real number
    // of distinct attacks.
    return recent(0).size();
}

void AttackLog::clearAll() {
    LogLock lk(mtx_);
    // Truncate by reopening for write.
    File f = LittleFS.open(LOG_PATH, "w");
    if (f) f.close();
    line_count_ = 0;
    next_id_ = 1;
}

void AttackLog::rewriteAll_(const std::vector<AttackEntry>& v) {
    LogLock lk(mtx_);
    // recent() returns newest-first; persist oldest-first to keep the file
    // chronologically ordered.
    File f = LittleFS.open(LOG_PATH, "w");
    if (!f) return;
    for (auto it = v.rbegin(); it != v.rend(); ++it) {
        JsonDocument d;
        JsonObject o = d.to<JsonObject>();
        it->toJson(o);
        serializeJson(d, f);
        f.println();
    }
    f.close();
    line_count_ = v.size();
}

} // namespace honeyopus
