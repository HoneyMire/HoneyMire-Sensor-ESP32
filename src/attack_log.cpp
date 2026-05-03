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
    next_id_ = 1;
    entries_.clear();
    appends_since_compact_ = 0;
    dirty_ = false;

    // Load + dedupe by id, keeping the latest revision. The file is
    // chronological (oldest first); we walk it in order, holding a tiny
    // unordered_map to overwrite earlier revisions in place.
    if (!fs_exists_silent(LOG_PATH)) return true;
    File f = LittleFS.open(LOG_PATH, "r");
    if (!f) return true;
    std::vector<AttackEntry> chrono;
    chrono.reserve(64);
    std::unordered_map<uint32_t, size_t> idx;
    size_t raw_lines = 0;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (!line.length()) continue;
        raw_lines++;
        JsonDocument d;
        if (deserializeJson(d, line) != DeserializationError::Ok) continue;
        AttackEntry e = AttackEntry::fromJson(d.as<JsonObjectConst>());
        if (e.id >= next_id_) next_id_ = e.id + 1;
        auto it = idx.find(e.id);
        if (it == idx.end()) {
            idx[e.id] = chrono.size();
            chrono.push_back(std::move(e));
        } else {
            chrono[it->second] = std::move(e);
        }
    }
    f.close();
    // chrono is oldest-first; entries_ is newest-first.
    entries_.reserve(chrono.size());
    for (auto it = chrono.rbegin(); it != chrono.rend(); ++it) entries_.push_back(std::move(*it));
    if (raw_lines > entries_.size()) dirty_ = true;
    return true;
}

uint32_t AttackLog::nextId() { LogLock lk(mtx_); return next_id_++; }

void AttackLog::persistAppend_(const AttackEntry& e) {
    // Under extreme heap pressure (typically right after a failed mbedTLS
    // handshake) LittleFS.open can return a File whose underlying lfs_file
    // wasn't successfully registered, and the RAII close in our destructor
    // then trips an `lfs_mlist_isopen` assert and reboots the device. Skip
    // the persist write in that window — the in-RAM cache still has the
    // entry, and we'll compact-flush it later via rewriteAll_() once heap
    // recovers. dirty_ keeps that compaction from being skipped.
    if (ESP.getFreeHeap() < 12 * 1024) {
        Serial.printf("[log] append skipped — heap low (%u)\n",
                      (unsigned)ESP.getFreeHeap());
        dirty_ = true;
        return;
    }
    File f = LittleFS.open(LOG_PATH, "a");
    if (!f) {
        Serial.printf("[log] append open failed for %s\n", LOG_PATH);
        dirty_ = true;
        return;
    }
    JsonDocument d;
    JsonObject o = d.to<JsonObject>();
    e.toJson(o);
    serializeJson(d, f);
    f.println();
    f.close();
}

void AttackLog::enforceCap_() {
    size_t cap = g_config.get().max_attack_entries;
    if (cap == 0) cap = 100;
    if (entries_.size() > cap) entries_.resize(cap);
}

void AttackLog::rewriteAll_() {
    File f = LittleFS.open(LOG_PATH, "w");
    if (!f) return;
    // Persist oldest-first to keep the file chronologically ordered.
    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
        JsonDocument d;
        JsonObject o = d.to<JsonObject>();
        it->toJson(o);
        serializeJson(d, f);
        f.println();
    }
    f.close();
    dirty_ = false;
    appends_since_compact_ = 0;
}

void AttackLog::append(const AttackEntry& e) {
    LogLock lk(mtx_);
    entries_.insert(entries_.begin(), e);
    enforceCap_();
    persistAppend_(e);
    appends_since_compact_++;
    // Compact the file when it has accumulated enough duplicate-revision
    // lines that re-reading it at next boot would be wasteful. Threshold
    // tracks both raw appends and the dirty flag.
    if (dirty_ && appends_since_compact_ >= 32) {
        rewriteAll_();
    }
}

void AttackLog::update(const AttackEntry& e) {
    LogLock lk(mtx_);
    bool found = false;
    for (auto& it : entries_) {
        if (it.id == e.id) { it = e; found = true; break; }
    }
    if (!found) {
        entries_.insert(entries_.begin(), e);
        enforceCap_();
    }
    // Append-only: write the latest revision as a new line. Reads come from
    // the in-RAM cache so they're unaffected; on next boot we dedupe.
    persistAppend_(e);
    dirty_ = true;
    appends_since_compact_++;
    if (appends_since_compact_ >= 64) {
        rewriteAll_();
    }
}

std::vector<AttackEntry> AttackLog::recent(size_t limit) {
    LogLock lk(mtx_);
    if (limit == 0 || limit >= entries_.size()) return entries_;
    return std::vector<AttackEntry>(entries_.begin(), entries_.begin() + limit);
}

bool AttackLog::getById(uint32_t id, AttackEntry& out) {
    LogLock lk(mtx_);
    for (auto& e : entries_) if (e.id == id) { out = e; return true; }
    return false;
}

size_t AttackLog::count() {
    LogLock lk(mtx_);
    return entries_.size();
}

void AttackLog::clearAll() {
    LogLock lk(mtx_);
    entries_.clear();
    next_id_ = 1;
    dirty_ = false;
    appends_since_compact_ = 0;
    File f = LittleFS.open(LOG_PATH, "w");
    if (f) f.close();
}

} // namespace honeyopus
