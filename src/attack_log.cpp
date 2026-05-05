#include "attack_log.h"
#include "config.h"
#include "storage.h"

#include <LittleFS.h>
#include <algorithm>
#include <unordered_map>
#include <freertos/task.h>
#include <freertos/queue.h>

namespace honeyopus {

AttackLog g_attack_log;

static const char* LOG_PATH = "/attacks/log.jsonl";

// Persister-task tuning. The queue holds attack ids (uint32_t); a 0 sentinel
// means "compact the file now". 16 slots is plenty for a single ESP32-C3
// honeypot — bursts above that are extremely rare and would just block the
// caller for a few ms (xQueueSend with timeout below).
static const size_t   kPersistQueueLen   = 16;
static const uint32_t kPersistEnqueueTo  = pdMS_TO_TICKS(50);
// File-compaction triggers (moved off the producer path; the persister
// itself decides). Mirrors the previous inline thresholds.
static const size_t   kAppendCompactN    = 32;   // when dirty_ and counter exceeds
static const size_t   kUpdateCompactN    = 64;   // for update-only churn

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
    o["auth_attempts"] = auth_attempts;
    o["commands"]      = commands;
    o["duration_ms"]   = duration_ms;
    o["cast_path"]     = cast_path;
    o["telnet_persona"] = telnet_persona;
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
    o["reported_hub"]  = reported_hub;
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
    e.auth_attempts = o["auth_attempts"] | 0;
    e.commands      = o["commands"]      | 0;
    e.duration_ms   = o["duration_ms"]   | 0;
    e.cast_path     = (const char*)(o["cast_path"]     | "");
    e.telnet_persona = (const char*)(o["telnet_persona"] | "");
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
    e.reported_hub       = o["reported_hub"]       | false;
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
    if (fs_exists_silent(LOG_PATH)) {
        File f = LittleFS.open(LOG_PATH, "r");
        if (f) {
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
        }
    }

    // Spin up the persister task once. It owns ALL file I/O so async_tcp,
    // intel and ssh tasks never block on LittleFS while holding the
    // attack-log mutex. Without this, a slow LittleFS write during a flood
    // of telnet attacks freezes the dashboard for the duration of the
    // write — empirically tens to hundreds of ms each, occasionally seconds
    // when GC kicks in.
    if (!persist_q_) persist_q_ = xQueueCreate(kPersistQueueLen, sizeof(uint32_t));
    if (!persist_t_) {
        xTaskCreatePinnedToCore(&AttackLog::persistTaskTrampoline_,
                                "alog-persist",
                                4096, this, 1, &persist_t_, tskNO_AFFINITY);
    }
    return true;
}

uint32_t AttackLog::nextId() { LogLock lk(mtx_); return next_id_++; }

void AttackLog::persistAppend_(const AttackEntry& e) {
    // Under extreme heap pressure (typically right after a failed mbedTLS
    // handshake) LittleFS.open can return a File whose underlying lfs_file
    // wasn't successfully registered, and the RAII close in our destructor
    // then trips an `lfs_mlist_isopen` assert and reboots the device. Skip
    // the persist write in that window — the in-RAM cache still has the
    // entry, and we'll compact-flush it later via rewriteAllSnapshot_()
    // once heap recovers. dirty_ keeps that compaction from being skipped.
    if (ESP.getFreeHeap() < 12 * 1024) {
        Serial.printf("[log] append skipped — heap low (%u)\n",
                      (unsigned)ESP.getFreeHeap());
        LogLock lk(mtx_);
        dirty_ = true;
        return;
    }
    File f = LittleFS.open(LOG_PATH, "a");
    if (!f) {
        Serial.printf("[log] append open failed for %s\n", LOG_PATH);
        LogLock lk(mtx_);
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

void AttackLog::rewriteAllSnapshot_(const std::vector<AttackEntry>& snap) {
    // No lock held during the write — the caller passes a snapshot copy.
    // Concurrent appends that happen mid-rewrite will be re-persisted by
    // the next OP, and dedupe-on-load handles the duplicate lines.
    File f = LittleFS.open(LOG_PATH, "w");
    if (!f) return;
    // Persist oldest-first to keep the file chronologically ordered.
    for (auto it = snap.rbegin(); it != snap.rend(); ++it) {
        JsonDocument d;
        JsonObject o = d.to<JsonObject>();
        it->toJson(o);
        serializeJson(d, f);
        f.println();
    }
    f.close();
    {
        LogLock lk(mtx_);
        dirty_ = false;
        appends_since_compact_ = 0;
    }
}

void AttackLog::enqueuePersist_(uint32_t id) {
    if (!persist_q_) return;
    // Best-effort: if the persister is far behind we'd rather drop a queue
    // notification than block the producer (telnet disconnect runs on the
    // async_tcp task and MUST NOT stall). Worst case the entry stays only
    // in RAM and gets flushed by the next compaction trigger.
    (void)xQueueSend(persist_q_, &id, kPersistEnqueueTo);
}

void AttackLog::append(const AttackEntry& e) {
    {
        LogLock lk(mtx_);
        entries_.insert(entries_.begin(), e);
        enforceCap_();
        appends_since_compact_++;
    }
    enqueuePersist_(e.id);
}

void AttackLog::update(const AttackEntry& e) {
    {
        LogLock lk(mtx_);
        bool found = false;
        for (auto& it : entries_) {
            if (it.id == e.id) { it = e; found = true; break; }
        }
        if (!found) {
            entries_.insert(entries_.begin(), e);
            enforceCap_();
        }
        // Append-only on disk: write the latest revision as a new line. Reads
        // come from the in-RAM cache so they're unaffected; on next boot we
        // dedupe.
        dirty_ = true;
        appends_since_compact_++;
    }
    enqueuePersist_(e.id);
}

void AttackLog::persistTaskTrampoline_(void* arg) {
    static_cast<AttackLog*>(arg)->persistTaskRun_();
}

void AttackLog::persistTaskRun_() {
    for (;;) {
        uint32_t id = 0;
        if (xQueueReceive(persist_q_, &id, portMAX_DELAY) != pdTRUE) continue;
        if (id != 0) {
            // Snapshot the entry under the lock, then write without it.
            AttackEntry snap;
            bool have = false;
            {
                LogLock lk(mtx_);
                for (auto& it : entries_) {
                    if (it.id == id) { snap = it; have = true; break; }
                }
            }
            if (have) persistAppend_(snap);
        }

        // Compaction decision (counter-based, mirrors the previous inline
        // thresholds). Take a snapshot of the entries vector under the
        // lock, then write it without holding the lock.
        bool need_compact = false;
        std::vector<AttackEntry> snap;
        {
            LogLock lk(mtx_);
            const size_t threshold = dirty_ ? kAppendCompactN : kUpdateCompactN;
            if (appends_since_compact_ >= threshold) {
                need_compact = true;
                snap = entries_;
            }
        }
        if (need_compact) rewriteAllSnapshot_(snap);
    }
}

std::vector<AttackEntry> AttackLog::recent(size_t limit) {
    LogLock lk(mtx_);
    if (limit == 0 || limit >= entries_.size()) return entries_;
    return std::vector<AttackEntry>(entries_.begin(), entries_.begin() + limit);
}

void AttackLog::forEachRecent(size_t limit,
                              const std::function<bool(const AttackEntry&)>& fn) {
    LogLock lk(mtx_);
    size_t n = (limit == 0 || limit > entries_.size()) ? entries_.size() : limit;
    for (size_t i = 0; i < n; ++i) {
        if (!fn(entries_[i])) break;
    }
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
