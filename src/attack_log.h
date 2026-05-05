#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <functional>

namespace honeyopus {

struct AttackEntry {
    uint32_t id = 0;            // monotonically increasing
    time_t   ts = 0;            // unix timestamp (0 if NTP not yet synced)
    String   protocol;          // "telnet" | "ssh"
    String   ip;
    uint16_t port = 0;
    String   user;
    String   pass;
    String   pubkeys;           // SSH public keys offered by attacker, one per line: "type SHA256:fp base64key"
    bool     authenticated = false;  // firmware let them past the configured threshold (hub spec §3.4.2)
    uint16_t auth_attempts = 0;      // number of credential pairs submitted (drives dashboard "Auth" column)
    uint16_t commands = 0;
    uint32_t duration_ms = 0;
    String   cast_path;         // /sessions/<file>.cast or empty
    String   telnet_persona;    // Telnet server persona (e.g., "Ubuntu", "BusyBox", "RouterOS", "OpenWrt", "DVRDVS", "HiLinux"), empty for SSH

    // Behavioural fingerprint
    String   profile;           // classifier label: "mirai", "iot-loader", "scanner", "manual", "scripted", "creds-only", "creds-probe", "lan", "unknown"
    uint8_t  profile_confidence = 0;  // 0..100

    // Geo
    String   country;           // full name, e.g. "Germany"
    String   country_code;      // "DE"
    String   city;
    String   region;
    String   isp;
    String   asn;
    float    lat = 0.0f;
    float    lon = 0.0f;
    bool     geo_resolved = false;

    // Reporting state
    bool     reported_abuseipdb = false;
    bool     reported_otx = false;
    bool     reported_hub = false;

    void toJson(JsonObject o) const;
    static AttackEntry fromJson(JsonObjectConst o);
};

// In-RAM cache of recent attacks, persisted to /attacks/log.jsonl.
// Reads (recent / count / getById) hit memory only — they never block on
// LittleFS, so async_tcp can't be starved by file I/O on the intel task.
class AttackLog {
public:
    bool begin();
    uint32_t nextId();
    void append(const AttackEntry& e);
    void update(const AttackEntry& e);            // replace-by-id in cache + append delta line
    std::vector<AttackEntry> recent(size_t limit);
    // Iterate the most recent entries under the lock without copying. The
    // visitor receives a const reference; returning false stops iteration.
    // This avoids heap spikes from copying ~16 heap-backed String fields per
    // entry × N rows when rendering pages.
    void forEachRecent(size_t limit, const std::function<bool(const AttackEntry&)>& fn);
    bool getById(uint32_t id, AttackEntry& out);
    size_t count();
    // Truncate the on-disk log. Resets next_id_ to 1.
    void clearAll();

private:
    void persistAppend_(const AttackEntry& e);    // serialise one entry as JSONL
    void rewriteAllSnapshot_(const std::vector<AttackEntry>& snap); // dump snapshot to file
    void enforceCap_();                           // keep cache within max_attack_entries
    void enqueuePersist_(uint32_t id);            // notify persister task
    static void persistTaskTrampoline_(void* arg);
    void persistTaskRun_();
    std::vector<AttackEntry> entries_;            // newest-first
    uint32_t next_id_ = 1;
    bool     dirty_   = false;                    // file has duplicate revisions, needs compaction
    size_t   appends_since_compact_ = 0;
    SemaphoreHandle_t mtx_ = nullptr;             // recursive
    QueueHandle_t     persist_q_ = nullptr;       // queue of uint32_t ids; 0 = compact
    TaskHandle_t      persist_t_ = nullptr;
};

extern AttackLog g_attack_log;

} // namespace honeyopus
