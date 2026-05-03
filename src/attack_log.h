#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

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
    bool     authenticated = false;
    uint16_t commands = 0;
    uint32_t duration_ms = 0;
    String   cast_path;         // /sessions/<file>.cast or empty

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

    void toJson(JsonObject o) const;
    static AttackEntry fromJson(JsonObjectConst o);
};

// Append-and-truncate JSONL log of attacks at /attacks/log.jsonl.
class AttackLog {
public:
    bool begin();
    uint32_t nextId();
    void append(const AttackEntry& e);
    void update(const AttackEntry& e);            // rewrite by id (rewrites whole file)
    std::vector<AttackEntry> recent(size_t limit);
    bool getById(uint32_t id, AttackEntry& out);
    size_t count();
    // Truncate the on-disk log. Resets next_id_ to 1.
    void clearAll();

private:
    void rewriteAll_(const std::vector<AttackEntry>& v);
    uint32_t next_id_ = 1;
    size_t   line_count_ = 0;       // tracked locally to avoid scanning the file on every append
    SemaphoreHandle_t mtx_ = nullptr;  // recursive: serialises all public ops + file IO
};

extern AttackLog g_attack_log;

} // namespace honeyopus
