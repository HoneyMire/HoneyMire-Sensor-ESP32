#include "dns_cache.h"

#include <WiFi.h>

namespace honeymire {

namespace {

struct Entry {
    String    host;
    IPAddress ip;
    uint32_t  expires_ms     = 0;  // positive cache: 0 = no entry
    uint32_t  fail_until_ms  = 0;  // negative cache: suppress retry until this time
};

// Small fixed table — we only resolve a handful of hosts (geoip, hub,
// abuseipdb, otx, dshield, plus maybe one or two NTP hosts). 8 slots
// is plenty; on overflow we evict the entry whose positive TTL or
// negative TTL is closest to expiry.
//
// arduino-esp32 6.7.0's public WiFi.hostByName takes only (host,
// IPAddress&) — no timeout overload. The framework's internal
// timeout (default 14 s) governs.
constexpr size_t   kSlots             = 8;
constexpr uint32_t kPositiveTtlMs     = 60UL * 60UL * 1000UL;  // 1 hour
constexpr uint32_t kNegativeTtlMs     = 30UL * 1000UL;         // 30 s

Entry s_slots[kSlots];

Entry* find_slot_(const char* host) {
    for (auto& e : s_slots) {
        if (e.host.length() && e.host == host) return &e;
    }
    return nullptr;
}

Entry* claim_slot_(const char* host) {
    if (Entry* hit = find_slot_(host)) return hit;
    // Prefer an empty slot.
    for (auto& e : s_slots) {
        if (e.host.length() == 0) {
            e.host = host;
            e.ip = IPAddress();
            e.expires_ms = 0;
            e.fail_until_ms = 0;
            return &e;
        }
    }
    // No empty slot — evict the entry whose latest TTL (positive or
    // negative) is the smallest, i.e. the most stale.
    Entry* victim = &s_slots[0];
    auto staleness = [](const Entry& e) {
        return (e.expires_ms > e.fail_until_ms) ? e.expires_ms : e.fail_until_ms;
    };
    for (auto& e : s_slots) {
        if (staleness(e) < staleness(*victim)) victim = &e;
    }
    victim->host = host;
    victim->ip = IPAddress();
    victim->expires_ms = 0;
    victim->fail_until_ms = 0;
    return victim;
}

} // namespace

bool dns_cache_resolve(const char* host, IPAddress& out) {
    if (!host || !*host) return false;
    uint32_t now = millis();
    Entry* hit = find_slot_(host);
    if (hit && hit->expires_ms != 0 && now < hit->expires_ms) {
        out = hit->ip;
        return true;
    }
    if (hit && hit->fail_until_ms != 0 && now < hit->fail_until_ms) {
        // Recent failure — silent skip, don't call hostByName again.
        return false;
    }
    // Fresh resolve. The framework's WiFi.hostByName may log [E] on
    // failure; that's the line we're trying to reduce. Caching the
    // result (positive or negative) means we don't re-call here for
    // kPositiveTtlMs / kNegativeTtlMs respectively.
    IPAddress ip;
    bool ok = WiFi.hostByName(host, ip);
    Entry* slot = claim_slot_(host);
    if (ok) {
        slot->ip = ip;
        slot->expires_ms = now + kPositiveTtlMs;
        slot->fail_until_ms = 0;
        Serial.printf("[dns] resolved %s = %s (cached %us)\n",
                      host, ip.toString().c_str(),
                      (unsigned)(kPositiveTtlMs / 1000));
        out = ip;
        return true;
    }
    slot->expires_ms = 0;
    slot->fail_until_ms = now + kNegativeTtlMs;
    Serial.printf("[dns] resolve failed for %s — suppressing for %us\n",
                  host, (unsigned)(kNegativeTtlMs / 1000));
    return false;
}

bool dns_cache_extract_host(const String& url, String& host_out) {
    int scheme = url.indexOf("://");
    if (scheme < 0) return false;
    int start = scheme + 3;
    if (start >= (int)url.length()) return false;
    int end = url.length();
    int slash = url.indexOf('/', start);
    if (slash >= start && slash < end) end = slash;
    int colon = url.indexOf(':', start);
    if (colon >= start && colon < end) end = colon;
    host_out = url.substring(start, end);
    return host_out.length() > 0;
}

} // namespace honeymire
