#include "geoip.h"
#include "config.h"
#include "wifi_manager.h"   // wifi_online_uptime_ms — DNS warmup gate
#include "dns_cache.h"      // pre-resolve + cache to suppress framework [E] DNS log

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <vector>

namespace honeyopus {

// In-memory GeoIP cache. Geolocation for an IP address effectively never
// changes within a honeypot uptime, so once a free GeoIP provider tells us
// (country, city, isp, asn, lat, lon) for an IP we can reuse it for every
// subsequent attack from the same IP. This avoids:
//   * burning quota on rate-limited providers (ip-api.com: 45 req/min)
//   * blowing TLS heap on every repeat brute-forcer
//   * flooding logs with empty lookups when the provider transiently 5xxs
//
// Bounded LRU; eviction is by oldest last_used (refreshed on hit).
namespace {
struct GeoEntry {
    String   ip;
    uint32_t last_used;     // millis()/1000 — touched on insert + hit
    String   country;
    String   country_code;
    String   city;
    String   region;
    String   isp;
    String   asn;
    float    lat = 0.0f;
    float    lon = 0.0f;
};

constexpr size_t kGeoCacheMax = 64;
std::vector<GeoEntry> s_geo_cache;

void geo_cache_apply_(const GeoEntry& g, AttackEntry& e) {
    e.country      = g.country;
    e.country_code = g.country_code;
    e.city         = g.city;
    e.region       = g.region;
    e.isp          = g.isp;
    e.asn          = g.asn;
    e.lat          = g.lat;
    e.lon          = g.lon;
    e.geo_resolved = true;
}

bool geo_cache_lookup_(const String& ip, AttackEntry& e) {
    uint32_t now = (uint32_t)(millis() / 1000);
    for (auto& g : s_geo_cache) {
        if (g.ip == ip) {
            g.last_used = now;
            geo_cache_apply_(g, e);
            return true;
        }
    }
    return false;
}

void geo_cache_store_(const AttackEntry& e) {
    if (!e.geo_resolved || !e.ip.length()) return;
    uint32_t now = (uint32_t)(millis() / 1000);
    for (auto& g : s_geo_cache) {
        if (g.ip == e.ip) {
            g.last_used    = now;
            g.country      = e.country;
            g.country_code = e.country_code;
            g.city         = e.city;
            g.region       = e.region;
            g.isp          = e.isp;
            g.asn          = e.asn;
            g.lat          = e.lat;
            g.lon          = e.lon;
            return;
        }
    }
    if (s_geo_cache.size() >= kGeoCacheMax) {
        size_t oldest = 0;
        for (size_t i = 1; i < s_geo_cache.size(); ++i) {
            if (s_geo_cache[i].last_used < s_geo_cache[oldest].last_used) oldest = i;
        }
        s_geo_cache.erase(s_geo_cache.begin() + oldest);
    }
    GeoEntry g;
    g.ip           = e.ip;
    g.last_used    = now;
    g.country      = e.country;
    g.country_code = e.country_code;
    g.city         = e.city;
    g.region       = e.region;
    g.isp          = e.isp;
    g.asn          = e.asn;
    g.lat          = e.lat;
    g.lon          = e.lon;
    s_geo_cache.push_back(std::move(g));
}
} // namespace

bool geoip_lookup(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.geoip_enabled) return false;

    if (geo_cache_lookup_(e.ip, e)) return true;

    String url = cfg.geoip_url;
    int idx = url.indexOf("{ip}");
    if (idx < 0) {
        if (url.endsWith("/")) url += e.ip;
        else url += "/" + e.ip;
    } else {
        url = url.substring(0, idx) + e.ip + url.substring(idx + 4);
    }

    // DNS warmup gate. Same rationale as the intel reporters: the
    // first geoip request after every reconnect was emitting a
    // [E] DNS Failed for ip-api.com line. 8 s of post-GOT_IP grace
    // covers the resolver settle time empirically.
    static const uint32_t kGeoDnsWarmupMs = 8000;
    {
        uint32_t up = wifi_online_uptime_ms();
        if (up == 0) {
            Serial.println("[geoip] skip — STA not online");
            return false;
        }
        if (up < kGeoDnsWarmupMs) {
            Serial.printf("[geoip] skip — STA online %ums (DNS warmup, need %ums)\n",
                          (unsigned)up, (unsigned)kGeoDnsWarmupMs);
            return false;
        }
    }

    // DNS gate. Pre-resolve via the application cache so steady-state
    // resolver flakiness doesn't repeatedly emit
    //   [E][WiFiGeneric.cpp:1583] hostByName(): DNS Failed for ip-api.com
    // After a successful resolve the result is cached for an hour;
    // after a failed one, retries are suppressed for 30 s.
    {
        String host;
        if (dns_cache_extract_host(url, host)) {
            IPAddress ip;
            if (!dns_cache_resolve(host.c_str(), ip)) {
                Serial.printf("[geoip] skip — dns negative-cached for %s\n",
                              host.c_str());
                return false;
            }
        }
    }

    // Heap gate. mbedTLS handshake (HTTPS endpoints) needs ~30-50 KB of
    // contiguous heap; plain HTTP is much cheaper but HTTPClient still
    // allocates response buffers. Skipping when heap is fragmented
    // protects the rest of the system from a fail-fast cascade —
    // geoip is best-effort metadata, not a load-bearing path. See
    // ESP32 stability review E4.
    const bool tls_url = url.startsWith("https://");
    const size_t need_heap   = tls_url ? 32u * 1024u : 12u * 1024u;
    const size_t need_largest = tls_url ? 24u * 1024u :  8u * 1024u;
    size_t free_heap = ESP.getFreeHeap();
    size_t largest   = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    if (free_heap < need_heap || largest < need_largest) {
        Serial.printf("[geoip] skip — heap low (free=%u largest=%u need=%u/%u tls=%s)\n",
                      (unsigned)free_heap, (unsigned)largest,
                      (unsigned)need_heap, (unsigned)need_largest,
                      tls_url ? "yes" : "no");
        return false;
    }

    HTTPClient http;
    bool ok = false;
    if (tls_url) {
        WiFiClientSecure cs;
        cs.setInsecure();
        ok = http.begin(cs, url);
    } else {
        ok = http.begin(url);
    }
    if (!ok) return false;
    http.setTimeout(8000);
    int code = http.GET();
    if (code != 200) {
        http.end();
        return false;
    }
    String body = http.getString();
    http.end();

    JsonDocument d;
    if (deserializeJson(d, body) != DeserializationError::Ok) return false;

    // ip-api.com uses "status":"success"; ipapi.co/co just returns fields.
    String status = (const char*)(d["status"] | "");
    if (status.length() && status != "success") return false;

    // Try common field names across providers.
    auto pick = [&](std::initializer_list<const char*> keys) -> String {
        for (auto k : keys) {
            const char* v = d[k] | (const char*)nullptr;
            if (v && *v) return String(v);
        }
        return String("");
    };
    e.country      = pick({"country", "country_name"});
    e.country_code = pick({"countryCode", "country_code", "country"});
    if (e.country_code.length() > 3) e.country_code = e.country_code.substring(0, 2);
    e.city         = pick({"city"});
    e.region       = pick({"regionName", "region", "state"});
    e.isp          = pick({"isp", "org"});
    e.asn          = pick({"as", "asn"});
    if (d["lat"].is<float>())  e.lat = d["lat"].as<float>();
    if (d["lon"].is<float>())  e.lon = d["lon"].as<float>();
    if (d["latitude"].is<float>())  e.lat = d["latitude"].as<float>();
    if (d["longitude"].is<float>()) e.lon = d["longitude"].as<float>();
    e.geo_resolved = e.country.length() || e.city.length() || e.lat != 0;
    if (e.geo_resolved) geo_cache_store_(e);
    return e.geo_resolved;
}

} // namespace honeyopus
