#include "intel.h"
#include "config.h"
#include "geoip.h"

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <esp_heap_caps.h>
#include <vector>

namespace honeyopus {

// mbedTLS handshake on ESP32-C3 needs roughly 30-50 KB of contiguous heap.
// If we attempt it below this watermark the handshake fails with -32512
// (MBEDTLS_ERR_SSL_ALLOC_FAILED) and, worse, leaves the heap fragmented in
// a way that subsequent LittleFS opens can trip lfs_file_close asserts.
// Skip the request rather than risk the cascade.
static const size_t kTlsMinHeap   = 40 * 1024;
static const size_t kFlashMinHeap = 12 * 1024;

static bool heap_ok_for_tls_(const char* tag) {
    size_t free_heap = ESP.getFreeHeap();
    if (free_heap < kTlsMinHeap) {
        Serial.printf("[%s] skip — heap low (%u < %u)\n",
                      tag, (unsigned)free_heap, (unsigned)kTlsMinHeap);
        return false;
    }
    return true;
}

// ---- per-IP report cooldowns -------------------------------------------
// AbuseIPDB enforces a 15-minute cooldown when an identical
// (IP, categories, comment) tuple is reported repeatedly — re-submitting in
// that window returns HTTP 429 and, if abused, can get the API key revoked.
// AlienVault OTX silently dedupes indicators within a pulse and applies a
// 30-req/min burst cap with a 1000-req/day quota. To stay well clear of
// both, we maintain per-provider, per-IP cooldown maps that suppress
// duplicate reports inside the configured window.
//
// Storage is a tiny bounded vector — ESP32-C3 has very little RAM and the
// honeypot will only see a handful of attacker IPs at a time. When full we
// evict the oldest entry.
struct CdEntry { String ip; uint32_t last_sec; };

static const size_t          kCdMax              = 64;
static const uint32_t        kAbuseCdSec         = 20 * 60;   // 20 min — AbuseIPDB requires >=15.
static const uint32_t        kOtxCdSec           = 15 * 60;   // 15 min — OTX dedupes anyway, but spare the burst quota.
static std::vector<CdEntry>  s_cd_abuse;
static std::vector<CdEntry>  s_cd_otx;

// Returns true if the IP is OUTSIDE the cooldown window (i.e. it's ok to
// report now). On true, the entry is updated/inserted with `now`. On false,
// the caller should skip reporting.
static bool cooldown_check_(std::vector<CdEntry>& v, const String& ip,
                            uint32_t now, uint32_t period) {
    for (auto& e : v) {
        if (e.ip == ip) {
            if (now - e.last_sec < period) return false;
            e.last_sec = now;
            return true;
        }
    }
    if (v.size() >= kCdMax) {
        // evict oldest
        size_t oldest = 0;
        for (size_t i = 1; i < v.size(); ++i) {
            if (v[i].last_sec < v[oldest].last_sec) oldest = i;
        }
        v.erase(v.begin() + oldest);
    }
    v.push_back({ip, now});
    return true;
}

// RFC1918 / loopback / link-local / CGNAT / IPv6 ULA & link-local. We never
// report these to public threat-intel feeds — submitting LAN addresses pollutes
// the dataset and can get the API key revoked.
bool intel_ip_is_private(const String& ip) {
    if (ip.length() == 0) return true;
    if (ip == "::1" || ip.startsWith("127.")) return true;
    if (ip.startsWith("10.")) return true;
    if (ip.startsWith("192.168.")) return true;
    if (ip.startsWith("169.254.")) return true;
    if (ip.startsWith("100.")) {
        int second = ip.substring(4).toInt();
        if (second >= 64 && second <= 127) return true;
    }
    if (ip.startsWith("172.")) {
        int second = ip.substring(4).toInt();
        if (second >= 16 && second <= 31) return true;
    }
    if (ip.startsWith("0.")) return true;
    if (ip.startsWith("224.") || ip.startsWith("239.")) return true;
    String low = ip; low.toLowerCase();
    if (low.startsWith("fe80:") || low.startsWith("fe80::")) return true;
    if (low.length() && (low[0] == 'f' && (low[1] == 'c' || low[1] == 'd'))) return true;
    if (low.startsWith("ff")) return true;
    return false;
}

static QueueHandle_t s_q = nullptr;

bool intel_report_abuseipdb(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.abuseipdb_enabled || cfg.abuseipdb_key.length() == 0) return false;
    if (e.reported_abuseipdb) return true;
    if (intel_ip_is_private(e.ip)) {
        Serial.printf("[abuseipdb] skip private/LAN ip=%s\n", e.ip.c_str());
        return false;
    }
    // AbuseIPDB rejects repeat (IP, categories, comment) submissions within
    // 15 min. Suppress on our side with a slightly larger window.
    uint32_t now = (uint32_t)(millis() / 1000);
    if (!cooldown_check_(s_cd_abuse, e.ip, now, kAbuseCdSec)) {
        Serial.printf("[abuseipdb] cooldown skip ip=%s\n", e.ip.c_str());
        return false;
    }
    if (!heap_ok_for_tls_("abuseipdb")) return false;

    WiFiClientSecure cs;
    cs.setInsecure();
    HTTPClient http;
    if (!http.begin(cs, "https://api.abuseipdb.com/api/v2/report")) return false;
    http.addHeader("Key", cfg.abuseipdb_key);
    http.addHeader("Accept", "application/json");
    http.addHeader("Content-Type", "application/x-www-form-urlencoded");
    http.setTimeout(10000);

    // Categories per AbuseIPDB taxonomy: 18=Brute-Force, 22=SSH, 23=IoT Targeted.
    // For Telnet attacks 14=Port Scan and 15=Hacking are also useful, but 18+23 are the
    // most descriptive and supported on every account tier.
    String cats = (e.protocol == "ssh") ? "18,22,23" : "18,23";
    String body = "ip=" + e.ip;
    body += "&categories=" + cats;
    body += "&comment=";
    String comment = cfg.abuseipdb_comment;
    comment += " [proto=" + e.protocol + " user=" + e.user + "]";
    // URL-encode comment minimally.
    for (size_t i = 0; i < comment.length(); ++i) {
        char c = comment[i];
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') body += c;
        else if (c == ' ') body += '+';
        else { char buf[4]; snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c); body += buf; }
    }

    int code = http.POST(body);
    String resp = http.getString();
    http.end();
    if (code >= 200 && code < 300) {
        e.reported_abuseipdb = true;
        Serial.printf("[abuseipdb] %s reported, http=%d\n", e.ip.c_str(), code);
        return true;
    }
    Serial.printf("[abuseipdb] failed http=%d resp=%s\n", code, resp.c_str());
    return false;
}

// ---- OTX pulse cache ----------------------------------------------------
// We keep a single long-lived pulse and POST per-attack indicators to it,
// instead of creating a new pulse for every attack (which spammed OTX). The
// pulse id is cached in NVS alongside the name it was created for; if the
// user changes otx_pulse_name in /config, we drop the cache and create a
// fresh pulse on the next report.
static SemaphoreHandle_t s_otx_mtx = nullptr;
static String s_otx_pulse_id;
static String s_otx_pulse_name_for_id;
// Backoff after a failed pulse creation. We MUST NOT keep slamming
// /pulses/create on every attack — under heap pressure it fails reliably,
// burns OTX quota, and (worse) leaves the heap fragmented for the
// LittleFS write that follows.
static uint32_t s_otx_create_backoff_until = 0;
static const uint32_t kOtxCreateBackoffSec = 5 * 60;

static void otx_load_cache_() {
    if (!s_otx_mtx) s_otx_mtx = xSemaphoreCreateMutex();
    if (s_otx_pulse_id.length()) return;
    Preferences p;
    if (p.begin("otx", true)) {
        s_otx_pulse_id          = p.getString("pid", "");
        s_otx_pulse_name_for_id = p.getString("pname", "");
        p.end();
    }
}

static void otx_save_cache_(const String& id, const String& name_used) {
    Preferences p;
    if (p.begin("otx", false)) {
        p.putString("pid",   id);
        p.putString("pname", name_used);
        p.end();
    }
    s_otx_pulse_id = id;
    s_otx_pulse_name_for_id = name_used;
}

// Create a new OTX pulse using cfg.otx_pulse_name; on success caches and
// returns the new pulse id. Returns "" on failure.
static String otx_create_pulse_(const Config& cfg) {
    if (!heap_ok_for_tls_("otx-create")) return String();
    WiFiClientSecure cs; cs.setInsecure();
    HTTPClient http;
    if (!http.begin(cs, "https://otx.alienvault.com/api/v1/pulses/create")) return String();
    http.addHeader("X-OTX-API-KEY", cfg.otx_key);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(10000);

    JsonDocument d;
    d["name"] = cfg.otx_pulse_name;
    d["description"] = "Live capture of brute-force login attempts against an "
                       "ESP32-C3 Telnet/SSH honeypot (HoneyOpus). Indicators "
                       "are appended automatically as new attackers connect.";
    d["public"] = false;
    JsonArray tags = d["tags"].to<JsonArray>();
    tags.add("honeypot"); tags.add("brute-force"); tags.add("ssh"); tags.add("telnet");
    // Empty seed is fine — indicators are appended later via /indicators.
    d["indicators"].to<JsonArray>();

    String body; serializeJson(d, body);
    int code = http.POST(body);
    String resp = http.getString();
    http.end();
    if (code < 200 || code >= 300) {
        Serial.printf("[otx] pulse-create failed http=%d resp=%s\n", code, resp.c_str());
        return String();
    }
    JsonDocument r;
    if (deserializeJson(r, resp) != DeserializationError::Ok) return String();
    String id = (const char*)(r["id"] | "");
    if (!id.length()) {
        Serial.printf("[otx] pulse-create no id in resp=%s\n", resp.c_str());
        return String();
    }
    Serial.printf("[otx] created pulse id=%s name=%s\n", id.c_str(), cfg.otx_pulse_name.c_str());
    return id;
}

// Returns the pulse id to use, creating one if needed. Empty string on failure.
static String otx_ensure_pulse_(const Config& cfg) {
    otx_load_cache_();
    if (s_otx_pulse_id.length() && s_otx_pulse_name_for_id == cfg.otx_pulse_name) {
        return s_otx_pulse_id;
    }
    // Don't retry creation if we recently failed. Repeated /pulses/create
    // attempts under heap pressure are how we triggered the lfs assertion.
    uint32_t now = (uint32_t)(millis() / 1000);
    if (now < s_otx_create_backoff_until) {
        Serial.printf("[otx] create-backoff active for %us\n",
                      (unsigned)(s_otx_create_backoff_until - now));
        return String();
    }
    String id = otx_create_pulse_(cfg);
    if (id.length()) {
        otx_save_cache_(id, cfg.otx_pulse_name);
    } else {
        s_otx_create_backoff_until = now + kOtxCreateBackoffSec;
    }
    return id;
}

bool intel_report_otx(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.otx_enabled || cfg.otx_key.length() == 0) return false;
    if (e.reported_otx) return true;
    if (intel_ip_is_private(e.ip)) {
        Serial.printf("[otx] skip private/LAN ip=%s\n", e.ip.c_str());
        return false;
    }
    // OTX dedupes indicators inside a pulse on its end, but we still want to
    // avoid burning quota / hitting the 30-req/min burst cap on a flood of
    // attempts from the same attacker.
    uint32_t now = (uint32_t)(millis() / 1000);
    if (!cooldown_check_(s_cd_otx, e.ip, now, kOtxCdSec)) {
        Serial.printf("[otx] cooldown skip ip=%s\n", e.ip.c_str());
        return false;
    }
    if (!heap_ok_for_tls_("otx")) return false;

    if (!s_otx_mtx) s_otx_mtx = xSemaphoreCreateMutex();
    xSemaphoreTake(s_otx_mtx, portMAX_DELAY);
    String pulse_id = otx_ensure_pulse_(cfg);
    if (!pulse_id.length()) {
        xSemaphoreGive(s_otx_mtx);
        return false;
    }

    WiFiClientSecure cs; cs.setInsecure();
    HTTPClient http;
    String url = "https://otx.alienvault.com/api/v1/pulses/" + pulse_id + "/indicators/";
    if (!http.begin(cs, url.c_str())) { xSemaphoreGive(s_otx_mtx); return false; }
    http.addHeader("X-OTX-API-KEY", cfg.otx_key);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(10000);

    JsonDocument d;
    JsonArray inds = d["indicators"].to<JsonArray>();
    JsonObject i = inds.add<JsonObject>();
    i["type"]      = "IPv4";
    i["indicator"] = e.ip;
    i["role"]      = "bruteforce";
    String title;
    if (e.protocol == "ssh")         title = "SSH login attempt";
    else if (e.protocol == "telnet") title = "Telnet login attempt";
    else                              title = e.protocol + " login attempt";
    i["title"] = title;

    String desc = "Brute-force capture. user='";
    desc += e.user; desc += "'";
    if (e.country_code.length()) { desc += " geo="; desc += e.country_code; }
    if (e.isp.length())          { desc += " isp="; desc += e.isp; }
    // Attacker profile, in cautious wording. The classifier is heuristic and
    // can mis-label, so we hedge ("likely", "possibly") and never assert
    // attribution. Also include the raw label + confidence for analysts who
    // want to filter on it.
    if (e.profile.length() && e.profile != "unknown" && e.profile != "lan") {
        String hint;
        if      (e.profile == "mirai")       hint = "likely automated bot (Mirai-family)";
        else if (e.profile == "iot-loader")  hint = "likely automated IoT loader";
        else if (e.profile == "scanner")     hint = "likely automated scanner";
        else if (e.profile == "scripted")    hint = "likely scripted client";
        else if (e.profile == "creds-only" ||
                 e.profile == "creds-probe") hint = "credential probe, likely automated";
        else if (e.profile == "manual")      hint = "interactive session, possibly human-operated";
        if (hint.length()) {
            desc += " behavior='"; desc += hint; desc += "'";
            desc += " (heuristic label="; desc += e.profile;
            desc += " confidence="; desc += String(e.profile_confidence); desc += "%)";
        }
    }
    i["description"] = desc;

    String body; serializeJson(d, body);
    int code = http.POST(body);
    String resp = http.getString();
    http.end();
    xSemaphoreGive(s_otx_mtx);

    if (code >= 200 && code < 300) {
        e.reported_otx = true;
        Serial.printf("[otx] %s indicator added to pulse %s, http=%d\n",
                      e.ip.c_str(), pulse_id.c_str(), code);
        return true;
    }
    // 404 means our cached pulse was deleted upstream — drop the cache so a
    // fresh pulse is created on the next attack.
    if (code == 404) {
        Serial.printf("[otx] cached pulse %s gone (404), clearing cache\n", pulse_id.c_str());
        otx_save_cache_(String(), String());
    }
    Serial.printf("[otx] failed http=%d resp=%s\n", code, resp.c_str());
    return false;
}

void intel_report_all(AttackEntry& e) {
    intel_report_abuseipdb(e);
    intel_report_otx(e);
}

static void intelTask_(void*) {
    uint32_t id;
    for (;;) {
        if (xQueueReceive(s_q, &id, portMAX_DELAY) != pdTRUE) continue;
        AttackEntry e;
        if (!g_attack_log.getById(id, e)) continue;
        if (!e.geo_resolved && g_config.get().geoip_enabled) geoip_lookup(e);
        intel_report_all(e);
        g_attack_log.update(e);
    }
}

void intel_begin() {
    if (s_q) return;
    s_q = xQueueCreate(8, sizeof(uint32_t));
    xTaskCreatePinnedToCore(intelTask_, "intel", 8192, nullptr, 1, nullptr, tskNO_AFFINITY);
}

void intel_enqueue(uint32_t id) {
    if (!s_q) return;
    xQueueSend(s_q, &id, 0);
}

} // namespace honeyopus
