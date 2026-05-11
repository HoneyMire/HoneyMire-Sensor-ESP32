#include "intel.h"
#include "config.h"
#include "geoip.h"
#include "storage.h"        // fs_exists_silent — silent cast-file probes
#include "wifi_manager.h"   // wifi_online_uptime_ms — DNS warmup gate
#include "dns_cache.h"      // pre-resolve + cache to suppress framework [E] DNS log

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <esp_heap_caps.h>
#include <vector>

namespace honeymire {

// mbedTLS handshake on ESP32-C3 needs roughly 30-50 KB of contiguous heap.
// Total free heap is not enough to know — under fragmentation we can have
// 80 KB free with a largest block under 50 KB and operator new still throws.
// Skip the request when either watermark fails to avoid the cascade
// (handshake -32512 -> LittleFS.open partial failure -> lfs assert).
static const size_t kTlsMinHeap        = 32 * 1024;
static const size_t kTlsMinLargestBlk  = 24 * 1024;
static const size_t kFlashMinHeap      = 12 * 1024;

static bool heap_ok_for_tls_(const char* tag) {
    size_t free_heap = ESP.getFreeHeap();
    size_t largest   = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    if (free_heap < kTlsMinHeap || largest < kTlsMinLargestBlk) {
        Serial.printf("[%s] skip — heap low (free=%u largest=%u min=%u/%u)\n",
                      tag, (unsigned)free_heap, (unsigned)largest,
                      (unsigned)kTlsMinHeap, (unsigned)kTlsMinLargestBlk);
        return false;
    }
    return true;
}

// Sanitize an attacker-controlled String for safe JSON serialization.
// Replaces every byte that is not safe-printable-ASCII (< 0x20 or
// >= 0x80) with '?'. Used on user/pass/command_summary/etc. before
// they're assigned to a JsonDocument — ArduinoJson serialises
// strings byte-for-byte, so a raw 0x80-0xFF byte slips through and
// the hub's Postgres jsonb input parser then rejects the request
// with "invalid byte sequence for encoding UTF8". The asciinema
// cast file has its own per-byte escape (Asciinema::writeEscaped_),
// but JSON-document fields don't go through that path.
//
// The "?" replacement is deliberate: visible to the operator on the
// hub dashboard, makes it obvious that the original byte was
// non-ASCII, doesn't pretend to be valid Unicode.
static String json_safe_(const String& s) {
    String out;
    out.reserve(s.length());
    for (size_t i = 0; i < s.length(); ++i) {
        unsigned char c = (unsigned char)s[i];
        out += (c < 0x20 || c >= 0x80) ? '?' : (char)c;
    }
    return out;
}

// DNS-warmup gate. The arduino-esp32 / lwIP DNS resolver sometimes
// returns SERVFAIL for the first few seconds after STA association
// even on healthy networks (especially noticeable right after a
// reconnect). Without this gate, the first hub/AbuseIPDB/OTX/DShield
// POST after every reconnect spammed
//   [E][WiFiGeneric.cpp:1583] hostByName(): DNS Failed for ...
//   [W][HTTPClient.cpp:1483] returnError(): error(-1): connection refused
// — the work was retried-by-attack-volume anyway, so deferring the
// first attempt for a few seconds saves the noise without missing
// reports. 8 s covers the resolver warmup empirically.
static const uint32_t kDnsWarmupMs = 8000;

static bool dns_warm_for_tls_(const char* tag) {
    uint32_t up = wifi_online_uptime_ms();
    if (up == 0) {
        Serial.printf("[%s] skip — STA not online\n", tag);
        return false;
    }
    if (up < kDnsWarmupMs) {
        Serial.printf("[%s] skip — STA online %ums (DNS warmup, need %ums)\n",
                      tag, (unsigned)up, (unsigned)kDnsWarmupMs);
        return false;
    }
    return true;
}

// Pre-resolve the URL's hostname via the application-level DNS cache.
// Returns true on hit (cached or fresh successful resolution); on
// success, lwIP's resolver cache is hot, so HTTPClient's internal
// hostByName won't re-trigger the framework [E] log. Returns false
// silently when the cache says the host is in a failure window — we
// don't even attempt the request, no [E] log fires for the rest of
// the negative-TTL window. See src/dns_cache.{h,cpp}.
static bool dns_ok_for_url_(const String& url, const char* tag) {
    String host;
    if (!dns_cache_extract_host(url, host)) {
        // Unparseable URL — let HTTPClient handle it; this gate isn't
        // meant to be a URL validator.
        return true;
    }
    IPAddress ip;
    if (!dns_cache_resolve(host.c_str(), ip)) {
        Serial.printf("[%s] skip — dns negative-cached for %s\n",
                      tag, host.c_str());
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
// report now). DOES NOT update state — call cooldown_commit_() only after a
// successful 2xx response so a failed/skipped report can be retried
// immediately instead of being suppressed for the full window.
static bool cooldown_check_(const std::vector<CdEntry>& v, const String& ip,
                            uint32_t now, uint32_t period) {
    for (auto& e : v) {
        if (e.ip == ip) {
            if (now - e.last_sec < period) return false;
            return true;
        }
    }
    return true;
}

// Record `ip` as having been successfully reported at `now`. Inserts a new
// entry or refreshes the existing one; evicts the oldest entry if the
// table is full.
static void cooldown_commit_(std::vector<CdEntry>& v, const String& ip,
                             uint32_t now) {
    for (auto& e : v) {
        if (e.ip == ip) { e.last_sec = now; return; }
    }
    if (v.size() >= kCdMax) {
        size_t oldest = 0;
        for (size_t i = 1; i < v.size(); ++i) {
            if (v[i].last_sec < v[oldest].last_sec) oldest = i;
        }
        v.erase(v.begin() + oldest);
    }
    v.push_back({ip, now});
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
    if (!dns_warm_for_tls_("abuseipdb")) return false;
    if (!dns_ok_for_url_(String("https://api.abuseipdb.com/api/v2/report"), "abuseipdb")) return false;
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
        cooldown_commit_(s_cd_abuse, e.ip, now);
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
// returns the new pulse id. Returns "" on failure. Requires a seed entry —
// OTX's /pulses/create rejects empty-indicators payloads with HTTP 400
// ("Can't create pulse without indicators"), so we seed it with the attacker
// IP from the attack that triggered creation.
static String otx_create_pulse_(const Config& cfg, const AttackEntry& seed) {
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
                       HONEYMIRE_BOARD_NAME " Telnet/SSH honeypot (HoneyMire). "
                       "Indicators are appended automatically as new attackers connect.";
    d["public"] = false;
    JsonArray tags = d["tags"].to<JsonArray>();
    tags.add("honeypot"); tags.add("brute-force"); tags.add("ssh"); tags.add("telnet");
    JsonArray inds = d["indicators"].to<JsonArray>();
    JsonObject i0 = inds.add<JsonObject>();
    i0["type"]      = "IPv4";
    i0["indicator"] = seed.ip;
    i0["role"]      = "bruteforce";
    i0["title"]     = (seed.protocol == "ssh")    ? "SSH login attempt"
                    : (seed.protocol == "telnet") ? "Telnet login attempt"
                    : (seed.protocol + " login attempt");

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

// Returns the pulse id to use, creating one if needed (seeded with `seed`).
// Empty string on failure.
static String otx_ensure_pulse_(const Config& cfg, const AttackEntry& seed) {
    // Highest priority: a user-configured fixed pulse id (set via /config or
    // hardcoded default). This guarantees every reboot publishes to the same
    // pulse instead of fragmenting data across one-pulse-per-boot.
    if (cfg.otx_pulse_id.length()) {
        return cfg.otx_pulse_id;
    }
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
    String id = otx_create_pulse_(cfg, seed);
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
    if (!dns_warm_for_tls_("otx")) return false;
    if (!dns_ok_for_url_(String("https://otx.alienvault.com/api/v1/pulses/create"), "otx")) return false;
    if (!heap_ok_for_tls_("otx")) return false;

    if (!s_otx_mtx) s_otx_mtx = xSemaphoreCreateMutex();
    xSemaphoreTake(s_otx_mtx, portMAX_DELAY);
    String pulse_id = otx_ensure_pulse_(cfg, e);
    if (!pulse_id.length()) {
        xSemaphoreGive(s_otx_mtx);
        return false;
    }

    WiFiClientSecure cs; cs.setInsecure();
    HTTPClient http;
    // The OTX Python SDK (AlienVault-OTX/OTX-Python-SDK, OTXv2.py
    // add_pulse_indicators -> edit_pulse) shows the correct way to append
    // indicators to an existing pulse is a PATCH on /api/v1/pulses/{id}
    // with body {"indicators": {"add": [ ... ]}}. The intuitive-looking
    // /pulses/{id}/indicators/ and /pulses/{id}/indicators/bulk_create
    // routes both 404 — they're not real endpoints.
    String url = "https://otx.alienvault.com/api/v1/pulses/" + pulse_id;
    if (!http.begin(cs, url.c_str())) { xSemaphoreGive(s_otx_mtx); return false; }
    http.addHeader("X-OTX-API-KEY", cfg.otx_key);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(10000);

    JsonDocument d;
    JsonArray inds = d["indicators"]["add"].to<JsonArray>();
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
    desc += json_safe_(e.user); desc += "'";
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
    // HTTPClient has no .PATCH() helper; use sendRequest("PATCH", ...).
    int code = http.sendRequest("PATCH", (uint8_t*)body.c_str(), body.length());
    String resp = http.getString();
    http.end();
    xSemaphoreGive(s_otx_mtx);

    if (code >= 200 && code < 300) {
        cooldown_commit_(s_cd_otx, e.ip, now);
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

// =====================================================================
// HoneyMire Hub reporter (docs/INGEST_PROTOCOL.md, schema "honeymire.attack/v1")
// =====================================================================

// Per-board events-payload cap. Spec §7 caps `events` at 96 KiB total
// (sum of `d` field lengths). The C3 has the tightest heap so we cap
// lower there; the S3 boards run with the protocol max. Override per env.
//
// HONEYMIRE_HUB_CAST_MAX_KB is accepted as a backwards-compatible alias
// of HONEYMIRE_HUB_EVENTS_MAX_KB so existing platformio.ini fragments
// keep working through this protocol revision.
#ifndef HONEYMIRE_HUB_EVENTS_MAX_KB
#  ifdef  HONEYMIRE_HUB_CAST_MAX_KB
#    define HONEYMIRE_HUB_EVENTS_MAX_KB HONEYMIRE_HUB_CAST_MAX_KB
#  else
#    define HONEYMIRE_HUB_EVENTS_MAX_KB 96
#  endif
#endif
static const size_t kHubEventsMaxBytes = (size_t)HONEYMIRE_HUB_EVENTS_MAX_KB * 1024;
// Spec §7 hard limits — the hub stops parsing past these regardless of
// what the firmware sends.
static const size_t kHubMaxEvents     = 2000;
static const size_t kHubMaxEventBytes = 16 * 1024;

// Hub does not need TLS handshake quite as much heap as the ones above
// because the body is large but the request is single-shot; still we use
// the same conservative gate.
static String hub_device_id_() {
    uint64_t mac = ESP.getEfuseMac();
    // Use the lower 6 bytes (the MAC). Format lowercase hex, no colons.
    char buf[24];
    snprintf(buf, sizeof(buf), "hp-%02x%02x%02x%02x%02x%02x",
             (unsigned)((mac >> 40) & 0xff), (unsigned)((mac >> 32) & 0xff),
             (unsigned)((mac >> 24) & 0xff), (unsigned)((mac >> 16) & 0xff),
             (unsigned)((mac >>  8) & 0xff), (unsigned)( mac        & 0xff));
    return String(buf);
}

static void hub_fill_hardware_(JsonObject hw) {
    hw["mcu"]      = HONEYMIRE_HW_MCU;
    hw["board"]    = HONEYMIRE_HW_BOARD;
    hw["display"]  = HONEYMIRE_HW_DISPLAY;
    hw["flash_mb"] = (uint32_t)((ESP.getFlashChipSize() + 1024 * 1024 - 1) / (1024 * 1024));
    hw["psram_kb"] = (uint32_t)(ESP.getPsramSize() / 1024);
    hw["cpu_mhz"]  = (uint32_t)getCpuFrequencyMhz();
}

// Parse one body line of a HONEYMIRE-TRANSCRIPT/1 file:
//   <DIR>:"<escaped-data>"
// where DIR is 'S' (server→client = terminal output) or 'O' (client→server
// = user input). Maps to asciicast event semantics: S→'o', O→'i'. The
// (d_off, d_len) slice contains the already-JSON-escaped payload between
// the surrounding quotes — identical shape to hub_parse_cast_line_'s
// output, so the downstream coalesce/budget/JSON-build path is
// format-agnostic from this point on.
static bool hub_parse_transcript_line_(const char* line, size_t len,
                                       char& k, size_t& d_off, size_t& d_len) {
    if (len < 4) return false;
    char dir = line[0];
    if (line[1] != ':' || line[2] != '"') return false;
    if      (dir == 'S') k = 'o';
    else if (dir == 'O') k = 'i';
    else return false;
    d_off = 3;
    size_t i = d_off;
    while (i < len) {
        if (line[i] == '"') {
            size_t bs = 0, p = i;
            while (p > d_off && line[p - 1] == '\\') { bs++; p--; }
            if ((bs & 1) == 0) {
                d_len = i - d_off;
                return true;
            }
        }
        i++;
    }
    return false;
}

// Parse one event line of an asciicast v2 file:
//   [<time>,"<k>","<escaped-data>"]
// Returns false on malformed input. `k` receives 'i' or 'o'; (d_off, d_len)
// describe the slice of `line` holding the already-JSON-escaped data
// payload (i.e. the bytes between the d field's surrounding quotes,
// suitable to embed verbatim into another JSON string).
static bool hub_parse_cast_line_(const char* line, size_t len,
                                 char& k, size_t& d_off, size_t& d_len) {
    size_t i = 0;
    while (i < len && line[i] != ',') i++;          // skip [time
    if (i >= len) return false;
    i++;
    if (i + 3 >= len || line[i] != '"') return false;
    k = line[i + 1];
    if ((k != 'i' && k != 'o') || line[i + 2] != '"') return false;
    i += 3;
    if (i >= len || line[i] != ',') return false;
    i++;
    if (i >= len || line[i] != '"') return false;
    i++;
    d_off = i;
    // Find the closing quote, skipping any escaped quotes. Track parity
    // of immediately-preceding backslashes — an even count means the
    // quote is unescaped and terminates the string.
    while (i < len) {
        if (line[i] == '"') {
            size_t bs = 0, p = i;
            while (p > d_off && line[p - 1] == '\\') { bs++; p--; }
            if ((bs & 1) == 0) {
                d_len = i - d_off;
                return true;
            }
        }
        i++;
    }
    return false;
}

// Build the `events` JSON array from the local cast file. Returns the raw
// JSON array as a String (e.g. `[{"k":"o","d":"hi"}]`); empty on failure.
// Sets `truncated` if any spec cap (per-event size, total bytes, event
// count) was hit. Consecutive same-direction events are coalesced — spec
// §3.4.3 recommends one event per direction-change.
//
// Accepts both on-disk formats produced by the recorder (selected at
// firmware build time via HONEYMIRE_USE_TRANSCRIPT):
//   - asciicast v2  — first non-blank byte is `{`; one JSON header line
//                     followed by `[t,"k","d"]` event lines.
//   - HONEYMIRE-TRANSCRIPT/1 — first non-blank byte is `H`; key:value
//                     header lines, blank-line separator, then
//                     `S:"…"` / `O:"…"` body lines.
// The wire-format `events[]` shape is identical regardless of source so
// the hub side does not need to know which the device wrote. Any other
// leading byte yields an empty result (legacy/corrupt file).
static String hub_build_events_(const String& cast_path,
                                size_t budget_bytes,
                                bool& truncated) {
    truncated = false;
    if (!cast_path.length() || budget_bytes == 0) return String();
    // Silent existence check first — calling LittleFS.open(path, "r")
    // when the file isn't there logs a noisy "[E] vfs_api.cpp:105
    // ... no permits for creation" line. The recorder's begin() can
    // fail to actually create the cast file under LittleFS pressure,
    // but entry.cast_path is still populated, so this path fires
    // routinely and is not an error condition.
    if (!fs_exists_silent(cast_path.c_str())) return String();
    File f = LittleFS.open(cast_path, "r");
    if (!f) return String();

    // Format probe: skip any leading newlines, then peek the first real
    // byte. Leaves the file pointer ON that byte so the main loop reads
    // it as part of line 1.
    int peek = -1;
    while (f.available()) {
        peek = f.peek();
        if (peek != '\n' && peek != '\r') break;
        f.read();
    }
    bool is_transcript;
    if      (peek == '{') is_transcript = false;
    else if (peek == 'H') is_transcript = true;
    else { f.close(); return String(); }

    String out;
    out.reserve(budget_bytes < 2048 ? 1024 : (budget_bytes / 2));
    out += '[';
    size_t total_d   = 0;
    size_t n_events  = 0;
    bool   first_out = true;

    // Pending coalesced event — only flushed on direction change, when the
    // per-event byte cap is hit, or at end-of-file.
    String pending;
    char   pending_k   = 0;
    size_t pending_len = 0;

    auto flush_pending = [&]() {
        if (!pending_len) return;
        if (n_events >= kHubMaxEvents) {
            truncated = true;
            pending = String();
            pending_len = 0;
            pending_k = 0;
            return;
        }
        if (!first_out) out += ',';
        out += "{\"k\":\"";
        out += pending_k;
        out += "\",\"d\":\"";
        out += pending;
        out += "\"}";
        first_out = false;
        n_events++;
        pending = String();
        pending_len = 0;
        pending_k = 0;
    };

    char buf[2048];
    // header_done flips when we've consumed the format-specific header:
    //   asciicast — exactly one line (`{...}`)
    //   transcript — every line up to and including the blank separator
    bool header_done = false;
    bool asciicast_first_line = true;
    while (f.available()) {
        size_t off = 0;
        while (off + 1 < sizeof(buf) && f.available()) {
            int c = f.read();
            if (c < 0) break;
            if (c == '\n') break;
            buf[off++] = (char)c;
        }
        buf[off] = 0;
        if (!header_done) {
            if (is_transcript) {
                // Blank line ends the transcript header.
                if (off == 0) header_done = true;
                continue;
            }
            // Asciicast: skip exactly the first (header) line.
            if (asciicast_first_line) {
                asciicast_first_line = false;
                header_done = true;
                continue;
            }
        }
        if (off == 0) continue;

        char   k;
        size_t d_off, d_len;
        bool ok = is_transcript
                  ? hub_parse_transcript_line_(buf, off, k, d_off, d_len)
                  : hub_parse_cast_line_(buf, off, k, d_off, d_len);
        if (!ok) continue;
        if (d_len == 0) continue;

        if (total_d + d_len > budget_bytes) { truncated = true; break; }

        if (pending_k && pending_k != k) flush_pending();
        if (pending_len + d_len > kHubMaxEventBytes) flush_pending();

        if (!pending_k) pending_k = k;
        // Postgres' jsonb cannot store NUL inside a text value; an
        // INSERT of a payload containing the JSON escape " "
        // fails with "22P05:   cannot be converted to text"
        // and crashes the hub. Asciinema records every byte the
        // attacker generated, and commands like `cat /proc/self/
        // cmdline` produce NUL-delimited binary output which the
        // cast file faithfully escapes as " ". Replace each
        // such 6-byte sequence with "�" (U+FFFD, Unicode
        // replacement character) so the position is preserved for
        // forensic playback. Same byte length, so pending_len /
        // total_d / kHubMaxEventBytes accounting is unchanged.
        const char* p = &buf[d_off];
        size_t i = 0;
        while (i < d_len) {
            // Find next " " (six chars: '\\','u','0','0','0','0').
            size_t j = i;
            while (j + 6 <= d_len) {
                if (p[j]   == '\\' && p[j+1] == 'u' &&
                    p[j+2] == '0'  && p[j+3] == '0' &&
                    p[j+4] == '0'  && p[j+5] == '0') break;
                j++;
            }
            if (j + 6 > d_len) {
                // No more matches in scan window; copy the rest verbatim.
                pending.concat(&p[i], d_len - i);
                break;
            }
            if (j > i) pending.concat(&p[i], j - i);
            pending.concat("\\ufffd", 6);
            i = j + 6;
        }
        pending_len += d_len;
        total_d     += d_len;
    }
    flush_pending();
    f.close();
    out += ']';
    return out;
}

bool intel_report_hub(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.hub_enabled) return false;
    if (cfg.hub_url.length() == 0 || cfg.hub_token.length() == 0) return false;
    if (e.reported_hub) return true;
    // Per spec §12.6: hub does NOT suppress LAN attacks.

    if (!dns_warm_for_tls_("hub")) return false;
    if (!dns_ok_for_url_(cfg.hub_url, "hub")) return false;
    if (!heap_ok_for_tls_("hub")) return false;

    // Catch the most common misconfiguration: pointing the ESP at
    // "localhost" or "127.0.0.1" — that's the ESP itself, not the user's
    // laptop. Print a clear warning instead of failing silently with
    // http=-1 (CONNECTION_REFUSED) over and over.
    {
        String low = cfg.hub_url; low.toLowerCase();
        if (low.indexOf("//localhost") >= 0 || low.indexOf("//127.") >= 0 ||
            low.indexOf("//[::1]") >= 0) {
            Serial.printf("[hub] WARNING: hub_url=%s — 'localhost' resolves to the ESP itself, "
                          "not your laptop. Use the LAN IP of the hub host (e.g. 192.168.x.y).\n",
                          cfg.hub_url.c_str());
        }
    }

    // Build payload --------------------------------------------------------
    JsonDocument doc;
    doc["schema"] = "honeymire.attack/v1";

    JsonObject hp = doc["honeypot"].to<JsonObject>();
    hp["device_id"]        = hub_device_id_();
    hp["firmware_version"] = HONEYMIRE_VERSION;
    hp["firmware_build"]   = __DATE__ " " __TIME__;
    hp["uptime_s"]         = (uint32_t)(millis() / 1000);
    hub_fill_hardware_(hp["hardware"].to<JsonObject>());

    JsonObject at = doc["attack"].to<JsonObject>();
    at["id"]          = e.id;
    at["ts"]          = (uint32_t)e.ts;
    at["protocol"]    = e.protocol;
    at["duration_ms"] = e.duration_ms;

    JsonObject src = at["source"].to<JsonObject>();
    src["ip"]   = e.ip;
    src["port"] = e.port;

    JsonObject au = at["auth"].to<JsonObject>();
    au["user"]          = json_safe_(e.user);
    au["pass"]          = json_safe_(e.pass);
    au["authenticated"] = e.authenticated;
    au["attempts"]      = e.auth_attempts;

    if (e.pubkeys.length()) {
        // pubkeys field stores one OpenSSH-format line per offered key:
        //   "<type> <SHA256:fp> [base64key]"
        // Spec §3.4.2 wants {type, fingerprint, key} objects.
        JsonArray pk = au["ssh_pubkeys"].to<JsonArray>();
        int start = 0;
        while (start < (int)e.pubkeys.length()) {
            int nl = e.pubkeys.indexOf('\n', start);
            String line = (nl < 0) ? e.pubkeys.substring(start)
                                   : e.pubkeys.substring(start, nl);
            line.trim();
            if (line.length()) {
                int sp1 = line.indexOf(' ');
                int sp2 = (sp1 >= 0) ? line.indexOf(' ', sp1 + 1) : -1;
                JsonObject o = pk.add<JsonObject>();
                if (sp1 < 0) {
                    o["type"]        = json_safe_(line);
                    o["fingerprint"] = "";
                } else if (sp2 < 0) {
                    o["type"]        = json_safe_(line.substring(0, sp1));
                    o["fingerprint"] = json_safe_(line.substring(sp1 + 1));
                } else {
                    o["type"]        = json_safe_(line.substring(0, sp1));
                    o["fingerprint"] = json_safe_(line.substring(sp1 + 1, sp2));
                    String key = line.substring(sp2 + 1);
                    if (key.length() && key.length() <= 800) o["key"] = json_safe_(key);
                }
            }
            if (nl < 0) break;
            start = nl + 1;
        }
    }

    if (e.profile.length()) {
        JsonObject cls = at["classification"].to<JsonObject>();
        cls["profile"]    = e.profile;
        cls["confidence"] = e.profile_confidence;
    }

    if (e.geo_resolved && e.country.length()) {
        JsonObject g = at["geo"].to<JsonObject>();
        if (e.country.length())      g["country"]      = e.country;
        if (e.country_code.length()) g["country_code"] = e.country_code;
        if (e.city.length())         g["city"]         = e.city;
        if (e.region.length())       g["region"]       = e.region;
        if (e.isp.length())          g["isp"]          = e.isp;
        if (e.asn.length())          g["asn"]          = e.asn;
        if (e.lat != 0.0f)           g["lat"]          = e.lat;
        if (e.lon != 0.0f)           g["lon"]          = e.lon;
    }

    JsonArray rt = at["reported_to"].to<JsonArray>();
    if (e.reported_abuseipdb) rt.add("abuseipdb");
    if (e.reported_otx)       rt.add("otx");
    if (e.reported_dshield)   rt.add("dshield");

    // attack.session — optional but recommended; carries the i/o transcript.
    JsonObject ses = at["session"].to<JsonObject>();
    ses["commands"] = e.commands;
    // Spec §3.4.3: hub defaults the asciicast it reconstructs to 80×24 if
    // `term` is absent. Both honeypots run an 80×24 PTY today, so emit it
    // explicitly so the hub doesn't have to guess.
    JsonObject term = ses["term"].to<JsonObject>();
    term["cols"] = 80;
    term["rows"] = 24;

    if (e.cast_path.length()) {
        // Spec §3.4.3 replaces the v0 inline `cast_v2` asciicast with a
        // structured `events` array — `{k:'i'|'o', d:'<bytes>'}` per
        // direction-change. The hub reconstructs the asciicast with
        // synthetic timings (§3.4.3.1), so the firmware no longer has to
        // JSON-escape ~50 KiB of byte-level events through a tight heap.
        //
        // We still keep two live copies of the events string in RAM (the
        // raw JSON inside the events_doc String, then again inside the
        // serialised body String), so we shrink the cap dynamically when
        // free heap is low.
        bool tls_url = cfg.hub_url.startsWith("https://");
        size_t tls_overhead = tls_url ? 50 * 1024 : 8 * 1024;
        size_t cushion      = 16 * 1024;
        size_t free_now     = ESP.getFreeHeap();
        size_t budget       = 0;
        if (free_now > tls_overhead + cushion) {
            budget = (free_now - tls_overhead - cushion) / 2;
        }
        size_t cap = (budget < kHubEventsMaxBytes) ? budget : kHubEventsMaxBytes;
        // Below ~2 KiB an events array is essentially worthless; submit
        // metadata only and mark it truncated so the hub UI shows the gap.
        if (cap < 2 * 1024) {
            Serial.printf("[hub] heap tight (free=%u, tls=%s) — submitting without events\n",
                          (unsigned)free_now, tls_url ? "yes" : "no");
            ses["cast_truncated"] = true;
        } else {
            if (cap < kHubEventsMaxBytes) {
                Serial.printf("[hub] heap=%u — capping events at %u B (max %u)\n",
                              (unsigned)free_now, (unsigned)cap,
                              (unsigned)kHubEventsMaxBytes);
            }
            bool truncated = false;
            String events_json = hub_build_events_(e.cast_path, cap, truncated);
            if (events_json.length() > 2) {     // not just "[]"
                // serialized() embeds the raw JSON verbatim — without this
                // ArduinoJson would re-escape every quote and backslash,
                // doubling the payload and corrupting the data.
                ses["events"] = serialized(events_json);
            }
            ses["cast_truncated"] = truncated;
        }
    }

    String body;
    serializeJson(doc, body);
    doc.clear();

    // POST -----------------------------------------------------------------
    String url = cfg.hub_url;
    while (url.length() && url[url.length() - 1] == '/') url.remove(url.length() - 1);
    url += "/api/v1/ingest";

    bool tls = url.startsWith("https://");
    size_t free_before  = ESP.getFreeHeap();
    size_t largest_before = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);

    HTTPClient http;
    int code = -1;
    String resp;
    // We use the same setInsecure() pattern as the other reporters because
    // the ESP can't realistically ship a CA bundle. Timeouts are generous
    // because we may push up to 200 KiB to a hub on a slow link.
    if (tls) {
        WiFiClientSecure cs;
        cs.setInsecure();
        cs.setHandshakeTimeout(15);
        if (!http.begin(cs, url)) {
            Serial.printf("[hub] http.begin() rejected url=%s\n", url.c_str());
            return false;
        }
        http.addHeader("Authorization", String("Bearer ") + cfg.hub_token);
        http.addHeader("Content-Type", "application/json; charset=utf-8");
        http.setConnectTimeout(15000);
        http.setTimeout(20000);
        code = http.POST(body);
        if (code > 0) resp = http.getString();
        http.end();
    } else {
        WiFiClient c;
        if (!http.begin(c, url)) {
            Serial.printf("[hub] http.begin() rejected url=%s\n", url.c_str());
            return false;
        }
        http.addHeader("Authorization", String("Bearer ") + cfg.hub_token);
        http.addHeader("Content-Type", "application/json; charset=utf-8");
        http.setConnectTimeout(15000);
        http.setTimeout(20000);
        code = http.POST(body);
        if (code > 0) resp = http.getString();
        http.end();
    }

    if (code >= 200 && code < 300) {
        e.reported_hub = true;
        // Pick `dedup` and `max_hp_local_id` out of the hub's ~80-byte
        // JSON response with a manual scan rather than a second
        // JsonDocument. The request's payload doc (line 782, ~2-3 KB
        // of attack metadata) is still alive in this scope; stacking a
        // second JsonDocument under heap pressure caused stack/heap
        // corruption in the wild (Guru Meditation InstructionFetchError
        // immediately after the hub-reply printf, see field report
        // 2026-05-08). The fields are flat scalars at known keys —
        // a 20-line scan handles them safely with zero allocation.
        //
        // The drift case being recovered: a `pio run -t uploadfs` or
        // `esptool erase_flash` wipes LittleFS / NVS, our next_id_
        // resets to 1, but the DB still has rows with hp_local_id
        // 1..N — so every subsequent ingest silently ON-CONFLICT-
        // dedups against an old row. With max_hp_local_id returned in
        // every 2xx, we self-heal on the very next report and future
        // ingests land cleanly. `dedup:true` also surfaces in the log.
        bool dedup = false;
        uint32_t max_hp_local_id = 0;
        if (resp.length()) {
            // Boolean: look for `"dedup":true`. False or absent → false.
            int di = resp.indexOf("\"dedup\"");
            if (di >= 0) {
                int p = di + 7;  // past the closing quote of the key
                while (p < (int)resp.length() &&
                       (resp[p] == ' ' || resp[p] == ':')) p++;
                if (p + 4 <= (int)resp.length() &&
                    resp.substring(p, p + 4) == "true") {
                    dedup = true;
                }
            }
            // Unsigned integer: look for `"max_hp_local_id":<digits>`.
            // null or absent → leave at 0.
            int mi = resp.indexOf("\"max_hp_local_id\"");
            if (mi >= 0) {
                int p = mi + 17;  // past the closing quote of the key
                while (p < (int)resp.length() &&
                       (resp[p] == ' ' || resp[p] == ':')) p++;
                while (p < (int)resp.length() &&
                       resp[p] >= '0' && resp[p] <= '9') {
                    max_hp_local_id = max_hp_local_id * 10 + (resp[p] - '0');
                    p++;
                }
            }
        }
        if (max_hp_local_id > 0) {
            g_attack_log.bumpNextIdAtLeast(max_hp_local_id + 1);
        }
        Serial.printf("[hub] %s id=%u reported, http=%d (%u B body)%s\n",
                      e.ip.c_str(), (unsigned)e.id, code, (unsigned)body.length(),
                      dedup ? " DEDUP" : "");
        return true;
    }
    // Spec §4: 4xx (other than 429) are permanent — don't retry. Mark as
    // "reported" so we don't keep re-uploading rejected payloads forever.
    if (code >= 400 && code < 500 && code != 429) {
        e.reported_hub = true;
        Serial.printf("[hub] %s id=%u rejected http=%d resp=%s (dropped)\n",
                      e.ip.c_str(), (unsigned)e.id, code, resp.c_str());
        return false;
    }
    // Negative codes from HTTPClient are connection-level failures — print
    // the human-readable label so the user can tell DNS-failure from
    // TLS-handshake-failure from heap-exhaustion at a glance.
    const char* err = (code < 0) ? HTTPClient::errorToString(code).c_str() : "";
    Serial.printf("[hub] %s id=%u failed http=%d (%s) url=%s body=%uB heap=%u/%u resp=%s\n",
                  e.ip.c_str(), (unsigned)e.id, code, err, url.c_str(),
                  (unsigned)body.length(),
                  (unsigned)free_before, (unsigned)largest_before,
                  resp.c_str());
    return false;
}

// ---- DShield bulk submitter -------------------------------------------
//
// DShield is rate-strict: we MUST NOT submit more than once per 30
// minutes, MUST NOT submit at all in the first 30 minutes after boot,
// and SHOULD batch multiple captures into a single bulk POST.
//
// Each call to intel_report_dshield(e) only ENQUEUES the attack id;
// the actual POST happens later in intel_dshield_drain_(), which the
// intel task wakes up to run periodically. cooldown_check_/commit_
// pre-deduplicates same-IP entries inside a single batch so the bulk
// payload doesn't list the same attacker twice.
//
// Side effect: when the hub reporter POSTs an attack, e.reported_dshield
// is still false (the bulk POST happens up to 30 min later), so
// "dshield" won't appear in the hub payload's reported_to[] for that
// attack. The local dashboard's 🌊 icon DOES update correctly when the
// drain succeeds — g_attack_log.update(e) re-persists the flag.
static const uint32_t       kDshieldCdSec          = 15 * 60;
static const uint32_t       kDshieldMinIntervalMs  = 30u * 60u * 1000u;
static const size_t         kDshieldPendingMax     = 100;
static std::vector<CdEntry> s_cd_dshield;
static std::vector<uint32_t> s_dshield_pending;     // attack ids awaiting bulk POST
// Earliest absolute millis() we're allowed to send. Initialised to
// kDshieldMinIntervalMs so the first allowable send is at least 30 min
// after boot, satisfying "never just after booting on first attack".
static uint32_t              s_dshield_next_ms     = kDshieldMinIntervalMs;

bool intel_report_dshield(AttackEntry& e) {
    auto& cfg = g_config.get();
    if (!cfg.dshield_enabled) return false;
    if (cfg.dshield_email.length() == 0 || cfg.dshield_apikey.length() == 0) return false;
    if (e.reported_dshield) return true;
    if (intel_ip_is_private(e.ip)) {
        Serial.printf("[dshield] skip private/LAN ip=%s\n", e.ip.c_str());
        return false;
    }
    uint32_t now = (uint32_t)(millis() / 1000);
    if (!cooldown_check_(s_cd_dshield, e.ip, now, kDshieldCdSec)) {
        // Same IP already queued or recently submitted — drop the
        // duplicate so the bulk payload stays compact.
        return false;
    }
    // Bound the pending list. If we hit the cap (e.g. heavy attack burst
    // during the first-30-min boot window), drop the oldest entry to
    // make room — the newer capture is more likely to still be in the
    // attack log when we eventually drain.
    if (s_dshield_pending.size() >= kDshieldPendingMax) {
        s_dshield_pending.erase(s_dshield_pending.begin());
    }
    s_dshield_pending.push_back(e.id);
    cooldown_commit_(s_cd_dshield, e.ip, now);
    return true;
}

// Run from the intel task on each wake-up. Sends at most one POST per
// invocation, only when the 30-min interval has elapsed since the last
// send (or since boot for the very first send).
static void intel_dshield_drain_() {
    auto& cfg = g_config.get();
    if (!cfg.dshield_enabled) return;
    if (cfg.dshield_email.length() == 0 || cfg.dshield_apikey.length() == 0) return;
    if (s_dshield_pending.empty()) return;
    if (millis() < s_dshield_next_ms) return;
    if (!dns_warm_for_tls_("dshield")) return;
    if (!dns_ok_for_url_(String("https://dshield.org/api/handler/submit/"), "dshield")) return;
    if (!heap_ok_for_tls_("dshield")) return;

    JsonDocument d;
    d["email"]  = cfg.dshield_email;
    d["apikey"] = cfg.dshield_apikey;
    d["format"] = "json";
    JsonArray logs = d["logs"].to<JsonArray>();
    std::vector<uint32_t> sent_ids;
    sent_ids.reserve(s_dshield_pending.size());
    for (uint32_t id : s_dshield_pending) {
        AttackEntry e;
        if (!g_attack_log.getById(id, e)) continue;
        JsonObject o = logs.add<JsonObject>();
        o["timestamp"]     = (uint32_t)e.ts;
        o["src_ip"]        = e.ip;
        o["dst_port"]      = e.port;
        o["protocol"]      = e.protocol;
        o["username"]      = json_safe_(e.user);
        o["authenticated"] = e.authenticated;
        o["attempts"]      = e.auth_attempts;
        o["commands"]      = e.commands;
        sent_ids.push_back(id);
    }
    if (sent_ids.empty()) {
        // All pending ids were aged out of the on-disk log; drop them.
        s_dshield_pending.clear();
        return;
    }

    WiFiClientSecure cs;
    cs.setInsecure();
    cs.setHandshakeTimeout(15);
    HTTPClient http;
    if (!http.begin(cs, "https://dshield.org/api/handler/submit/")) return;
    http.addHeader("Content-Type", "application/json");
    http.setConnectTimeout(15000);
    http.setTimeout(30000);

    String body; serializeJson(d, body);
    int code = http.POST(body);
    String resp = http.getString();
    http.end();

    // Consume the 30-min window regardless of outcome. The user
    // explicitly asked for ≥30 min between attempts; respecting that on
    // failure too is safer than hammering a service that just refused.
    s_dshield_next_ms = millis() + kDshieldMinIntervalMs;

    if (code >= 200 && code < 300) {
        Serial.printf("[dshield] bulk submitted %u attacks, http=%d (%u B body)\n",
                      (unsigned)sent_ids.size(), code, (unsigned)body.length());
        for (uint32_t id : sent_ids) {
            AttackEntry e;
            if (!g_attack_log.getById(id, e)) continue;
            e.reported_dshield = true;
            g_attack_log.update(e);
        }
        s_dshield_pending.clear();
    } else {
        Serial.printf("[dshield] bulk submit failed http=%d size=%u resp=%s — retrying in 30 min\n",
                      code, (unsigned)sent_ids.size(), resp.c_str());
        // Keep pending list intact — next drain will retry the same set.
    }
}

void intel_report_all(AttackEntry& e) {
    intel_report_abuseipdb(e);
    intel_report_otx(e);
    intel_report_dshield(e);
    // Hub LAST so reported_to[] reflects the upstream reporters.
    intel_report_hub(e);
}

static void intelTask_(void*) {
    for (;;) {
        // Wake on a new attack OR after 60 s, whichever comes first. The
        // periodic wake lets the DShield bulk drain fire even when no
        // new attacks are arriving — required so the 30-min retry path
        // and the post-boot first-send still trigger.
        uint32_t id = 0;
        if (xQueueReceive(s_q, &id, pdMS_TO_TICKS(60000)) == pdTRUE) {
            AttackEntry e;
            if (g_attack_log.getById(id, e)) {
                if (!e.geo_resolved && g_config.get().geoip_enabled) geoip_lookup(e);
                intel_report_all(e);
                g_attack_log.update(e);
            }
        }
        intel_dshield_drain_();
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

} // namespace honeymire
