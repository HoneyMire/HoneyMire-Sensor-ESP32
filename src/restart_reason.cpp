#include "restart_reason.h"

#include <Preferences.h>
#include <esp_attr.h>

namespace honeymire {
namespace restart {

// RTC slow-memory breadcrumb. Marked RTC_NOINIT_ATTR so it survives a
// software reset (panic, esp_restart) without being zero'd by the
// startup code. A canary distinguishes "we crashed mid-loop" from
// "this is a fresh power cycle" (where the SRAM contents are random).
static RTC_NOINIT_ATTR const char* s_bc_tag;
static RTC_NOINIT_ATTR uint32_t    s_bc_canary;
static constexpr uint32_t          kBcCanary = 0xC0FFEE42;

// NVS namespace + key shape:
//   "rstr" / "last"            → last reason label (string)
//   "rstr" / "last_uptime"     → uptime in seconds at the moment of restart
//   "rstr" / "<reason>_n"      → per-reason counter (uint32_t)
//   "rstr" / "total"           → sum of all reason counters
// Keys stay under the 15-char NVS limit.
static const char* kNs = "rstr";

void log_on_boot() {
    Preferences p;
    if (!p.begin(kNs, true)) {
        Serial.println("[restart] no prior reason recorded");
        return;
    }
    String last = p.getString("last", "");
    uint32_t at = p.getUInt("last_uptime", 0);
    uint32_t total = p.getUInt("total", 0);
    if (last.length() == 0 && total == 0) {
        Serial.println("[restart] first boot (no reason history)");
        p.end();
        return;
    }
    Serial.printf("[restart] last=%s at_uptime=%us  total=%u",
                  last.length() ? last.c_str() : "?",
                  (unsigned)at, (unsigned)total);
    // Walk a small list of the labels we write so the log shows what
    // actually got bumped. Not exhaustive — unknown labels appended in
    // future firmware revisions still bump correctly, just don't appear
    // here until added.
    static const char* kLabels[] = {
        kReasonHeapLow,
        kReasonWifiOutage,
        kReasonTelnetStuck,
        kReasonPortalSaved,
        kReasonOomNew,
        kReasonUserAction,
    };
    for (const char* lbl : kLabels) {
        char key[24];
        snprintf(key, sizeof(key), "%s_n", lbl);
        uint32_t n = p.getUInt(key, 0);
        if (n) Serial.printf(" %s=%u", lbl, (unsigned)n);
    }
    Serial.println();
    p.end();
}

void summary_json(String& out) {
    Preferences p;
    if (!p.begin(kNs, true)) {
        out += "\"last_reason\":null,\"total\":0,\"counts\":{}";
        return;
    }
    String last = p.getString("last", "");
    uint32_t at_uptime = p.getUInt("last_uptime", 0);
    uint32_t total = p.getUInt("total", 0);
    out += "\"last_reason\":";
    if (last.length()) { out += '"'; out += last; out += '"'; }
    else               { out += "null"; }
    out += ",\"last_uptime_s\":";
    out += at_uptime;
    out += ",\"total\":";
    out += total;
    out += ",\"counts\":{";
    static const char* kLabels[] = {
        kReasonHeapLow, kReasonWifiOutage, kReasonTelnetStuck,
        kReasonPortalSaved, kReasonOomNew, kReasonUserAction,
    };
    bool first = true;
    for (const char* lbl : kLabels) {
        char key[24];
        snprintf(key, sizeof(key), "%s_n", lbl);
        uint32_t n = p.getUInt(key, 0);
        if (!n) continue;
        if (!first) out += ',';
        first = false;
        out += '"'; out += lbl; out += "\":"; out += n;
    }
    out += '}';
    p.end();
}

void breadcrumb(const char* tag) {
    s_bc_tag = tag;
    s_bc_canary = kBcCanary;
}

void breadcrumb_log_on_boot() {
    if (s_bc_canary != kBcCanary || s_bc_tag == nullptr) {
        Serial.println("[breadcrumb] cold boot (no prior section recorded)");
        s_bc_canary = 0;
        s_bc_tag = nullptr;
        return;
    }
    Serial.printf("[breadcrumb] last loop section before reset: %s\n", s_bc_tag);
    // Clear the canary so the next boot's log doesn't re-print stale
    // info if this boot finishes setup() and never enters loop().
    s_bc_canary = 0;
    s_bc_tag = nullptr;
}

[[noreturn]] void restart_with(const char* reason) {
    // Best-effort: never let a flash hiccup keep us from rebooting.
    // The whole point of this path is recovery; if we can't even
    // commit the counter, the reboot still has to happen.
    {
        Preferences p;
        if (p.begin(kNs, false)) {
            const char* lbl = (reason && *reason) ? reason : "unknown";
            p.putString("last", lbl);
            p.putUInt("last_uptime", (uint32_t)(millis() / 1000));
            char key[24];
            snprintf(key, sizeof(key), "%s_n", lbl);
            uint32_t n = p.getUInt(key, 0);
            p.putUInt(key, n + 1);
            uint32_t total = p.getUInt("total", 0);
            p.putUInt("total", total + 1);
            p.end();
        }
    }
    Serial.printf("[restart] reason=%s — rebooting\n",
                  reason ? reason : "?");
    Serial.flush();
    delay(50);
    ESP.restart();
    // Compiler doesn't always know ESP.restart() doesn't return.
    for (;;) {}
}

} // namespace restart
} // namespace honeymire
