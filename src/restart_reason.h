#pragma once

#include <Arduino.h>

namespace honeyopus {

// Persisted restart-reason tracking. Every deliberate ESP.restart()
// site goes through restart_with(): we stamp a short reason label and
// bump a per-reason counter in NVS before rebooting. On boot,
// restart_log_on_boot() prints what happened last time and the running
// totals — turning what used to be silent self-heal events into a
// trail you can correlate with logs and uptime. See ESP32 stability
// review WD2.
//
// Reason labels are short tokens; keep them stable across firmware
// versions so historical counters remain meaningful. Add new labels
// rather than renaming existing ones.
namespace restart {

inline constexpr const char* kReasonHeapLow      = "heap_low";
inline constexpr const char* kReasonWifiOutage   = "wifi_outage";
inline constexpr const char* kReasonTelnetStuck  = "telnet_stuck";
inline constexpr const char* kReasonPortalSaved  = "portal_saved";
inline constexpr const char* kReasonOomNew       = "oom_new";
inline constexpr const char* kReasonUserAction   = "user_action";

// Print last-restart info + running counters. Call once from setup().
void log_on_boot();

// Stamp the reason in NVS, then ESP.restart(). Does not return.
[[noreturn]] void restart_with(const char* reason);

// Loop-section breadcrumb. Update before each section in loop() so a
// WDT panic / hard fault leaves a trail: the next boot can print which
// section was running just before the reset. Stored in RTC slow memory,
// so it survives software resets but not full power cycles.
//
// `tag` MUST point to a string literal (or any address that's stable
// across resets — flash addresses are). We store the pointer directly,
// not a copy, to keep the per-call cost a single 32-bit write.
//
// See ESP32 stability review WD1.
void breadcrumb(const char* tag);

// Print the last breadcrumb captured before the previous reset, if
// any. Call once from setup(), right after log_on_boot().
void breadcrumb_log_on_boot();

// Append the persisted restart-reason summary to `out` as a JSON
// object (no surrounding braces handled by caller; this writes the
// fields in K/V form). Used by /health.json so operators can see
// the device's history of self-heals from a browser.
//
// Shape:
//   "restart": {
//     "last_reason": "heap_low",
//     "last_uptime_s": 91234,
//     "total": 5,
//     "counts": { "heap_low": 3, "wifi_outage": 2, ... }
//   }
//
// `out` is appended to; caller writes the surrounding key + braces.
void summary_json(String& out);

} // namespace restart
} // namespace honeyopus
