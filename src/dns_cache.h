#pragma once

#include <Arduino.h>
#include <IPAddress.h>

namespace honeymire {

// Tiny application-level DNS cache. Wraps WiFi.hostByName with both
// positive and negative TTLs.
//
// Why this exists: arduino-esp32's WiFi.hostByName logs
//   [E][WiFiGeneric.cpp:1583] hostByName(): DNS Failed for <host>
// at framework level on every failure. There's no app-side knob to
// silence it. A flaky upstream DNS server therefore floods serial
// once per attack as the geoip + intel reporters each make their
// own lookups. The cache shrinks that to:
//
//   - One framework [E] line per failure-window (30 s) per host.
//   - Zero framework calls during the 1-hour positive TTL after a
//     successful lookup.
//
// Thread safety: not currently locked. All callers run on the intel
// task. If that changes, add a mutex.
//
// See also: src/wifi_manager.cpp's wifi_online_uptime_ms() — the
// 8-second post-reconnect warmup gate covers the cold-resolver
// window; this cache covers steady-state.

// Look up `host`. On success (cache hit OR fresh resolution succeeds)
// returns true and writes the IP to `out`. On failure returns false
// silently — including failures cached from a previous call within
// the negative-TTL window, in which case WiFi.hostByName is NOT
// called again, so the framework [E] log doesn't re-fire.
bool dns_cache_resolve(const char* host, IPAddress& out);

// Extract the hostname from a URL of the form "<scheme>://<host>[:port][/...]".
// Returns false if the URL doesn't look right.
bool dns_cache_extract_host(const String& url, String& host_out);

} // namespace honeymire
