#pragma once

#include "attack_log.h"

namespace honeymire {

// Submits e to AbuseIPDB if enabled. Sets e.reported_abuseipdb on success.
bool intel_report_abuseipdb(AttackEntry& e);

// Submits e to AlienVault OTX as a tiny one-IP pulse. Sets e.reported_otx.
bool intel_report_otx(AttackEntry& e);

// Submits e to DShield.org if enabled.
bool intel_report_dshield(AttackEntry& e);

// Submits e to the configured HoneyMire Hub (docs/INGEST_PROTOCOL.md).
// Sets e.reported_hub on 2xx (or on permanent 4xx so we don't retry forever).
bool intel_report_hub(AttackEntry& e);

// Convenience that runs all reporters according to config.
void intel_report_all(AttackEntry& e);

// Spawns the dedicated background reporter task. Subsequent enqueue() calls
// will trigger geo lookup + intel reporting + log update for the given attack id.
void intel_begin();
void intel_enqueue(uint32_t attack_id);

// Returns true for RFC1918 / loopback / link-local / CGNAT / IPv6 ULA & link-local.
// Used both to suppress public threat-intel reports and to badge LAN attacks
// in the dashboard.
bool intel_ip_is_private(const String& ip);

} // namespace honeymire
