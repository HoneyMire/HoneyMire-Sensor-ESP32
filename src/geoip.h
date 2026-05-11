#pragma once

#include "attack_log.h"

namespace honeymire {

// Performs a synchronous HTTP GET against the configured GeoIP endpoint and
// fills the geo-related fields on `e`. Safe to call only from a dedicated
// network task (it blocks). Returns true if any field was filled.
bool geoip_lookup(AttackEntry& e);

} // namespace honeymire
