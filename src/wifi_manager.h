#pragma once

#include <Arduino.h>

namespace honeymire {

enum class NetMode { Boot, ConnectingSTA, OnlineSTA, FallbackAP };

void wifi_begin();
void wifi_loop();

NetMode wifi_mode();
String wifi_ip_string();
String wifi_ap_ssid();          // SSID used in AP mode

// Forces AP mode for setup; persistent until creds are saved or device reboots.
void wifi_force_ap();

// Tries to (re)connect to STA using credentials in g_config.
void wifi_try_sta();

// Milliseconds since the last successful STA association (GOT_IP). 0 if
// not currently associated. Used by the intel and geoip paths to skip
// outbound HTTP/TLS work for the first few seconds after STA-up while
// the framework's DNS resolver is still warming — without it, the
// first hub/geoip POSTs after every reconnect spam
// "[E] DNS Failed for ..." and "http=-1 connection refused" before
// settling.
uint32_t wifi_online_uptime_ms();

} // namespace honeymire
