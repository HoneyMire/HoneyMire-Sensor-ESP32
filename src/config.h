#pragma once

#include <Arduino.h>
#include <Preferences.h>

namespace honeyopus {

#ifndef HONEYOPUS_BOARD_NAME
#define HONEYOPUS_BOARD_NAME "ESP32"
#endif
#ifndef HONEYOPUS_HAS_PSRAM
#define HONEYOPUS_HAS_PSRAM 0
#endif

struct Config {
    // WiFi
    String wifi_ssid;
    String wifi_pass;
    String hostname = "honeyopus";

    // Honeypot banners / behavior
    String telnet_banner = "Ubuntu 18.04.6 LTS";
    String ssh_banner    = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7";
    String fake_hostname = "ubuntu";
    String fake_user     = "root";
    uint8_t login_attempts_before_accept = 3; // accept on the Nth attempt to look weak
    bool   telnet_enabled = true;
    bool   ssh_enabled    = true;

    // Dashboard auth
    bool   dashboard_auth_enabled = false;
    String dashboard_user = "admin";
    String dashboard_pass = "honeyopus";

    // Geolocation
    bool   geoip_enabled  = true;
    // Default uses ip-api.com free endpoint (no key, ~45 req/min).
    String geoip_url      = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,regionName,lat,lon,isp,org,as";

    // Intel reporting
    bool   abuseipdb_enabled = false;
    String abuseipdb_key     = "";
    String abuseipdb_comment = "Brute-force login attempt captured by HoneyOpus on " HONEYOPUS_BOARD_NAME ".";
    bool   otx_enabled       = false;
    String otx_key           = "";
    String otx_pulse_name    = "HoneyOpus " HONEYOPUS_BOARD_NAME " SSH/Telnet Brute-force";
    // If set, every reboot reuses this exact pulse id instead of creating
    // a new one (the previous behavior fragmented data across many pulses
    // — one per reboot). Leave empty to fall back to the cached/created
    // pulse-by-name behavior.
    String otx_pulse_id      = "69f726101fd2d1e4eba3a886";

    // Time / timezone — POSIX TZ string. Default is Central European Time with
    // EU DST rules (last Sunday of March → last Sunday of October at 03:00).
    String tz           = "CET-1CEST,M3.5.0,M10.5.0/3";
    String ntp_server1  = "pool.ntp.org";
    String ntp_server2  = "time.cloudflare.com";
    String ntp_server3  = "time.google.com";

    // Display
    uint16_t display_on_seconds = 30;     // hard ceiling for screen-on time
    uint16_t attack_icon_seconds = 15;    // duration of attack icon flash

    // Storage caps
    uint16_t max_sessions       = 50;     // ring-buffer of asciicast files
    uint16_t max_attack_entries = 100;    // attack log ring buffer
    uint16_t max_session_dir_kb = 1024;   // total bytes cap for /sessions (KB); 0=unlimited
};

class ConfigStore {
public:
    bool begin();
    Config& get() { return cfg_; }
    bool save();
    bool load();
    void reset();
private:
    Config cfg_;
    Preferences prefs_;
};

extern ConfigStore g_config;

// Re-applies cfg.tz / cfg.ntp_server* to libc + lwIP SNTP. Safe to call from
// any task. Internally the NTP server names are copied into static heap
// buffers we own forever (lwIP's sntp_setservername stores its argument as a
// raw pointer, so we must hand it stable storage).
void apply_time_config();

} // namespace honeyopus
