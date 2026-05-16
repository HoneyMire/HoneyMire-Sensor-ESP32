#pragma once

#include <Arduino.h>
#include <Preferences.h>

// Some ESP32-S3 dev boards expose their visible USB jack through a
// CH340/CP2102 USB-UART chip on UART0 — not through the S3's native
// USB pins. Our shared build_flags enable ARDUINO_USB_CDC_ON_BOOT, which
// makes `Serial` the native USB-CDC instance. That instance enumerates
// fine but its output never reaches the USB-UART bridge, so the monitor
// stays silent forever even though the firmware is running. Profiles can
// define HONEYMIRE_USE_UART0_SERIAL to redirect every `Serial.print` in
// our own translation units to UART0 (`Serial0`).
// Framework .cpp files have already #included HardwareSerial.h before
// this header is reached, so this define only rewrites references in
// our code — no clash with the framework's own `extern Serial0`.
#if defined(HONEYMIRE_USE_UART0_SERIAL) && !defined(HONEYMIRE_NO_SERIAL_REMAP)
#  ifdef Serial
#    undef Serial
#  endif
#  define Serial Serial0
#endif

namespace honeymire {

#ifndef HONEYMIRE_BOARD_NAME
#define HONEYMIRE_BOARD_NAME "ESP32"
#endif
#ifndef HONEYMIRE_HAS_PSRAM
#define HONEYMIRE_HAS_PSRAM 0
#endif

struct Config {
    // WiFi
    String wifi_ssid;
    String wifi_pass;
    String hostname = "honeymire";

    // Honeypot banners / behavior
    String telnet_banner = "Ubuntu 18.04.6 LTS";
    String ssh_banner    = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7";
    String fake_hostname = "ubuntu";
    String fake_user     = "root";
    uint8_t login_attempts_before_accept = 3; // accept on the Nth attempt to look weak
    bool   telnet_enabled = true;
    // SSH default-on for boards that have heap headroom (S3 + PSRAM);
    // default-off for ESP32-C3 — libssh's residual heap (~50 KB lost
    // per session even on clean disconnect) makes sustained exposure
    // marginal there. Operator can flip via /config or the serial
    // menu without a re-flash. See ESP32 stability review S1.
#ifndef HONEYMIRE_DEFAULT_SSH_ENABLED
#define HONEYMIRE_DEFAULT_SSH_ENABLED 1
#endif
    bool   ssh_enabled    = (HONEYMIRE_DEFAULT_SSH_ENABLED != 0);

    // Dashboard auth
    bool   dashboard_auth_enabled = false;
    String dashboard_user = "admin";
    String dashboard_pass = "honeymire";
    // When true (default), clients on RFC1918 / link-local / CGNAT
    // addresses skip the basic-auth prompt — convenient on a home LAN
    // but a privacy hazard if the device sits on an untrusted network
    // (campus Wi-Fi, conference network, hotel LAN). Disable this to
    // require auth from every client.
    bool   dashboard_lan_bypass = true;

    // WiFi reliability tuning. The outbound probe (TCP/53 to the
    // gateway) is a coarse "do packets leave the LAN" check. Many
    // routers don't accept TCP/53 on the gateway IP, so the probe can
    // false-negative on healthy networks. By default the probe is
    // observability-only — failures are logged but do NOT force STA
    // reconnects. Enable wifi_probe_kick if you actually want failed
    // probes to bounce STA (matches the historical behaviour).
    bool   wifi_probe_enabled = true;
    bool   wifi_probe_kick    = false;

    // Whether the web dashboard / API is started at boot. Disabling it
    // frees ~30-50 KiB of internal heap (AsyncWebServer + handlers +
    // listening socket buffers), which is significant on the C3 / TQT-Pro
    // and helps the hub reporter fit a full asciicast in RAM during TLS.
    // Only respected when WiFi comes up in STA mode — in the AP setup /
    // fallback portal it is always forced on, otherwise the user could
    // brick themselves out of recovery. Toggling the flag requires a
    // reboot to take effect (we don't tear down a running AsyncTCP).
    bool   web_enabled = true;

    // Geolocation
    bool   geoip_enabled  = true;
    // Default uses ip-api.com free endpoint (no key, ~45 req/min).
    String geoip_url      = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,regionName,lat,lon,isp,org,as";

    // Intel reporting
    bool   abuseipdb_enabled = false;
    String abuseipdb_key     = "";
    String abuseipdb_comment = "Brute-force login attempt captured by HoneyMire on " HONEYMIRE_BOARD_NAME ".";
    bool   otx_enabled       = false;
    String otx_key           = "";
    String otx_pulse_name    = "HoneyMire " HONEYMIRE_BOARD_NAME " SSH/Telnet Brute-force";
    // If set, every reboot reuses this exact pulse id instead of creating
    // a new one (the previous behavior fragmented data across many pulses
    // — one per reboot). Leave empty to fall back to the cached/created
    // pulse-by-name behavior.
    String otx_pulse_id      = "69f726101fd2d1e4eba3a886";
    bool   dshield_enabled   = false;
    String dshield_email     = "";
    String dshield_apikey    = "";

    // HoneyMire Hub reporter — the project's own ingest endpoint, in
    // addition to AbuseIPDB / OTX. Spec: docs/HONEYPOT_PROTOCOL.md
    // (HoneyMire/HoneyMireHUB). The hub aggregates this device's attacks
    // alongside the user's other honeypots and renders them on a
    // dashboard. Token format is `hop_` + 32 base64url chars; see §2.
    bool   hub_enabled    = false;
    String hub_url        = "";        // origin only, e.g. "https://my-hub.example"
    String hub_token      = "";        // bearer token issued by the hub

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

// True if at least one threat-intel reporter is fully configured (toggle
// on AND credentials present). Used to gate web-dashboard disable: if no
// intelligence site is active, the user would lose all visibility into
// the device — we refuse the toggle in that case.
inline bool intel_any_active(const Config& c) {
    if (c.abuseipdb_enabled && c.abuseipdb_key.length()) return true;
    if (c.otx_enabled       && c.otx_key.length())       return true;
    if (c.hub_enabled       && c.hub_url.length() && c.hub_token.length()) return true;
    return false;
}

// Re-applies cfg.tz / cfg.ntp_server* to libc + lwIP SNTP. Safe to call from
// any task. Internally the NTP server names are copied into static heap
// buffers we own forever (lwIP's sntp_setservername stores its argument as a
// raw pointer, so we must hand it stable storage).
void apply_time_config();

} // namespace honeymire
