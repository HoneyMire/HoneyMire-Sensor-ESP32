#include "config.h"

#include <esp_sntp.h>

namespace honeyopus {

ConfigStore g_config;

static const char* NS = "honeyopus";

// Stable, heap-owned, NEVER FREED storage for the NTP server names — see the
// comment on apply_time_config() in config.h.
static char* s_ntp_buf[3] = { nullptr, nullptr, nullptr };

static void set_stable_ntp_(uint8_t idx, const String& src) {
    if (idx >= 3) return;
    if (s_ntp_buf[idx]) { free(s_ntp_buf[idx]); s_ntp_buf[idx] = nullptr; }
    if (src.length() == 0) return;
    s_ntp_buf[idx] = strdup(src.c_str());
}

void apply_time_config() {
    auto& c = g_config.get();
    setenv("TZ", c.tz.c_str(), 1);    // newlib setenv copies — safe.
    tzset();

    if (esp_sntp_enabled()) esp_sntp_stop();
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    set_stable_ntp_(0, c.ntp_server1);
    set_stable_ntp_(1, c.ntp_server2);
    set_stable_ntp_(2, c.ntp_server3);
    esp_sntp_setservername(0, s_ntp_buf[0]);
    esp_sntp_setservername(1, s_ntp_buf[1]);
    esp_sntp_setservername(2, s_ntp_buf[2]);
    esp_sntp_init();

    Serial.printf("[time] tz=%s ntp=%s,%s,%s\n",
                  c.tz.c_str(),
                  s_ntp_buf[0] ? s_ntp_buf[0] : "(none)",
                  s_ntp_buf[1] ? s_ntp_buf[1] : "(none)",
                  s_ntp_buf[2] ? s_ntp_buf[2] : "(none)");
}

bool ConfigStore::begin() {
    if (!prefs_.begin(NS, false)) {
        Serial.println("[cfg] NVS open failed");
        return false;
    }
    return load();
}

bool ConfigStore::load() {
    cfg_.wifi_ssid       = prefs_.getString("wifi_ssid", cfg_.wifi_ssid);
    cfg_.wifi_pass       = prefs_.getString("wifi_pass", cfg_.wifi_pass);
    cfg_.hostname        = prefs_.getString("hostname", cfg_.hostname);
    cfg_.telnet_banner   = prefs_.getString("tn_banner", cfg_.telnet_banner);
    cfg_.ssh_banner      = prefs_.getString("ssh_banner", cfg_.ssh_banner);
    cfg_.fake_hostname   = prefs_.getString("fhost", cfg_.fake_hostname);
    cfg_.fake_user       = prefs_.getString("fuser", cfg_.fake_user);
    cfg_.login_attempts_before_accept = prefs_.getUChar("lthresh", cfg_.login_attempts_before_accept);
    cfg_.telnet_enabled  = prefs_.getBool("tn_en", cfg_.telnet_enabled);
    cfg_.ssh_enabled     = prefs_.getBool("ssh_en", cfg_.ssh_enabled);
    cfg_.dashboard_auth_enabled = prefs_.getBool("dash_en", cfg_.dashboard_auth_enabled);
    cfg_.dashboard_user  = prefs_.getString("dash_u", cfg_.dashboard_user);
    cfg_.dashboard_pass  = prefs_.getString("dash_p", cfg_.dashboard_pass);
    cfg_.geoip_enabled   = prefs_.getBool("geo_en", cfg_.geoip_enabled);
    cfg_.geoip_url       = prefs_.getString("geo_url", cfg_.geoip_url);
    cfg_.abuseipdb_enabled = prefs_.getBool("aipdb_en", cfg_.abuseipdb_enabled);
    cfg_.abuseipdb_key   = prefs_.getString("aipdb_k", cfg_.abuseipdb_key);
    cfg_.abuseipdb_comment = prefs_.getString("aipdb_c", cfg_.abuseipdb_comment);
    cfg_.otx_enabled     = prefs_.getBool("otx_en", cfg_.otx_enabled);
    cfg_.otx_key         = prefs_.getString("otx_k", cfg_.otx_key);
    cfg_.otx_pulse_name  = prefs_.getString("otx_p", cfg_.otx_pulse_name);
    cfg_.tz              = prefs_.getString("tz",     cfg_.tz);
    cfg_.ntp_server1     = prefs_.getString("ntp1",   cfg_.ntp_server1);
    cfg_.ntp_server2     = prefs_.getString("ntp2",   cfg_.ntp_server2);
    cfg_.ntp_server3     = prefs_.getString("ntp3",   cfg_.ntp_server3);
    cfg_.display_on_seconds  = prefs_.getUShort("disp_on", cfg_.display_on_seconds);
    cfg_.attack_icon_seconds = prefs_.getUShort("disp_atk", cfg_.attack_icon_seconds);
    cfg_.max_sessions    = prefs_.getUShort("max_sess", cfg_.max_sessions);
    cfg_.max_attack_entries = prefs_.getUShort("max_atk", cfg_.max_attack_entries);
    cfg_.max_session_dir_kb = prefs_.getUShort("max_skb", cfg_.max_session_dir_kb);
    return true;
}

bool ConfigStore::save() {
    prefs_.putString("wifi_ssid", cfg_.wifi_ssid);
    prefs_.putString("wifi_pass", cfg_.wifi_pass);
    prefs_.putString("hostname", cfg_.hostname);
    prefs_.putString("tn_banner", cfg_.telnet_banner);
    prefs_.putString("ssh_banner", cfg_.ssh_banner);
    prefs_.putString("fhost", cfg_.fake_hostname);
    prefs_.putString("fuser", cfg_.fake_user);
    prefs_.putUChar("lthresh", cfg_.login_attempts_before_accept);
    prefs_.putBool("tn_en", cfg_.telnet_enabled);
    prefs_.putBool("ssh_en", cfg_.ssh_enabled);
    prefs_.putBool("dash_en", cfg_.dashboard_auth_enabled);
    prefs_.putString("dash_u", cfg_.dashboard_user);
    prefs_.putString("dash_p", cfg_.dashboard_pass);
    prefs_.putBool("geo_en", cfg_.geoip_enabled);
    prefs_.putString("geo_url", cfg_.geoip_url);
    prefs_.putBool("aipdb_en", cfg_.abuseipdb_enabled);
    prefs_.putString("aipdb_k", cfg_.abuseipdb_key);
    prefs_.putString("aipdb_c", cfg_.abuseipdb_comment);
    prefs_.putBool("otx_en", cfg_.otx_enabled);
    prefs_.putString("otx_k", cfg_.otx_key);
    prefs_.putString("otx_p", cfg_.otx_pulse_name);
    prefs_.putString("tz",     cfg_.tz);
    prefs_.putString("ntp1",   cfg_.ntp_server1);
    prefs_.putString("ntp2",   cfg_.ntp_server2);
    prefs_.putString("ntp3",   cfg_.ntp_server3);
    prefs_.putUShort("disp_on", cfg_.display_on_seconds);
    prefs_.putUShort("disp_atk", cfg_.attack_icon_seconds);
    prefs_.putUShort("max_sess", cfg_.max_sessions);
    prefs_.putUShort("max_atk", cfg_.max_attack_entries);
    prefs_.putUShort("max_skb", cfg_.max_session_dir_kb);
    return true;
}

void ConfigStore::reset() {
    prefs_.clear();
    cfg_ = Config{};
    save();
}

} // namespace honeyopus
