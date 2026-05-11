#include "config.h"

#include <esp_sntp.h>

namespace honeymire {

ConfigStore g_config;

static const char* NS = "honeymire";

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
    bool first_run = !prefs_.isKey("hostname");
    bool ok = load();
    if (first_run) {
        Serial.println("[cfg] first-boot NVS: writing defaults");
        save();
    }
    return ok;
}

bool ConfigStore::load() {
    // Wrappers that skip the get*() path when the key doesn't exist yet.
    // Arduino-ESP32's Preferences class log_e()'s a NOT_FOUND error from
    // every get on a missing key, which floods the console with ~20
    // scary-looking lines on first boot. isKey() is silent.
    auto getStr  = [&](const char* k, const String& def) -> String {
        return prefs_.isKey(k) ? prefs_.getString(k) : def;
    };
    auto getU8   = [&](const char* k, uint8_t  def) {
        return prefs_.isKey(k) ? prefs_.getUChar(k)  : def;
    };
    auto getU16  = [&](const char* k, uint16_t def) {
        return prefs_.isKey(k) ? prefs_.getUShort(k) : def;
    };
    auto getBool = [&](const char* k, bool     def) {
        return prefs_.isKey(k) ? prefs_.getBool(k)   : def;
    };
    cfg_.wifi_ssid       = getStr("wifi_ssid", cfg_.wifi_ssid);
    cfg_.wifi_pass       = getStr("wifi_pass", cfg_.wifi_pass);
    cfg_.hostname        = getStr("hostname",  cfg_.hostname);
    cfg_.telnet_banner   = getStr("tn_banner", cfg_.telnet_banner);
    cfg_.ssh_banner      = getStr("ssh_banner",cfg_.ssh_banner);
    cfg_.fake_hostname   = getStr("fhost",     cfg_.fake_hostname);
    cfg_.fake_user       = getStr("fuser",     cfg_.fake_user);
    cfg_.login_attempts_before_accept = getU8("lthresh", cfg_.login_attempts_before_accept);
    cfg_.telnet_enabled  = getBool("tn_en",  cfg_.telnet_enabled);
    cfg_.ssh_enabled     = getBool("ssh_en", cfg_.ssh_enabled);
    cfg_.dashboard_auth_enabled = getBool("dash_en", cfg_.dashboard_auth_enabled);
    cfg_.dashboard_user  = getStr("dash_u", cfg_.dashboard_user);
    cfg_.dashboard_pass  = getStr("dash_p", cfg_.dashboard_pass);
    cfg_.dashboard_lan_bypass = getBool("dash_lan", cfg_.dashboard_lan_bypass);
    cfg_.web_enabled     = getBool("web_en",  cfg_.web_enabled);
    cfg_.wifi_probe_enabled = getBool("wf_pb_en", cfg_.wifi_probe_enabled);
    cfg_.wifi_probe_kick    = getBool("wf_pb_kk", cfg_.wifi_probe_kick);
    cfg_.geoip_enabled   = getBool("geo_en", cfg_.geoip_enabled);
    cfg_.geoip_url       = getStr("geo_url", cfg_.geoip_url);
    cfg_.abuseipdb_enabled = getBool("aipdb_en", cfg_.abuseipdb_enabled);
    cfg_.abuseipdb_key   = getStr("aipdb_k", cfg_.abuseipdb_key);
    cfg_.abuseipdb_comment = getStr("aipdb_c", cfg_.abuseipdb_comment);
    cfg_.otx_enabled     = getBool("otx_en", cfg_.otx_enabled);
    cfg_.otx_key         = getStr("otx_k",   cfg_.otx_key);
    cfg_.otx_pulse_name  = getStr("otx_p",   cfg_.otx_pulse_name);
    cfg_.otx_pulse_id    = getStr("otx_pid", cfg_.otx_pulse_id);
    cfg_.hub_enabled     = getBool("hub_en",  cfg_.hub_enabled);
    cfg_.hub_url         = getStr("hub_url",  cfg_.hub_url);
    cfg_.hub_token       = getStr("hub_tok",  cfg_.hub_token);
    cfg_.dshield_enabled = getBool("ds_en",   cfg_.dshield_enabled);
    cfg_.dshield_email   = getStr("ds_email", cfg_.dshield_email);
    cfg_.dshield_apikey  = getStr("ds_key",   cfg_.dshield_apikey);
    cfg_.tz              = getStr("tz",       cfg_.tz);
    cfg_.ntp_server1     = getStr("ntp1",     cfg_.ntp_server1);
    cfg_.ntp_server2     = getStr("ntp2",     cfg_.ntp_server2);
    cfg_.ntp_server3     = getStr("ntp3",     cfg_.ntp_server3);
    cfg_.display_on_seconds  = getU16("disp_on",  cfg_.display_on_seconds);
    cfg_.attack_icon_seconds = getU16("disp_atk", cfg_.attack_icon_seconds);
    cfg_.max_sessions    = getU16("max_sess", cfg_.max_sessions);
    cfg_.max_attack_entries = getU16("max_atk", cfg_.max_attack_entries);
    cfg_.max_session_dir_kb = getU16("max_skb", cfg_.max_session_dir_kb);
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
    prefs_.putBool("dash_lan", cfg_.dashboard_lan_bypass);
    prefs_.putBool("web_en",  cfg_.web_enabled);
    prefs_.putBool("wf_pb_en", cfg_.wifi_probe_enabled);
    prefs_.putBool("wf_pb_kk", cfg_.wifi_probe_kick);
    prefs_.putBool("geo_en", cfg_.geoip_enabled);
    prefs_.putString("geo_url", cfg_.geoip_url);
    prefs_.putBool("aipdb_en", cfg_.abuseipdb_enabled);
    prefs_.putString("aipdb_k", cfg_.abuseipdb_key);
    prefs_.putString("aipdb_c", cfg_.abuseipdb_comment);
    prefs_.putBool("otx_en", cfg_.otx_enabled);
    prefs_.putString("otx_k", cfg_.otx_key);
    prefs_.putString("otx_p", cfg_.otx_pulse_name);
    prefs_.putString("otx_pid", cfg_.otx_pulse_id);
    prefs_.putBool("hub_en",  cfg_.hub_enabled);
    prefs_.putString("hub_url", cfg_.hub_url);
    prefs_.putString("hub_tok", cfg_.hub_token);
    prefs_.putBool("ds_en",      cfg_.dshield_enabled);
    prefs_.putString("ds_email", cfg_.dshield_email);
    prefs_.putString("ds_key",   cfg_.dshield_apikey);
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

} // namespace honeymire
