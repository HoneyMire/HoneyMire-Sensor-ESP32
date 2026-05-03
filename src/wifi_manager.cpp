#include "wifi_manager.h"
#include "config.h"
#include "display.h"

#include <WiFi.h>
#include <DNSServer.h>

namespace honeyopus {

static NetMode s_mode = NetMode::Boot;
static String s_ap_ssid;
static String s_ap_pass = "honeyopus";
static uint32_t s_last_attempt = 0;
static uint32_t s_attempts = 0;
static DNSServer s_dns;
static bool s_dns_running = false;
// Tracks the last time we observed a healthy network (STA connected OR
// running as fallback AP). Used to reboot after a prolonged total outage,
// which is the only reliable way to recover from rare LWIP/Wi-Fi-driver
// states that AutoReconnect + WiFi.begin can't unwedge.
static uint32_t s_last_healthy = 0;
static const uint32_t kWifiOutageRebootMs = 5 * 60 * 1000;

NetMode wifi_mode() { return s_mode; }
String wifi_ip_string() {
    if (s_mode == NetMode::FallbackAP) return WiFi.softAPIP().toString();
    return WiFi.localIP().toString();
}
String wifi_ap_ssid() { return s_ap_ssid; }

static void start_ap_() {
    String mac = WiFi.macAddress();
    mac.replace(":", "");
    s_ap_ssid = String("HoneyOpus-") + mac.substring(8);
    WiFi.mode(WIFI_AP);
    WiFi.softAP(s_ap_ssid.c_str(), s_ap_pass.c_str());
    IPAddress ap_ip(192, 168, 4, 1);
    IPAddress ap_nm(255, 255, 255, 0);
    WiFi.softAPConfig(ap_ip, ap_ip, ap_nm);
    if (s_dns_running) { s_dns.stop(); s_dns_running = false; }
    s_dns.setErrorReplyCode(DNSReplyCode::NoError);
    s_dns.start(53, "*", ap_ip);
    s_dns_running = true;
    s_mode = NetMode::FallbackAP;
    Serial.printf("[wifi] AP up SSID=%s pass=%s ip=%s\n",
                  s_ap_ssid.c_str(), s_ap_pass.c_str(), ap_ip.toString().c_str());
    g_display.showStatus("AP MODE", s_ap_ssid, ap_ip.toString());
    g_display.wakeFromButton();
}

void wifi_force_ap() { start_ap_(); }

void wifi_try_sta() {
    auto& cfg = g_config.get();
    if (cfg.wifi_ssid.length() == 0) {
        start_ap_();
        return;
    }
    if (s_dns_running) { s_dns.stop(); s_dns_running = false; }
    WiFi.mode(WIFI_STA);
    WiFi.setHostname(cfg.hostname.c_str());
    WiFi.begin(cfg.wifi_ssid.c_str(), cfg.wifi_pass.c_str());
    s_mode = NetMode::ConnectingSTA;
    s_attempts++;
    s_last_attempt = millis();
    Serial.printf("[wifi] connecting to %s (attempt %u)\n",
                  cfg.wifi_ssid.c_str(), (unsigned)s_attempts);
    g_display.showStatus("WiFi...", cfg.wifi_ssid);
}

void wifi_begin() {
    WiFi.persistent(false);
    WiFi.setAutoReconnect(true);
    s_last_healthy = millis();
    wifi_try_sta();
}

void wifi_loop() {
    if (s_dns_running) s_dns.processNextRequest();

    auto status = WiFi.status();
    static uint32_t last_status_log = 0;
    if (millis() - last_status_log > 5000) {
        last_status_log = millis();
    }

    if (s_mode == NetMode::ConnectingSTA) {
        if (status == WL_CONNECTED) {
            s_mode = NetMode::OnlineSTA;
            s_last_healthy = millis();
            Serial.printf("[wifi] STA connected ip=%s\n", WiFi.localIP().toString().c_str());
            g_display.showStatus("Online", g_config.get().wifi_ssid, WiFi.localIP().toString());
            g_display.wakeFromButton();
        } else if (millis() - s_last_attempt > 25000) {
            // give up STA attempts, drop to AP after 3
            if (s_attempts >= 3) start_ap_();
            else wifi_try_sta();
        }
    } else if (s_mode == NetMode::OnlineSTA) {
        if (status != WL_CONNECTED) {
            // Will auto-reconnect; if that fails for 30 s, fall back.
            if (millis() - s_last_attempt > 30000) {
                Serial.println("[wifi] STA lost, retrying...");
                // Force a clean STA stack — AutoReconnect alone has been
                // observed to silently stay in WL_DISCONNECTED forever after
                // certain router-side de-auths (e.g. Reason 6 NOT_AUTHED).
                WiFi.disconnect(false, true);
                s_attempts = 0;
                wifi_try_sta();
            }
        } else {
            s_last_attempt = millis();
            s_last_healthy = millis();
        }
    } else if (s_mode == NetMode::FallbackAP) {
        // AP itself counts as healthy — admin can still reach the
        // dashboard from the SoftAP SSID.
        s_last_healthy = millis();
    }

    // Last-resort self-heal. If we've spent kWifiOutageRebootMs with neither
    // a working STA association nor an AP up, reboot. This is a deliberate
    // sledgehammer for the rare cases where WiFi.begin() / AutoReconnect
    // get stuck in an unrecoverable state and the device would otherwise
    // need manual power-cycling.
    if (s_last_healthy != 0 &&
        (millis() - s_last_healthy) > kWifiOutageRebootMs) {
        Serial.println("[wifi] outage > 5 min, rebooting to recover");
        delay(100);
        ESP.restart();
    }
}

} // namespace honeyopus
