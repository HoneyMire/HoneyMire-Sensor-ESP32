#include "serial_menu.h"
#include "config.h"
#include "wifi_manager.h"
#include "storage.h"
#include "attack_log.h"

#include <WiFi.h>

namespace honeyopus {

enum class State { Idle, Menu, Reading };

static State s_state = State::Idle;
static String s_buf;
static String s_pending_field; // when reading a value

static void println_banner_() {
    Serial.println();
    Serial.println("============================================");
    Serial.println("  HoneyOpus serial menu");
    Serial.println("  Type ? or help for commands");
    Serial.println("============================================");
}

static void show_menu_() {
    Serial.println();
    Serial.println("HoneyOpus :: menu");
    Serial.println("  1) Set WiFi SSID");
    Serial.println("  2) Set WiFi password");
    Serial.println("  3) Set hostname");
    Serial.println("  4) Show config");
    Serial.println("  5) Save & reconnect WiFi");
    Serial.println("  6) Force AP setup mode");
    Serial.println("  7) Reset config to defaults");
    Serial.println("  8) List attacks");
    Serial.println("  9) List asciinema sessions");
    Serial.println("  s) Toggle SSH enabled");
    Serial.println("  t) Toggle Telnet enabled");
    Serial.println("  w) Toggle Web dashboard (next reboot)");
    Serial.println("  k) Set AbuseIPDB API key");
    Serial.println("  o) Set AlienVault OTX API key");
    Serial.println("  u) Set HoneyOpus Hub URL");
    Serial.println("  b) Set HoneyOpus Hub token");
    Serial.println("  q) Quit menu");
    Serial.print("> ");
}

static void show_config_() {
    auto& c = g_config.get();
    Serial.println();
    Serial.printf("  wifi_ssid       : %s\n", c.wifi_ssid.c_str());
    Serial.printf("  wifi_pass       : %s\n", c.wifi_pass.length() ? "(set)" : "(empty)");
    Serial.printf("  hostname        : %s\n", c.hostname.c_str());
    Serial.printf("  telnet_enabled  : %d\n", (int)c.telnet_enabled);
    Serial.printf("  ssh_enabled     : %d\n", (int)c.ssh_enabled);
    Serial.printf("  fake_hostname   : %s\n", c.fake_hostname.c_str());
    Serial.printf("  fake_user       : %s\n", c.fake_user.c_str());
    Serial.printf("  login_thresh    : %u\n", (unsigned)c.login_attempts_before_accept);
    Serial.printf("  geoip_enabled   : %d\n", (int)c.geoip_enabled);
    Serial.printf("  abuseipdb       : %s (%s)\n",
                  c.abuseipdb_enabled ? "ENABLED" : "disabled",
                  c.abuseipdb_key.length() ? "key set" : "no key");
    Serial.printf("  otx             : %s (%s)\n",
                  c.otx_enabled ? "ENABLED" : "disabled",
                  c.otx_key.length() ? "key set" : "no key");
    Serial.printf("  hub             : %s url=%s (%s)\n",
                  c.hub_enabled ? "ENABLED" : "disabled",
                  c.hub_url.length() ? c.hub_url.c_str() : "(unset)",
                  c.hub_token.length() ? "token set" : "no token");
    Serial.printf("  web_dashboard   : %s\n", c.web_enabled ? "ENABLED" : "disabled");
    Serial.printf("  dashboard       : http://%s/  user=%s\n",
                  WiFi.localIP() == IPAddress() ? WiFi.softAPIP().toString().c_str()
                                                : WiFi.localIP().toString().c_str(),
                  c.dashboard_user.c_str());
}

static void list_attacks_() {
    auto v = g_attack_log.recent(20);
    Serial.printf("Recent attacks (%u):\n", (unsigned)v.size());
    for (auto& e : v) {
        Serial.printf(" #%u %s %s %s/%s authed=%d cmds=%u %s\n",
                      (unsigned)e.id, e.protocol.c_str(), e.ip.c_str(),
                      e.user.c_str(), e.pass.c_str(),
                      (int)e.authenticated, e.commands,
                      e.country.c_str());
    }
}

static void list_sessions_() {
    auto names = storage_list_dir("/sessions", 20);
    Serial.printf("Sessions on flash (%u):\n", (unsigned)names.size());
    for (auto& n : names) Serial.printf("  /sessions/%s\n", n.c_str());
}

static void prompt_for_(const char* what) {
    s_pending_field = what;
    Serial.printf("  %s = ", what);
    s_state = State::Reading;
    s_buf = "";
}

static void apply_pending_(const String& val) {
    auto& c = g_config.get();
    if (s_pending_field == "wifi_ssid")     c.wifi_ssid = val;
    else if (s_pending_field == "wifi_pass") c.wifi_pass = val;
    else if (s_pending_field == "hostname")  c.hostname  = val.length() ? val : String("honeyopus");
    else if (s_pending_field == "abuseipdb_key") {
        c.abuseipdb_key = val;
        c.abuseipdb_enabled = val.length() > 0;
    } else if (s_pending_field == "otx_key") {
        c.otx_key = val;
        c.otx_enabled = val.length() > 0;
    } else if (s_pending_field == "hub_url") {
        String u = val;
        while (u.length() && u[u.length() - 1] == '/') u.remove(u.length() - 1);
        c.hub_url = u;
        c.hub_enabled = c.hub_url.length() > 0 && c.hub_token.length() > 0;
    } else if (s_pending_field == "hub_token") {
        c.hub_token = val;
        c.hub_enabled = c.hub_url.length() > 0 && c.hub_token.length() > 0;
    }
    g_config.save();
    Serial.printf("  saved %s.\n", s_pending_field.c_str());
    s_pending_field = "";
    show_menu_();
    s_state = State::Menu;
}

static void handle_menu_char_(char c) {
    if (c == '\r' || c == '\n') return;
    Serial.write(c);
    Serial.println();
    switch (c) {
        case '1': prompt_for_("wifi_ssid");     return;
        case '2': prompt_for_("wifi_pass");     return;
        case '3': prompt_for_("hostname");      return;
        case '4': show_config_();               break;
        case '5':
            g_config.save();
            wifi_try_sta();
            Serial.println("  config saved; reconnecting WiFi...");
            break;
        case '6':
            wifi_force_ap();
            break;
        case '7':
            g_config.reset();
            Serial.println("  config wiped; reboot to apply.");
            break;
        case '8': list_attacks_();              break;
        case '9': list_sessions_();             break;
        case 's': {
            auto& cf = g_config.get();
            cf.ssh_enabled = !cf.ssh_enabled;
            g_config.save();
            Serial.printf("  ssh_enabled = %d\n", (int)cf.ssh_enabled);
            break;
        }
        case 't': {
            auto& cf = g_config.get();
            cf.telnet_enabled = !cf.telnet_enabled;
            g_config.save();
            Serial.printf("  telnet_enabled = %d\n", (int)cf.telnet_enabled);
            break;
        }
        case 'w': {
            auto& cf = g_config.get();
            if (cf.web_enabled) {
                if (!intel_any_active(cf)) {
                    Serial.println("  refusing to disable web: no threat-intel reporter is");
                    Serial.println("  enabled with credentials (AbuseIPDB / OTX / Hub).");
                    Serial.println("  Configure one first — otherwise this device would have");
                    Serial.println("  zero remote visibility once web is off.");
                    break;
                }
                cf.web_enabled = false;
            } else {
                cf.web_enabled = true;
            }
            g_config.save();
            Serial.printf("  web_enabled = %d (takes effect at next reboot)\n",
                          (int)cf.web_enabled);
            break;
        }
        case 'k': prompt_for_("abuseipdb_key"); return;
        case 'o': prompt_for_("otx_key");       return;
        case 'u': prompt_for_("hub_url");       return;
        case 'b': prompt_for_("hub_token");     return;
        case 'q':
            Serial.println("  quitting menu.");
            s_state = State::Idle;
            return;
        case '?':
        case 'h':
        default:
            break;
    }
    show_menu_();
}

void serial_menu_begin() {
    println_banner_();
    Serial.println("Press any key to enter the menu, 'm' anytime to open it.");
}

void serial_menu_loop() {
    // Periodic liveness/diagnostic. On the ESP32-S3 with USB-Serial-JTAG
    // (HWCDC), some hosts/terminals fail to forward keystrokes even when
    // TX works fine. This heartbeat lets the user see the menu task is
    // alive, the current state, and how many bytes the HWCDC RX queue
    // is exposing — invaluable for diagnosing "menu doesn't react"
    // reports without needing a JTAG probe. Stays quiet once any byte
    // has actually been read so it never spams a working interactive
    // session.
    static uint32_t s_last_hb = 0;
    static bool s_seen_input = false;
    uint32_t now = millis();
    if (!s_seen_input && (now - s_last_hb) > 10000) {
        s_last_hb = now;
        Serial.printf(
            "\r\n[serial_menu] alive state=%d avail=%d  (press 'm' or Enter to open menu)\r\n",
            (int)s_state, Serial.available());
    }

    while (Serial.available() > 0) {
        int b = Serial.read();
        if (b < 0) break;
        s_seen_input = true;
        char c = (char)b;
        if (s_state == State::Idle) {
            if (c == 'm' || c == 'M' || c == '\r' || c == '\n' || c == '?') {
                s_state = State::Menu;
                show_menu_();
            }
            continue;
        }
        if (s_state == State::Reading) {
            if (c == '\r' || c == '\n') {
                Serial.println();
                apply_pending_(s_buf);
            } else if (c == 0x7f || c == 0x08) {
                if (s_buf.length()) {
                    s_buf.remove(s_buf.length() - 1);
                    Serial.print("\b \b");
                }
            } else if (c >= 0x20 && c < 0x7f) {
                s_buf += c;
                Serial.write(c);
            }
            continue;
        }
        // Menu state
        handle_menu_char_(c);
    }
}

} // namespace honeyopus
