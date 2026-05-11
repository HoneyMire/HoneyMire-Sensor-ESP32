#include "wifi_manager.h"
#include "config.h"
#include "display.h"
#include "restart_reason.h"

#include <WiFi.h>
#include <DNSServer.h>
#include <WiFiClient.h>

namespace honeymire {

static NetMode s_mode = NetMode::Boot;
static String s_ap_ssid;
static String s_ap_pass = "honeymire";
static uint32_t s_last_attempt = 0;
static uint32_t s_attempts = 0;
static DNSServer s_dns;
static bool s_dns_running = false;
// Tracks the last time we observed a healthy network (STA connected OR
// running as fallback AP). Used to reboot after a prolonged total outage,
// which is the only reliable way to recover from rare LWIP/Wi-Fi-driver
// states that AutoReconnect + WiFi.begin can't unwedge.
static uint32_t s_last_healthy = 0;
static const uint32_t kWifiOutageRebootMs = 3 * 60 * 1000;
// Outbound connectivity probe — catches the "associated but no traffic"
// failure mode where WiFi.status() == WL_CONNECTED but LWIP can't actually
// route packets (e.g. after certain router-side deauths).
static const uint32_t kProbeIntervalMs = 60 * 1000;
static const uint32_t kProbeTimeoutMs  = 3000;
static const uint8_t  kProbeFailLimit  = 3;
static uint32_t s_last_probe = 0;
static uint8_t  s_probe_fails = 0;
static volatile bool s_event_disconnected = false;
// millis() at the most recent GOT_IP. 0 while disconnected. Drives
// wifi_online_uptime_ms() so callers can defer DNS-dependent work for
// a few seconds after every reconnect.
static volatile uint32_t s_online_since_ms = 0;
// Last STA disconnect reason captured by the event handler. Logged once
// from wifi_loop() when it changes — the event handler runs on the WiFi
// task and must stay short. Reasons are documented in
// esp_wifi_types.h::wifi_err_reason_t (e.g. 2=AUTH_EXPIRE, 6=NOT_AUTHED,
// 8=ASSOC_LEAVE, 15=4WAY_HANDSHAKE_TIMEOUT, 200/201/202=AUTH_FAIL).
static volatile uint8_t s_last_disc_reason   = 0;
static volatile bool    s_last_disc_logged   = true;
// On boot we don't yet have a reason to report; flip false the first
// time the handler captures one so wifi_loop() can surface it.

// Reconnect FSM (W2 / W3 in the stability review). We deliberately do
// NOT use WiFi.setAutoReconnect(true): the driver-side auto-reconnect
// runs concurrently with our explicit retries, which on certain APs
// produces a back-and-forth churn (manual disconnect → driver auto
// reconnects → we disconnect again …) and racks up spurious AUTH_FAIL
// noise. Instead we own the policy:
//
//   - On a transient drop (BEACON_TIMEOUT, NOT_AUTHED, ASSOC_LEAVE,
//     4WAY_HANDSHAKE_TIMEOUT, …) we apply an exponential backoff
//     between WiFi.begin() retries, capping at kBackoffMaxMs.
//   - On a config-permanent reason (NO_AP_FOUND, AUTH_FAIL) we still
//     retry a couple of times — the AP can be transiently absent
//     during a router reboot — but bail to fallback AP much sooner.
//   - On every transient-drop reconnect we use disconnect(false,
//     /*eraseAP=*/false). The eraseAP=true form is only used on
//     operator-driven AP fallback (wifi_force_ap) and after the
//     reconnect FSM gives up; doing it on every glitch is heavier
//     than necessary and can interact badly with AP roaming.
static const uint32_t kBackoffMs[]      = { 1000, 2000, 5000, 10000, 30000, 60000 };
static const size_t   kBackoffSteps     = sizeof(kBackoffMs) / sizeof(kBackoffMs[0]);
static const uint32_t kBackoffMaxMs     = kBackoffMs[kBackoffSteps - 1];
static const uint32_t kAttemptWaitMs    = 20000;  // how long to let WiFi.begin try before declaring fail
// Bail to fallback AP after this many failed STA attempts. For auth-permanent
// reasons we use the lower threshold so we surface the config error fast.
static const uint8_t  kStaAttemptsTransient = 6;
static const uint8_t  kStaAttemptsPermanent = 2;
// Earliest absolute millis() the next WiFi.begin() retry is allowed.
// Updated whenever an attempt times out.
static uint32_t s_next_retry_ms = 0;

// Auto-recovery from FallbackAP. Without this, a single transient
// disconnect that exhausts the kStaAttemptsTransient retry budget
// drops the device into FallbackAP forever — its IP becomes
// 192.168.4.1 on its own SoftAP, NAT/port-forwarding from the
// router stops reaching it, and the honeypot silently sees zero
// attack traffic until rebooted. The pre-Pass-B build hid this
// because setAutoReconnect(true) silently kept STA retries going
// in the background; with the FSM now owning everything, AP became
// a terminal state.
//
// Fix: every kApStaRetryMs while in FallbackAP, attempt STA once.
// The existing FSM handles success (leaves AP) or failure (after
// the standard retry budget, drops back to AP). 10 minutes is
// short enough that a transient router reboot is recovered from
// promptly, long enough that genuinely-bad credentials don't spam
// AUTH_FAIL.
static const uint32_t kApStaRetryMs    = 10UL * 60UL * 1000UL;
static uint32_t       s_ap_since_ms    = 0;
static uint32_t       s_last_ap_retry_ms = 0;

static bool reason_is_permanent_(uint8_t r) {
    // Auth-class failures and "AP not found" indicate a config problem
    // or a vanished AP. Worth bailing to portal mode after a couple of
    // tries instead of pounding the radio.
    return r == 201 /*NO_AP_FOUND*/ ||
           r == 202 /*AUTH_FAIL*/   ||
           r == 203 /*ASSOC_FAIL*/;
}

static uint32_t backoff_for_(uint8_t attempts) {
    if (attempts == 0) return 0;
    size_t idx = attempts - 1;
    if (idx >= kBackoffSteps) idx = kBackoffSteps - 1;
    return kBackoffMs[idx];
}

NetMode wifi_mode() { return s_mode; }
String wifi_ip_string() {
    if (s_mode == NetMode::FallbackAP) return WiFi.softAPIP().toString();
    return WiFi.localIP().toString();
}
String wifi_ap_ssid() { return s_ap_ssid; }

uint32_t wifi_online_uptime_ms() {
    uint32_t since = s_online_since_ms;
    if (since == 0) return 0;
    return millis() - since;
}

static void on_wifi_event_(WiFiEvent_t event, WiFiEventInfo_t info) {
    switch (event) {
        case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
            // Flag for the loop task — keep the handler short, it runs on
            // the WiFi event task and must not call WiFi.begin() directly.
            s_event_disconnected = true;
            s_last_disc_reason = info.wifi_sta_disconnected.reason;
            s_last_disc_logged = false;
            s_online_since_ms = 0;
            break;
        case ARDUINO_EVENT_WIFI_STA_GOT_IP:
            s_event_disconnected = false;
            s_probe_fails = 0;
            s_last_healthy = millis();
            s_online_since_ms = millis();
            break;
        default:
            break;
    }
}

// Map a wifi_err_reason_t value to a short human label. Covers the
// codes we actually see in the field — auth failure, deauth, beacon
// timeout, handshake timeout, AP not found, plus a generic fallback.
static const char* disc_reason_label_(uint8_t reason) {
    switch (reason) {
        case 1:   return "UNSPECIFIED";
        case 2:   return "AUTH_EXPIRE";
        case 3:   return "AUTH_LEAVE";
        case 4:   return "ASSOC_EXPIRE";
        case 5:   return "ASSOC_TOOMANY";
        case 6:   return "NOT_AUTHED";
        case 7:   return "NOT_ASSOCED";
        case 8:   return "ASSOC_LEAVE";
        case 15:  return "4WAY_HANDSHAKE_TIMEOUT";
        case 16:  return "GROUP_KEY_UPDATE_TIMEOUT";
        case 200: return "BEACON_TIMEOUT";
        case 201: return "NO_AP_FOUND";
        case 202: return "AUTH_FAIL";
        case 203: return "ASSOC_FAIL";
        case 204: return "HANDSHAKE_TIMEOUT";
        case 205: return "CONNECTION_FAIL";
        default:  return "?";
    }
}

static bool probe_outbound_() {
    // Cheap "is the upstream really reachable" check: a short TCP connect
    // to the default gateway on port 53 (every consumer router answers).
    // Falls back to 1.1.1.1 if no gateway is known yet.
    IPAddress target = WiFi.gatewayIP();
    if (target == IPAddress(0,0,0,0)) target = IPAddress(1,1,1,1);
    WiFiClient c;
    c.setTimeout(kProbeTimeoutMs / 1000);
    bool ok = c.connect(target, 53, kProbeTimeoutMs);
    c.stop();
    return ok;
}

static void start_ap_() {
    String mac = WiFi.macAddress();
    mac.replace(":", "");
    s_ap_ssid = String("HoneyMire-") + mac.substring(8);
    WiFi.mode(WIFI_AP);
    // softAPConfig() MUST come before softAP() — calling it after has been
    // observed on certain arduino-esp32 versions to leave the AP listening
    // on the framework default (192.168.4.1 most of the time, but not
    // always) and the captive portal then advertises the wrong IP. See
    // ESP32 stability review W5.
    IPAddress ap_ip(192, 168, 4, 1);
    IPAddress ap_nm(255, 255, 255, 0);
    WiFi.softAPConfig(ap_ip, ap_ip, ap_nm);
    WiFi.softAP(s_ap_ssid.c_str(), s_ap_pass.c_str());
    if (s_dns_running) { s_dns.stop(); s_dns_running = false; }
    s_dns.setErrorReplyCode(DNSReplyCode::NoError);
    s_dns.start(53, "*", ap_ip);
    s_dns_running = true;
    s_mode = NetMode::FallbackAP;
    s_ap_since_ms = millis();
    s_last_ap_retry_ms = millis();   // first STA retry kApStaRetryMs from now
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
    s_next_retry_ms = 0;   // a fresh attempt: invalidate any pending backoff
    Serial.printf("[wifi] connecting to %s (attempt %u)\n",
                  cfg.wifi_ssid.c_str(), (unsigned)s_attempts);
    g_display.showStatus("WiFi...", cfg.wifi_ssid);
}

void wifi_begin() {
    WiFi.persistent(false);
    // setAutoReconnect(true) was removed — see the reconnect-FSM
    // comment block. Driver-side auto-reconnect raced with our
    // manual retries on certain APs.
    WiFi.setAutoReconnect(false);
    WiFi.onEvent(on_wifi_event_);
    s_last_healthy = millis();
    s_last_probe = millis();
    s_probe_fails = 0;
    s_event_disconnected = false;
    s_next_retry_ms = 0;
    wifi_try_sta();
}

void wifi_loop() {
    if (s_dns_running) s_dns.processNextRequest();

    auto status = WiFi.status();

    // Surface the last STA disconnect reason exactly once per occurrence.
    // Lets the operator distinguish "wrong password" (AUTH_FAIL) from
    // "router rebooted" (BEACON_TIMEOUT) from "AP gone" (NO_AP_FOUND)
    // without grepping ESP-IDF headers. See ESP32 stability review W1.
    if (!s_last_disc_logged) {
        uint8_t r = s_last_disc_reason;
        s_last_disc_logged = true;
        Serial.printf("[wifi] STA disconnect reason=%u (%s)\n",
                      (unsigned)r, disc_reason_label_(r));
    }

    // Event-driven disconnect path. We don't disconnect/erase here —
    // the FSM below drives the reconnect with backoff and reason-aware
    // bail-out. Just transition to ConnectingSTA so the next pass picks
    // it up.
    if (s_event_disconnected && s_mode == NetMode::OnlineSTA) {
        Serial.println("[wifi] event: STA disconnected, will retry");
        s_mode = NetMode::ConnectingSTA;
        s_attempts = 0;
        s_event_disconnected = false;
        // No eraseAP — transient drops shouldn't churn the driver's AP
        // record (W3). The radio remains in STA mode; we just need
        // WiFi.begin to fire again once the backoff window opens.
        WiFi.disconnect(false, /*eraseAP=*/false);
        s_next_retry_ms = millis();   // first retry: no backoff
        return;
    }

    if (s_mode == NetMode::ConnectingSTA) {
        if (status == WL_CONNECTED) {
            s_mode = NetMode::OnlineSTA;
            s_last_healthy = millis();
            s_last_probe = millis();
            s_probe_fails = 0;
            s_next_retry_ms = 0;
            Serial.printf("[wifi] STA connected ip=%s\n", WiFi.localIP().toString().c_str());
            g_display.showStatus("Online", g_config.get().wifi_ssid, WiFi.localIP().toString());
            g_display.wakeFromButton();
        } else {
            // FSM priority: backoff first, then "have we ever called
            // begin?", then attempt-timeout decision. The earlier
            // version had these checks ordered such that the
            // "millis() - s_last_attempt > kAttemptWaitMs" branch was
            // re-entered every loop pass once the first attempt timed
            // out — printing "attempt 1 failed" on every iteration and
            // never advancing s_attempts because the bail-or-backoff
            // path didn't fire wifi_try_sta() on backoff expiry. This
            // restructured chain runs each path exactly once per state
            // transition.
            const uint32_t now = millis();
            if (s_next_retry_ms != 0) {
                // A backoff window is active. Either still waiting,
                // or it just expired — in which case fire the next
                // begin() and clear the gate. Either way, we don't
                // fall through to the timeout-decision branch.
                if (now >= s_next_retry_ms) {
                    s_next_retry_ms = 0;
                    wifi_try_sta();
                }
            } else if (s_attempts == 0) {
                // No begin() fired yet (e.g. landed here via event path).
                wifi_try_sta();
            } else if (now - s_last_attempt > kAttemptWaitMs) {
                // Current attempt timed out. Decide bail vs backoff.
                const uint8_t reason  = s_last_disc_reason;
                const bool    perm    = reason_is_permanent_(reason);
                const uint8_t cap     = perm ? kStaAttemptsPermanent : kStaAttemptsTransient;
                if (s_attempts >= cap) {
                    Serial.printf("[wifi] giving up STA after %u attempts (%s reason=%u %s) — fallback AP\n",
                                  (unsigned)s_attempts, perm ? "permanent" : "transient",
                                  (unsigned)reason, disc_reason_label_(reason));
                    start_ap_();
                } else {
                    uint32_t wait = backoff_for_(s_attempts);
                    if (wait > kBackoffMaxMs) wait = kBackoffMaxMs;
                    s_next_retry_ms = now + wait;
                    Serial.printf("[wifi] attempt %u failed, backoff %ums (reason=%u %s)\n",
                                  (unsigned)s_attempts, (unsigned)wait,
                                  (unsigned)reason, disc_reason_label_(reason));
                }
            }
            // else: attempt still in flight (within kAttemptWaitMs of
            // s_last_attempt). Just wait.
        }
    } else if (s_mode == NetMode::OnlineSTA) {
        if (status != WL_CONNECTED) {
            // Polled detection of a missed disconnect event. Same
            // policy as the event path: retire to ConnectingSTA, no
            // eraseAP.
            if (millis() - s_last_attempt > kAttemptWaitMs) {
                Serial.println("[wifi] STA lost (polled), will retry");
                WiFi.disconnect(false, /*eraseAP=*/false);
                s_mode = NetMode::ConnectingSTA;
                s_attempts = 0;
                s_next_retry_ms = millis();
            }
        } else {
            s_last_attempt = millis();
            // Only update s_last_healthy on a positive probe (or right
            // after GOT_IP, handled in the event callback). Letting
            // status()==WL_CONNECTED alone refresh it is what hid 6 hours
            // of LWIP-stuck silence in the wild.
            // Outbound probe is observability-only by default. Many
            // routers don't accept TCP/53 on the gateway IP, so a
            // fail-count threshold would kick perfectly healthy
            // networks every few minutes (W4 in the stability review).
            // Operators who want the historical "kick STA on probe
            // fails" behaviour can enable wifi_probe_kick.
            const auto& cfg = g_config.get();
            if (cfg.wifi_probe_enabled &&
                millis() - s_last_probe > kProbeIntervalMs) {
                s_last_probe = millis();
                if (probe_outbound_()) {
                    s_probe_fails = 0;
                    s_last_healthy = millis();
                } else {
                    s_probe_fails++;
                    Serial.printf("[wifi] probe failed (%u/%u) gw=%s%s\n",
                                  (unsigned)s_probe_fails, (unsigned)kProbeFailLimit,
                                  WiFi.gatewayIP().toString().c_str(),
                                  cfg.wifi_probe_kick ? "" : " (observability-only)");
                    if (cfg.wifi_probe_kick && s_probe_fails >= kProbeFailLimit) {
                        Serial.println("[wifi] probe-stuck — kicking STA");
                        s_probe_fails = 0;
                        // eraseAP=false — see W3. Even on probe-stuck
                        // we don't need to forget the configured AP.
                        WiFi.disconnect(false, /*eraseAP=*/false);
                        s_mode = NetMode::ConnectingSTA;
                        s_attempts = 0;
                        s_next_retry_ms = millis();
                    }
                }
            }
        }
    } else if (s_mode == NetMode::FallbackAP) {
        // AP itself counts as healthy — admin can still reach the
        // dashboard from the SoftAP SSID.
        s_last_healthy = millis();
        // Periodically try STA again. A transient disconnect that
        // exhausted the retry budget no longer pins us in AP forever:
        // every kApStaRetryMs we attempt one more STA cycle. If it
        // succeeds the FSM transitions out via the WL_CONNECTED
        // branch in ConnectingSTA; if it fails we land back here and
        // wait another kApStaRetryMs.
        const auto& cfg = g_config.get();
        if (cfg.wifi_ssid.length() > 0 &&
            (millis() - s_last_ap_retry_ms) >= kApStaRetryMs) {
            s_last_ap_retry_ms = millis();
            // Don't bounce clients currently in the captive portal —
            // they may be mid-credential-fix. Defer until they leave.
            uint8_t ap_clients = WiFi.softAPgetStationNum();
            if (ap_clients > 0) {
                Serial.printf("[wifi] AP-retry deferred — %u portal client(s) connected\n",
                              (unsigned)ap_clients);
            } else {
                uint32_t ap_secs = (millis() - s_ap_since_ms) / 1000;
                Serial.printf("[wifi] AP-mode for %us — retrying STA\n",
                              (unsigned)ap_secs);
                s_attempts = 0;
                s_next_retry_ms = 0;
                s_event_disconnected = false;
                wifi_try_sta();
                return;
            }
        }
    }

    // Last-resort self-heal. If we've spent kWifiOutageRebootMs with neither
    // a working STA association nor an AP up, reboot. This is a deliberate
    // sledgehammer for the rare cases where WiFi.begin() / AutoReconnect
    // get stuck in an unrecoverable state and the device would otherwise
    // need manual power-cycling.
    if (s_last_healthy != 0 &&
        (millis() - s_last_healthy) > kWifiOutageRebootMs) {
        Serial.printf("[wifi] outage > %u s, rebooting to recover\n",
                      (unsigned)(kWifiOutageRebootMs / 1000));
        restart::restart_with(restart::kReasonWifiOutage);
    }
}

} // namespace honeymire
