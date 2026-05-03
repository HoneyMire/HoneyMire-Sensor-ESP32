// HoneyOpus — ESP32-C3 Telnet/SSH honeypot with OLED feedback, captive portal,
// asciinema recording, and threat-intelligence reporting.
//
// Boot sequence:
//   1. Serial up, banner.
//   2. Display init + boot logo flash.
//   3. NVS-backed config load.
//   4. LittleFS mount.
//   5. WiFi STA attempt → SoftAP captive portal fallback after 3 failed attempts.
//   6. NTP sync (best-effort).
//   7. Web dashboard, intel reporter task, telnet listener, ssh listener.
//
// Then in loop(): drive serial menu, captive DNS, display state machine.

#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include <esp_task_wdt.h>

#include "config.h"
#include "display.h"
#include "storage.h"
#include "attack_log.h"
#include "wifi_manager.h"
#include "serial_menu.h"
#include "web_dashboard.h"
#include "telnet_honeypot.h"
#include "ssh_honeypot.h"
#include "intel.h"

using namespace honeyopus;

void setup() {
    Serial.begin(115200);
    delay(150);
    Serial.println();
    Serial.println("==== HoneyOpus booting ====");
    Serial.printf("chip: %s rev=%u  cpu=%uMHz  free_heap=%u\n",
                  ESP.getChipModel(), ESP.getChipRevision(),
                  ESP.getCpuFreqMHz(), ESP.getFreeHeap());

    // Bump the global task watchdog timeout from the 5 s default to 30 s so
    // that legitimate slow operations (LittleFS rewrites, TLS handshakes for
    // AbuseIPDB / OTX / GeoIP) on this single-core chip don't reboot us.
    // AsyncTCP's WDT instrumentation is compiled out in platformio.ini
    // (CONFIG_ASYNC_TCP_USE_WDT=0) because its event handlers do inline
    // flash I/O for asciinema cast files which can stall on GC.
    esp_task_wdt_init(30, true);

    g_display.begin();
    g_display.showBootLogo(2000);

    if (!g_config.begin()) Serial.println("[main] config begin failed");
    if (!storage_begin())  Serial.println("[main] LittleFS begin failed");
    g_attack_log.begin();
    {
        auto& c = g_config.get();
        storage_enforce_session_quota(c.max_sessions, (size_t)c.max_session_dir_kb * 1024);
    }

    serial_menu_begin();
    wifi_begin();

    // Apply TZ + NTP from config. ESP-IDF's lwIP sntp_setservername() stores
    // the pointer it's given (no internal copy), so we MUST hand it stable
    // storage that lives forever — passing String::c_str() into it is a
    // use-after-free landmine if those Strings ever get reassigned (or the
    // heap shifts around them). strdup() into never-freed buffers fixes it.
    apply_time_config();

    web_begin();
    intel_begin();
    telnet_begin();
    ssh_begin();
}

void loop() {
    serial_menu_loop();
    wifi_loop();
    g_display.loop();
    delay(5);
}
