// HoneyMire — multi-board ESP32 Telnet/SSH honeypot with optional OLED/TFT
// feedback, captive portal,
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
#include <new>
#include <esp_task_wdt.h>
#include <esp_system.h>
#include <esp_rom_sys.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <rom/ets_sys.h>

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
#include "attacker_gate.h"
#include "restart_reason.h"

using namespace honeymire;

// Last-resort guard. AsyncWebServer / mbedTLS / ArduinoJson all use plain
// `new` and don't catch std::bad_alloc. When heap runs out, the unhandled
// exception unwinds straight to __cxxabiv1::__terminate which aborts with
// a confusing register dump. Restarting cleanly is far better.
//
// IMPORTANT: this can be called from *any* task, including from inside
// HWCDC::write / vfprintf / FreeRTOS internals while UART or stdio mutexes
// are held. Touching Serial.printf here would recurse into the same locks
// and assert (lock_acquire_generic / xQueueTakeMutexRecursive). Use
// ets_printf which writes to the ROM UART driver directly and is safe in
// any context.
static void honeymire_new_handler() {
    ets_printf("[heap] OOM new_handler free=%u largest=%u — restart\n",
               (unsigned)ESP.getFreeHeap(),
               (unsigned)ESP.getMaxAllocHeap());
    esp_restart();
}

void setup() {
    // On the ESP32-S3 with native USB-CDC (`ARDUINO_USB_MODE=1` +
    // `ARDUINO_USB_CDC_ON_BOOT=1`), the CDC port enumerates a few hundred
    // ms after reset. Bumping the RX buffer and giving the host a moment
    // to (re)open the port makes the serial menu reliably catch keystrokes
    // typed right after a reboot — without affecting boards that already
    // had a stable serial path.
    Serial.setRxBufferSize(512);
    Serial.begin(115200);
#if ARDUINO_USB_CDC_ON_BOOT && !defined(HONEYMIRE_USE_UART0_SERIAL)
    // HWCDC blocks on TX when the host hasn't opened the port yet. Drop
    // characters instead of stalling the loop task — much safer for a
    // headless honeypot that may run for weeks without anyone attached.
    Serial.setTxTimeoutMs(0);
    // Wait briefly for the host to open the CDC port; bail after 800 ms so
    // headless / power-only deployments still boot promptly.
    for (uint32_t t0 = millis(); !Serial && (millis() - t0) < 800; ) {
        delay(20);
    }
#endif
    delay(150);
    std::set_new_handler(honeymire_new_handler);
    Serial.println();
    Serial.println("==== HoneyMire booting (" HONEYMIRE_BOARD_NAME ") ====");
    restart::log_on_boot();
    restart::breadcrumb_log_on_boot();
    restart::breadcrumb("setup");
    Serial.printf("chip: %s rev=%u  cpu=%uMHz  free_heap=%u\n",
                  ESP.getChipModel(), ESP.getChipRevision(),
                  ESP.getCpuFreqMHz(), ESP.getFreeHeap());

    // Bump the global task watchdog timeout from the 5 s default and detach
    // CPU 0's IDLE task. ESP32-C3 is single-core: when async_tcp callbacks
    // open or write to a fragmented LittleFS, the cast file commit can stall
    // the CPU for several seconds during littlefs garbage collection. That
    // starves the IDLE task and the IDLE-task WDT (subscribed by default in
    // arduino-esp32) panics us. Flash GC is not a real lockup; the interrupt
    // watchdog (independent, hardware) still detects genuine CPU hangs.
    // AsyncTCP's per-event WDT subscription is already compiled out via
    // -DCONFIG_ASYNC_TCP_USE_WDT=0 in platformio.ini.
    esp_task_wdt_init(60, true);
    {
        TaskHandle_t idle0 = xTaskGetIdleTaskHandle();
        if (idle0) esp_task_wdt_delete(idle0);
    }
    // Subscribe the Arduino loop() task itself. Without this nothing watches
    // the main loop — and we've seen it wedge silently for >10 min after a
    // close(true) on a stuck telnet client. With the loop task subscribed,
    // a hang is auto-recovered within 60 s with a clear panic log instead
    // of the device dropping off Wi-Fi and never coming back.
    esp_task_wdt_add(nullptr);

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

    // Start the web dashboard unless the user has explicitly disabled it
    // AND we're in STA mode AND at least one intel reporter is active.
    // In AP fallback / setup mode we ALWAYS start the web server, otherwise
    // the user has no way to fix wifi credentials (the captive portal
    // lives there). The intel-active check is also re-applied on toggle
    // (web POST / serial menu), but we double-check here in case the
    // saved state is inconsistent (e.g. NVS edited externally).
    {
        auto& c = g_config.get();
        bool ap_mode  = (wifi_mode() == NetMode::FallbackAP);
        bool start_ok = c.web_enabled || ap_mode || !intel_any_active(c);
        if (start_ok) {
            web_begin();
        } else {
            Serial.println("[web] disabled by config (web_enabled=false). "
                           "Re-enable via serial menu 'w' or by clearing all "
                           "intel reporters.");
        }
    }
    intel_begin();
    telnet_begin();
    ssh_begin();
}

void loop() {
    esp_task_wdt_reset();
    // Section breadcrumbs — see ESP32 stability review WD1. The tag is
    // stamped to RTC slow memory before each call; if a WDT panic or
    // hard fault hits inside one of these, the next boot's log shows
    // which section was running. Cost: one 32-bit write per section.
    restart::breadcrumb("serial");
    serial_menu_loop();
    restart::breadcrumb("wifi");
    wifi_loop();
    restart::breadcrumb("display");
    g_display.loop();

    // Periodic health beacon. Without this, when the user reports "web is
    // gone" we have nothing to correlate against — AsyncTCP's lone
    // `rx timeout 4` line is benign (it's just an idle keep-alive being
    // reaped). Logging heap, mode and uptime every 30 s lets us tell apart
    // heap exhaustion, WiFi loss, AsyncTCP wedging and "device is fine,
    // browser tab is stale".
    static uint32_t last_health = 0;
    uint32_t now = millis();

    static uint32_t last_reap = 0;
    if (now - last_reap > 1000) {
        last_reap = now;
        restart::breadcrumb("telnet_reap");
        telnet_reap();
    }

    if (now - last_health > 30000) {
        last_health = now;
        const char* mode = "?";
        switch (wifi_mode()) {
            case NetMode::Boot:          mode = "boot"; break;
            case NetMode::ConnectingSTA: mode = "sta-conn"; break;
            case NetMode::OnlineSTA:     mode = "sta"; break;
            case NetMode::FallbackAP:    mode = "ap"; break;
        }
        Serial.printf("[health] up=%us heap=%u largest=%u min=%u mode=%s ip=%s "
                      "ssh=%d tn_act=%u tn=%u/%u ssh=%u/%u web=%u\n",
                      (unsigned)(now / 1000),
                      (unsigned)ESP.getFreeHeap(),
                      (unsigned)ESP.getMaxAllocHeap(),
                      (unsigned)ESP.getMinFreeHeap(),
                      mode,
                      wifi_ip_string().c_str(),
                      ssh_listener_running() ? 1 : 0,
                      (unsigned)g_gate.telnetActive(),
                      (unsigned)g_gate.telnetTotal(), (unsigned)g_gate.telnetGated(),
                      (unsigned)g_gate.sshTotal(),    (unsigned)g_gate.sshGated(),
                      (unsigned)g_gate.webTotal());
    }

    // Heap watchdog. libssh has known residual allocations after ssh_free
    // (~50 KB lost per session even on a clean disconnect). Once the device
    // has been beaten down to a sliver of heap and stays there, the
    // dashboard goes dark and TCP backlogs collapse. Cleanly rebooting is
    // far better than serving 503s for the rest of the uptime.
    static uint32_t low_heap_since = 0;
    constexpr size_t kCriticalHeap = 45000;
    constexpr uint32_t kLowHeapRebootMs = 90000;
    if (ESP.getFreeHeap() < kCriticalHeap) {
        if (low_heap_since == 0) low_heap_since = now;
        else if (now - low_heap_since > kLowHeapRebootMs) {
            Serial.printf("[health] heap stuck low for %us — rebooting\n",
                          (unsigned)((now - low_heap_since) / 1000));
            restart::restart_with(restart::kReasonHeapLow);
        }
    } else {
        low_heap_since = 0;
    }

    restart::breadcrumb("idle");
    delay(5);
}
