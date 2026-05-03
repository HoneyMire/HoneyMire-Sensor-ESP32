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

using namespace honeyopus;

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
static void honeyopus_new_handler() {
    ets_printf("[heap] OOM new_handler free=%u largest=%u — restart\n",
               (unsigned)ESP.getFreeHeap(),
               (unsigned)ESP.getMaxAllocHeap());
    esp_restart();
}

void setup() {
    Serial.begin(115200);
    delay(150);
    std::set_new_handler(honeyopus_new_handler);
    Serial.println();
    Serial.println("==== HoneyOpus booting ====");
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

    // Periodic health beacon. Without this, when the user reports "web is
    // gone" we have nothing to correlate against — AsyncTCP's lone
    // `rx timeout 4` line is benign (it's just an idle keep-alive being
    // reaped). Logging heap, mode and uptime every 30 s lets us tell apart
    // heap exhaustion, WiFi loss, AsyncTCP wedging and "device is fine,
    // browser tab is stale".
    static uint32_t last_health = 0;
    uint32_t now = millis();
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
            Serial.flush();
            delay(50);
            ESP.restart();
        }
    } else {
        low_heap_since = 0;
    }

    delay(5);
}
