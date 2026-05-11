#pragma once

#include <Arduino.h>
#include <stdint.h>
#include <freertos/FreeRTOS.h>
#include <freertos/portmacro.h>

namespace honeymire {

// Tiny ring of recently-seen attacker IPs used to slam the door on repeat
// connections from the same source. The honeypot's job is to capture
// what bots try ONCE — letting the same IP back in every few seconds
// just leaks ~50 KB of libssh heap per repeat (libssh has known
// non-zero residual allocations even after ssh_free) and starves the
// dashboard of memory.
//
// Counters are also surfaced so the [health] log can show how many
// telnet / ssh / web events have happened since boot. Lets us correlate
// "heap dropped" with "<which protocol> just had activity".
class AttackerGate {
public:
    // Call when an inbound TCP connection arrives. Returns true if the
    // peer should be admitted; false if it's still in the cooldown
    // window from a recent attack and should be dropped at the gate.
    bool admit(const String& ip);

    // Stamp an IP as "seen now" (called when a session begins).
    void touch(const String& ip);

    // Per-protocol counters, surfaced in the [health] log. All mutators
    // and readers share a critical section because callers span four
    // FreeRTOS tasks (telnet AsyncTCP, SSH, web, loopTask). Without it,
    // 32-bit counter increments are not guaranteed atomic on Xtensa
    // ESP32 — and the String slot mutations under touch() definitely
    // are not. See ESP32 stability review H6.
    void incTelnet()     { Lock l(mux_); tn_total_++; }
    void incTelnetGated(){ Lock l(mux_); tn_gated_++; }
    void incSsh()        { Lock l(mux_); ssh_total_++; }
    void incSshGated()   { Lock l(mux_); ssh_gated_++; }
    void incWeb()        { Lock l(mux_); web_total_++; }

    uint32_t telnetTotal()  const { Lock l(mux_); return tn_total_; }
    uint32_t telnetGated()  const { Lock l(mux_); return tn_gated_; }
    uint32_t sshTotal()     const { Lock l(mux_); return ssh_total_; }
    uint32_t sshGated()     const { Lock l(mux_); return ssh_gated_; }
    uint32_t webTotal()     const { Lock l(mux_); return web_total_; }

    // Number of currently-active telnet connections (live counter, not
    // a historical total).
    void setTelnetActive(uint8_t n) { Lock l(mux_); tn_active_ = n; }
    uint8_t telnetActive() const    { Lock l(mux_); return tn_active_; }

private:
    static constexpr size_t   kSlots          = 16;
    static constexpr uint32_t kCooldownMs     = 5UL * 60UL * 1000UL;

    struct Slot {
        String   ip;
        uint32_t last_ms = 0;
    };

    // RAII helper around a FreeRTOS critical section. portMUX_TYPE is a
    // spinlock; sections must stay short and must NOT touch flash, the
    // network stack, or anything that can block. AttackerGate's ops
    // (slot scan up to 16 entries, counter ++, String copy of an IP)
    // are all constant-time and allocator-light. .ip is a pre-existing
    // String slot; assignment uses its own heap allocations, but those
    // happen here in O(few bytes), and the alternative — letting two
    // tasks race on the underlying buffer — is heap corruption.
    struct Lock {
        portMUX_TYPE& m;
        explicit Lock(portMUX_TYPE& mx) : m(mx) { portENTER_CRITICAL(&m); }
        ~Lock() { portEXIT_CRITICAL(&m); }
        Lock(const Lock&) = delete;
        Lock& operator=(const Lock&) = delete;
    };
    mutable portMUX_TYPE mux_ = portMUX_INITIALIZER_UNLOCKED;

    Slot slots_[kSlots];

    uint32_t tn_total_  = 0;
    uint32_t tn_gated_  = 0;
    uint32_t ssh_total_ = 0;
    uint32_t ssh_gated_ = 0;
    uint32_t web_total_ = 0;
    uint8_t  tn_active_ = 0;
};

extern AttackerGate g_gate;

} // namespace honeymire
