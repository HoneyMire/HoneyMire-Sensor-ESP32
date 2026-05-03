#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace honeyopus {

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

    // Per-protocol counters, surfaced in the [health] log.
    void incTelnet()     { tn_total_++; }
    void incTelnetGated(){ tn_gated_++; }
    void incSsh()        { ssh_total_++; }
    void incSshGated()   { ssh_gated_++; }
    void incWeb()        { web_total_++; }

    uint32_t telnetTotal()  const { return tn_total_; }
    uint32_t telnetGated()  const { return tn_gated_; }
    uint32_t sshTotal()     const { return ssh_total_; }
    uint32_t sshGated()     const { return ssh_gated_; }
    uint32_t webTotal()     const { return web_total_; }

    // Number of currently-active telnet connections (live counter, not
    // a historical total).
    void setTelnetActive(uint8_t n) { tn_active_ = n; }
    uint8_t telnetActive() const    { return tn_active_; }

private:
    static constexpr size_t   kSlots          = 16;
    static constexpr uint32_t kCooldownMs     = 5UL * 60UL * 1000UL;

    struct Slot {
        String   ip;
        uint32_t last_ms = 0;
    };
    Slot slots_[kSlots];

    uint32_t tn_total_  = 0;
    uint32_t tn_gated_  = 0;
    uint32_t ssh_total_ = 0;
    uint32_t ssh_gated_ = 0;
    uint32_t web_total_ = 0;
    uint8_t  tn_active_ = 0;
};

extern AttackerGate g_gate;

} // namespace honeyopus
