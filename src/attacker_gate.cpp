#include "attacker_gate.h"

namespace honeyopus {

AttackerGate g_gate;

bool AttackerGate::admit(const String& ip) {
    if (ip.length() == 0) return true;
    uint32_t now = millis();
    for (auto& s : slots_) {
        if (s.ip == ip && s.last_ms != 0 &&
            (now - s.last_ms) < kCooldownMs) {
            return false;
        }
    }
    return true;
}

void AttackerGate::touch(const String& ip) {
    if (ip.length() == 0) return;
    uint32_t now = millis();
    // First pass: existing slot for this IP -> refresh.
    for (auto& s : slots_) {
        if (s.ip == ip) { s.last_ms = now; return; }
    }
    // Otherwise evict the oldest.
    Slot* oldest = &slots_[0];
    for (auto& s : slots_) {
        if (s.last_ms < oldest->last_ms) oldest = &s;
    }
    oldest->ip = ip;
    oldest->last_ms = now;
}

} // namespace honeyopus
