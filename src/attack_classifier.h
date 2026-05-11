#pragma once

#include "attack_log.h"

namespace honeymire {

// Returns one of: "mirai", "iot-loader", "scanner", "scripted", "manual",
// "recon-script", "creds-only", "creds-probe", "lan", "unknown".
// `cmds` is a newline-joined list of commands the attacker actually ran
// (typically FakeShell::commandSummary()). `first_ms` / `last_ms` are
// millis() timestamps of the first/last command (0 if none).
// Writes the chosen label into e.profile and a 0..100 confidence score into
// e.profile_confidence.
void classify_attack(AttackEntry& e,
                     const String& cmds,
                     uint32_t first_ms,
                     uint32_t last_ms);

// Returns a short emoji glyph + text alt for a given profile label. The
// caller is expected to render `<span title="alt" aria-label="alt">icon</span>`.
struct ProfileVisual { const char* icon; const char* alt; };
ProfileVisual profile_visual(const String& label);

} // namespace honeymire
