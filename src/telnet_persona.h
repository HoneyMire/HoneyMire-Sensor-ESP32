#pragma once

#include <Arduino.h>

namespace honeyopus {

// Telnet server personas — each represents a distinct device/OS that attackers
// expect to find on the honeypot. Randomly selected per connection.
enum class TelnetPersona {
    Ubuntu,    // Generic Linux server with full bash tooling
    BusyBox,   // Embedded Linux, minimal shell + busybox applets
    RouterOS,  // MikroTik RouterOS — menu-driven, not POSIX shell
    OpenWrt,   // OpenWrt router — POSIX shell but limited commands
    DVRDVS,    // DVR firmware — device-specific CLI
    HiLinux,   // Obscure NVR OS — minimal sysinfo-only shell
};

struct PersonaProfile {
    TelnetPersona persona;
    const char* banner;          // NULL = no banner, just prompts
    const char* login_prompt;    // format string with %s for hostname
    const char* post_login_msg;  // NULL = no message
    const char* hostname;        // Default: "localhost"
    const char* fake_user;       // Default: "root"
};

// Select a random persona; call once per telnet session.
TelnetPersona telnet_persona_random();

// Get the profile for a given persona.
const PersonaProfile& telnet_persona_profile(TelnetPersona p);

// Get the name of a persona as a string (e.g., "Ubuntu", "BusyBox").
const char* telnet_persona_name(TelnetPersona p);

} // namespace honeyopus
