#pragma once

#include <Arduino.h>

namespace honeymire {

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
    // Format string for unknown-command output, with one %s for the
    // command name. Real shells differ visibly here:
    //   bash:     "-bash: <cmd>: command not found\n"
    //   ash:      "<cmd>: not found\n"        (BusyBox / OpenWrt)
    //   busybox:  "<cmd>: applet not found\n" (busybox <applet> form,
    //                                          handled separately)
    //   RouterOS: "bad command name <cmd> (line 1 column 1)\n"
    // Bots fingerprint on this; getting it right per persona is
    // cheap credibility. NULL falls back to the bash form.
    const char* not_found_fmt;
};

// Select a random persona; call once per telnet session.
TelnetPersona telnet_persona_random();

// Get the profile for a given persona.
const PersonaProfile& telnet_persona_profile(TelnetPersona p);

// Get the name of a persona as a string (e.g., "Ubuntu", "BusyBox").
const char* telnet_persona_name(TelnetPersona p);

} // namespace honeymire
