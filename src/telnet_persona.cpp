#include "telnet_persona.h"
#include <esp_random.h>

namespace honeyopus {

static const PersonaProfile profiles[] = {
    {
        TelnetPersona::Ubuntu,
        "Ubuntu 22.04.1 LTS",
        "%s login: ",
        nullptr,
        "ubuntu-server",
        "ubuntu"
    },
    {
        TelnetPersona::BusyBox,
        nullptr,  // No banner
        "%s login: ",
        "BusyBox v1.35.0 (2022-12-01) built-in shell (ash)\nEnter 'help' for a list of built-in commands.",
        "router",
        "admin"
    },
    {
        TelnetPersona::RouterOS,
        "MikroTik RouterOS 7.5",
        "[%s] > ",  // RouterOS uses > not login:
        nullptr,
        "MikroTik",
        "admin"
    },
    {
        TelnetPersona::OpenWrt,
        "OpenWrt",
        "%s login: ",
        nullptr,
        "OpenWrt",
        "root"
    },
    {
        TelnetPersona::DVRDVS,
        nullptr,
        "%s login: ",
        "DVRDVS DVR System\nType ? for help",
        "DVRDVS",
        "admin"
    },
    {
        TelnetPersona::HiLinux,
        "Welcome to HiLinux.\n",
        "(%s) login: ",
        nullptr,
        "hilinux-nvrbox",
        "root"
    }
};

TelnetPersona telnet_persona_random() {
    static const TelnetPersona all[] = {
        TelnetPersona::Ubuntu,
        TelnetPersona::BusyBox,
        TelnetPersona::RouterOS,
        TelnetPersona::OpenWrt,
        TelnetPersona::DVRDVS,
        TelnetPersona::HiLinux
    };
    uint32_t idx = esp_random() % 6;
    return all[idx];
}

const PersonaProfile& telnet_persona_profile(TelnetPersona p) {
    return profiles[(int)p];
}

const char* telnet_persona_name(TelnetPersona p) {
    switch (p) {
        case TelnetPersona::Ubuntu:   return "Ubuntu";
        case TelnetPersona::BusyBox:  return "BusyBox";
        case TelnetPersona::RouterOS: return "RouterOS";
        case TelnetPersona::OpenWrt:  return "OpenWrt";
        case TelnetPersona::DVRDVS:   return "DVRDVS";
        case TelnetPersona::HiLinux:  return "HiLinux";
        default:                      return "Unknown";
    }
}

} // namespace honeyopus
