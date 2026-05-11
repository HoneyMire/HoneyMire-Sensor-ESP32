#include "attack_classifier.h"
#include "intel.h"

namespace honeymire {

// Compact subset of the original Mirai bruteforce dictionary plus a few common
// IoT-botnet variants (Gafgyt, Hajime, Bashlite). High-signal entries only.
static const struct { const char* u; const char* p; } MIRAI_DICT[] = {
    {"root", "xc3511"},  {"root", "vizxv"},   {"root", "admin"},
    {"admin", "admin"},  {"root", "888888"},  {"root", "xmhdipc"},
    {"root", "default"}, {"root", "juantech"},{"root", "123456"},
    {"root", "54321"},   {"support", "support"},{"root", ""},
    {"admin", ""},       {"root", "root"},    {"root", "12345"},
    {"user", "user"},    {"admin", "password"},{"root", "pass"},
    {"root", "klv123"},  {"root", "Zte521"},  {"root", "hi3518"},
    {"root", "jvbzd"},   {"root", "anko"},    {"root", "zlxx."},
    {"root", "7ujMko0vizxv"},{"root", "7ujMko0admin"},
    {"root", "system"},  {"root", "ikwb"},    {"root", "dreambox"},
    {"root", "user"},    {"root", "realtek"}, {"root", "00000000"},
    {"admin", "1111111"},{"admin", "1234"},   {"admin", "12345"},
    {"admin", "54321"},  {"admin", "123456"}, {"admin", "7ujMko0admin"},
    {"admin", "pass"},   {"admin", "meinsm"}, {"tech", "tech"},
    {"mother", "fucker"},{"ubnt", "ubnt"},    {"root", "666666"},
    {"root", "password"},{"root", "1234"},    {"guest", "guest"},
    {"guest", "12345"},  {"administrator", "1234"},
    {"666666", "666666"},{"888888", "888888"},
};

static bool match_mirai_creds(const String& u, const String& p) {
    for (auto& it : MIRAI_DICT) {
        if (u.equals(it.u) && p.equals(it.p)) return true;
    }
    return false;
}

static bool contains(const String& s, const char* needle) {
    return s.indexOf(needle) >= 0;
}

static bool contains_any(const String& s, std::initializer_list<const char*> needles) {
    for (auto n : needles) if (s.indexOf(n) >= 0) return true;
    return false;
}

// Cheap "looks like a typo" detector — humans hit Backspace or fat-finger;
// scripts don't. We look for command lines that are clearly mistakes
// (non-existing common command, double letters, etc.).
static bool looks_like_typos(const String& cmds) {
    static const char* TYPOS[] = {
        "knwn_", "auhtorized", "autorized", "lls ", "sl ", "cdd ", "exi ",
        "claer", "cler ", "histroy", "passwrd", "psswd", "nano ",
    };
    for (auto t : TYPOS) if (cmds.indexOf(t) >= 0) return true;
    return false;
}

void classify_attack(AttackEntry& e,
                     const String& cmds,
                     uint32_t first_ms,
                     uint32_t last_ms) {
    auto set = [&](const char* lbl, uint8_t conf) {
        e.profile = lbl;
        e.profile_confidence = conf;
    };

    String low = cmds; low.toLowerCase();

    // 1. Strongest signature: explicit Mirai/Gafgyt/Bashlite strings in payload.
    //    LAN sources are *not* short-circuited — the 🏠 already shows in the Geo
    //    column, and we still want to know what the attacker tried.
    if (contains_any(cmds, {"ECCHI", "MIRAI", "OWARI", "HOHO", "GAFGYT", "TSUNAMI", "LZRD"}) ||
        contains(low, "/bin/busybox echo") ||
        contains(low, "/bin/busybox cat /bin/sh")) {
        set("mirai", 95);
        return;
    }

    // 2. Generic IoT loader pattern: fetch + chmod + run from /tmp.
    bool fetch  = contains_any(low, {"wget ", "curl ", "tftp ", "ftpget"});
    bool chmod  = contains_any(low, {"chmod 777", "chmod +x", "chmod 755"});
    bool tmpexec= contains_any(low, {"/tmp/", "/var/run/", "./.x", "./loligang"});
    if (fetch && (chmod || tmpexec)) {
        set("iot-loader", 88);
        return;
    }

    // 3. No commands at all.
    if (e.commands == 0) {
        if (match_mirai_creds(e.user, e.pass)) { set("scanner", 75); return; }
        if (e.auth_attempts > 0) set("creds-only", 60);
        else                     set("creds-probe", 70);
        return;
    }

    // 4. Cadence-based: average gap between commands.
    uint32_t span = (last_ms > first_ms) ? (last_ms - first_ms) : 0;
    uint32_t avg_gap = (e.commands > 1) ? (span / (e.commands - 1)) : span;

    bool human_signals = looks_like_typos(cmds) ||
                         contains_any(low, {"clear\n", "history", "sudo ", "vi ", "vim ", "nano "});

    bool recon = contains(low, "uname -a") &&
                 contains_any(low, {"/proc/cpuinfo", "lscpu", "free -m", "df -h", "ip a", "ifconfig"});

    if (human_signals && avg_gap > 800) { set("manual", 80); return; }
    if (match_mirai_creds(e.user, e.pass) && recon) { set("scanner", 80); return; }
    if (recon && avg_gap < 500)         { set("recon-script", 80); return; }
    if (avg_gap < 150 && e.commands >= 3) { set("scripted", 75); return; }
    if (match_mirai_creds(e.user, e.pass)) { set("scanner", 65); return; }
    if (avg_gap > 1500)                 { set("manual", 55); return; }

    // Fallback — at least we know it's a LAN-internal probe vs. an internet
    // scanner. The 🏠 in Geo already conveys the network location.
    if (intel_ip_is_private(e.ip)) { set("lan", 30); return; }
    set("scanner", 40);
}

ProfileVisual profile_visual(const String& label) {
    if (label == "mirai")        return {"\xF0\x9F\x91\xBE", "Mirai/IoT-botnet"};        // 👾
    if (label == "iot-loader")   return {"\xF0\x9F\x93\xA6", "IoT loader / dropper"};   // 📦
    if (label == "scanner")      return {"\xF0\x9F\xA4\x96", "Automated scanner"};      // 🤖
    if (label == "scripted")     return {"\xF0\x9F\xA4\x96", "Scripted attack"};        // 🤖
    if (label == "recon-script") return {"\xF0\x9F\x94\x8D", "Recon script"};           // 🔍
    if (label == "manual")       return {"\xF0\x9F\xA7\x91", "Manual operator"};        // 🧑
    if (label == "creds-probe")  return {"\xF0\x9F\x97\x9D",  "Credential probe"};      // 🗝
    if (label == "creds-only")   return {"\xF0\x9F\x9A\xAA", "Logged in, no commands"}; // 🚪
    if (label == "lan")          return {"\xF0\x9F\x8F\xA0", "LAN / internal"};         // 🏠
    return {"\xE2\x9D\x93", "Unknown"};                                                  // ❓
}

} // namespace honeymire
