#pragma once

#include <Arduino.h>
#include <vector>
#include "telnet_persona.h"

namespace honeyopus {

// Medium-interaction Ubuntu 18.04 command emulator. The goal is not a real
// shell, but to keep simple bots / brute-force scripts engaged long enough to
// capture credentials, downloader URLs, payload filenames, persistence
// attempts, reverse-shell tricks, etc. No downloaded payload is ever fetched
// or executed; the entire environment is virtual.
//
// See NEW.md for the full behavioral spec this implements.

struct VirtualFile {
    String   path;            // absolute, normalized
    String   content;         // empty for "real" sized fake binaries
    String   source_url;      // wget/curl URL, if any
    String   created_by;      // wget|curl|touch|echo|tee|...
    String   payload_profile; // generic_bot|crypto_miner|mirai_like_bot|...
    String   arch;            // x86_64|x86|arm|...
    uint32_t size = 0;
    uint16_t mode = 0644;
    bool     is_dir = false;
    bool     executable = false;
    bool     executed = false;
    uint16_t exec_count = 0;
    uint32_t created_ms = 0;
    uint32_t mtime_ms = 0;
};

struct FakeProcess {
    uint16_t pid;
    String   user;
    String   tty;
    String   cmd;
    float    cpu = 0.0f;
    float    mem = 0.1f;
    uint32_t vsz = 8000;
    uint32_t rss = 1200;
};

class FakeShell {
public:
    void begin(const String& user, const String& host);
    void setPersona(TelnetPersona p);  // Set the server persona

    // When virtual_sleep is true, `sleep` and the post-payload realism
    // delay return immediately instead of calling delay(). The telnet
    // runner sets this so attacker shell commands don't block the
    // AsyncTCP callback for up to 3 s — see ESP32 stability review H5.
    // SSH runs on its own task and keeps the realistic delay
    // (virtual_sleep stays false).
    void setVirtualSleep(bool v) { virtual_sleep_ = v; }

    // Optional session metadata; safe to call any time before execute(). When
    // events_path is non-empty, structured per-command events are appended as
    // JSONL to that LittleFS file.
    void setSessionInfo(uint32_t session_id,
                        const String& source_ip,
                        uint16_t source_port,
                        const String& protocol,
                        const String& events_path);

    String motd() const;
    String prompt() const;
    String execute(const String& line);

    uint16_t commandsRun() const { return commands_; }
    bool exitRequested() const { return exit_; }

    // Behavioural fingerprint used by the attack classifier. firstCmdMs/lastCmdMs
    // are millis() timestamps of the first/last accepted command (0 if none).
    uint32_t firstCmdMs() const { return first_cmd_ms_; }
    uint32_t lastCmdMs()  const { return last_cmd_ms_;  }
    // Default cap chosen to fit the AbuseIPDB / OTX comment limit
    // (~4 KB) and the hub's command_summary column comfortably while
    // still giving the classifier enough tail context for sessions
    // that ran dozens of distinct commands. Was 1500.
    String   commandSummary(size_t max_bytes = 4000) const;

    // Session caps from NEW.md "Safety Rules". When sessionLimitsExceeded()
    // becomes true the caller (telnet/ssh runner) should drop the connection.
    bool sessionLimitsExceeded() const { return cap_hit_; }

private:
    // ---------- parsing ----------
    struct Cmd {
        String                  exe;     // normalized command name (basename)
        std::vector<String>     argv;    // exe + args (raw, post-quote)
        String                  raw;     // original token slice for logging
        std::vector<std::pair<String,String>> env_prefix; // VAR=value before cmd
        bool                    background = false;
        // Redirections — we don't actually redirect, but we strip and remember.
        bool                    redirect_null  = false;  // >/dev/null, &>/dev/null
        bool                    redirect_stderr_null = false;
        String                  redirect_stdout; // file path if not /dev/null
        String                  redirect_append; // file path for >>
    };
    enum Sep { SEP_NONE, SEP_SEMI, SEP_AND, SEP_OR, SEP_PIPE };
    struct CmdNode {
        Cmd  cmd;
        Sep  follow = SEP_NONE; // separator that follows this node
    };

    static int  splitChain_(const String& line, std::vector<CmdNode>& out);
    static bool parseCmd_(const String& src, Cmd& out);
    static String normalizeExe_(const String& exe);
    static String basename_(const String& p);

    // ---------- execution ----------
    String runChain_(const String& raw_line);
    String runOne_(Cmd& c);
    String runWithRedirects_(Cmd& c);

    // ---------- path / vfs ----------
    String resolvePath_(const String& p) const;
    static bool isWritableDir_(const String& dir);
    VirtualFile* findFile_(const String& abs);
    const VirtualFile* findFile_(const String& abs) const;
    bool fileExists_(const String& abs) const;
    bool isDir_(const String& abs) const;
    VirtualFile* createFile_(const String& abs, const String& created_by);

    // ---------- commands ----------
    String cmdEcho_(Cmd& c);
    String cmdPrintf_(Cmd& c);
    String cmdLs_(Cmd& c);
    String cmdCd_(Cmd& c);
    String cmdCat_(Cmd& c);
    String cmdHead_(Cmd& c, bool tail);
    String cmdGrep_(Cmd& c);
    String cmdWc_(Cmd& c);
    String cmdBase64_(Cmd& c);
    String cmdUname_(Cmd& c);
    String cmdId_(Cmd& c);
    String cmdPs_(Cmd& c);
    String cmdNetstat_(Cmd& c);
    String cmdSs_(Cmd& c);
    String cmdIfconfig_(Cmd& c);
    String cmdIp_(Cmd& c);
    String cmdRoute_(Cmd& c);
    String cmdDf_(Cmd& c);
    String cmdFree_(Cmd& c);
    String cmdUptime_(Cmd& c);
    String cmdW_(Cmd& c);
    String cmdLast_(Cmd& c);
    String cmdMount_(Cmd& c);
    String cmdLscpu_(Cmd& c);
    String cmdEnv_(Cmd& c);
    String cmdExport_(Cmd& c);
    String cmdHistory_(Cmd& c);
    String cmdWget_(Cmd& c);
    String cmdCurl_(Cmd& c);
    String cmdTftp_(Cmd& c);
    String cmdFtpget_(Cmd& c);
    String cmdDd_(Cmd& c);
    String cmdTop_(Cmd& c);
    String cmdChmod_(Cmd& c);
    String cmdChown_(Cmd& c);
    String cmdRm_(Cmd& c);
    String cmdMkdir_(Cmd& c);
    String cmdTouch_(Cmd& c);
    String cmdMv_(Cmd& c);
    String cmdCp_(Cmd& c);
    String cmdWhich_(Cmd& c);
    String cmdWhereis_(Cmd& c);
    String cmdSleep_(Cmd& c);
    String cmdApt_(Cmd& c);
    String cmdDpkg_(Cmd& c);
    String cmdPip_(Cmd& c);
    String cmdCrontab_(Cmd& c);
    String cmdSystemctl_(Cmd& c);
    String cmdService_(Cmd& c);
    String cmdKill_(Cmd& c, const String& which);
    String cmdNc_(Cmd& c);
    String cmdPing_(Cmd& c);
    String cmdIptables_(Cmd& c);
    String cmdUfw_(Cmd& c);
    String cmdShEval_(Cmd& c);    // sh -c / bash -c "..."
    String cmdExecute_(Cmd& c);   // ./file, /tmp/x, etc.
    String cmdInterp_(Cmd& c);    // python/perl/php one-liners

    // ---------- helpers ----------
    static String guessArch_(const String& s);
    static String guessProfile_(const String& url, const String& name);
    void detectReverseShell_(const Cmd& c, String& out);
    void logEvent_(const String& type, const String& json_body);
    void logCommand_(const String& raw, const std::vector<CmdNode>& chain);
    String passwdFile_() const;

    // Accessor for the per-persona content table (PERSONA_CONTENT in
    // fake_shell.cpp). Defined inline at use sites — the struct is
    // file-private to fake_shell.cpp because its fields are
    // implementation details of the FS-CR-1 persona pass.
    const struct PersonaContent& personaContent_() const;

    // Synthesize a /proc/<pid>/<file> or /proc/<topfile> response. Returns
    // true if `abs` is a recognized /proc path and writes its content to
    // `out`. `caller` is the cat/head/tail invocation, used for
    // /proc/self/cmdline so the output reflects the current command exactly
    // as a real kernel would (NUL-separated argv of the calling process).
    bool procVirtualFile_(const String& abs, const Cmd& caller, String& out) const;

private:
    String user_;
    String host_;
    String cwd_ = "/root";
    TelnetPersona persona_ = TelnetPersona::Ubuntu;
    uint16_t commands_ = 0;
    bool     exit_ = false;
    bool     cap_hit_ = false;
    bool     virtual_sleep_ = false;   // see setVirtualSleep()
    uint32_t first_cmd_ms_ = 0;
    uint32_t last_cmd_ms_ = 0;

    // session metadata
    uint32_t session_id_ = 0;
    String   src_ip_;
    uint16_t src_port_ = 0;
    String   proto_;
    String   events_path_;

    // env vars
    std::vector<std::pair<String,String>> env_;

    // command history (raw)
    std::vector<String> history_;

    // virtual filesystem
    std::vector<VirtualFile> files_;
    std::vector<FakeProcess> procs_;

    // crontab content (per-session)
    String crontab_;

    bool last_status_ok_ = true;
    // Set true when runOne_ falls through to the persona's
    // "command not found" path. Used by the `busybox <applet>`
    // dispatcher to distinguish "unknown applet" from "applet ran
    // and emitted its own error" — the former gets rewritten as
    // BusyBox's "applet not found" line, the latter passes through
    // verbatim.
    bool last_was_unknown_cmd_ = false;
};

} // namespace honeyopus
