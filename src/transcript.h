#pragma once

#include <Arduino.h>
#include <LittleFS.h>

namespace honeymire {

// Plain-text on-device session transcript. Replaces the asciicast
// writer (src/asciinema.{h,cpp}) on the storage path, behind the
// HONEYMIRE_USE_TRANSCRIPT compile flag. See
// docs/PLAN_PLAINTEXT_TRANSCRIPT.md for the full design rationale.
//
// File format ("HONEYMIRE-TRANSCRIPT/1"):
//
//   HONEYMIRE-TRANSCRIPT/1
//   session:1234
//   proto:telnet
//   persona:HiLinux
//   hostname:hilinux-nvrbox
//   user:root
//   authenticated:true
//   src:185.104.63.91:54321
//   ts:2026-05-08T14:23:45Z
//   cols:80
//   rows:24
//   <blank line>
//   S:"Welcome to HiLinux.\r\n(hilinux-nvrbox) login: "
//   O:"root\r\n"
//   S:"Password: "
//   ...
//
// The body uses the exact same strict-ASCII JSON-string escape as
// Asciinema::writeEscaped_ post-Pass-E: every byte < 0x20 OR >= 0x80
// becomes \uXXXX, plus the standard JSON \", \\, \b, \f, \n, \r, \t.
// Strict-ASCII guarantees the file parses cleanly anywhere
// (Postgres jsonb, JS JSON.parse, ArduinoJson) without UTF-8
// surprises — the cornerstone trade-off from the cast escape pass.
//
// Header field naming and ordering is forwards-compatible: unknown
// keys are ignored by parsers, new keys can be added without
// bumping the magic line.
struct TranscriptHeader {
    uint32_t session_id    = 0;
    String   proto;          // "telnet" or "ssh"
    String   persona;        // "Ubuntu", "HiLinux", … or "ssh" for SSH sessions
    String   hostname;
    String   user;
    bool     authenticated = false;
    String   src_ip;
    uint16_t src_port      = 0;
    String   ts_iso;         // ISO 8601 UTC, empty if NTP unsynced at session start
    uint16_t cols          = 80;
    uint16_t rows          = 24;
};

class Transcript {
public:
    bool begin(const String& path, const TranscriptHeader& hdr);
    void out(const char* data, size_t len);
    void in (const char* data, size_t len);
    void out(const String& s) { out(s.c_str(), s.length()); }
    void in (const String& s) { in (s.c_str(), s.length()); }
    void close();

    bool isOpen() const { return (bool)f_; }
    String path() const { return path_; }
    size_t bytes() const { return bytes_; }

    // Same semantics as Asciinema::setPaused — while paused, in/out
    // become no-ops. Used to suppress recording during the auth
    // dance so the body starts at the shell phase.
    void setPaused(bool p) { paused_ = p; }
    bool isPaused() const  { return paused_; }

private:
    void writeRecord_(char dir, const char* data, size_t len);
    void writeEscapedJsonString_(const char* data, size_t len);

    File     f_;
    String   path_;
    uint32_t last_flush_ms_ = 0;
    size_t   bytes_ = 0;
    bool     paused_ = false;
};

} // namespace honeymire
