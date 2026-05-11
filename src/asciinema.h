#pragma once

#include <Arduino.h>
#include <LittleFS.h>

namespace honeymire {

// Asciicast v2 writer: https://docs.asciinema.org/manual/asciicast/v2/
// Header is the first line as a single-line JSON object, then events follow:
//   [time_offset, "o" | "i", "data"]
// where data is JSON-string-escaped UTF-8.
//
// DEPRECATED post-TX (2026-05-08). The on-device session storage path now
// dispatches via src/recorder.h to the plain-text Transcript writer when
// the firmware is built with HONEYMIRE_USE_TRANSCRIPT defined; default
// builds still instantiate Asciinema, so this class stays in the tree
// for one soak cycle. After HONEYMIRE_USE_TRANSCRIPT is flipped
// default-on in platformio.ini and a release ships, the class can be
// removed along with src/asciinema.cpp; the read-side dual-format
// parsers (intel.cpp::hub_build_events_, web_dashboard.cpp::send_cast,
// the /play page JS) keep working with legacy `.cast` files written by
// older firmware in the field, so the read paths must outlive this
// writer. See docs/PLAN_PLAINTEXT_TRANSCRIPT.md for the full migration
// plan and which downstream consumers anchor the format choice.
class Asciinema {
public:
    bool begin(const String& path,
               uint16_t cols,
               uint16_t rows,
               const String& title,
               const String& shell_cmd = "/bin/bash");
    void out(const char* data, size_t len);
    void in(const char* data, size_t len);
    void out(const String& s) { out(s.c_str(), s.length()); }
    void in (const String& s) { in (s.c_str(), s.length()); }
    void close();

    bool isOpen() const { return f_; }
    String path() const { return path_; }
    size_t bytes() const { return bytes_; }

    // While paused, in()/out() become no-ops. The honeypots use this to
    // suppress recording during the auth dance (login prompts, typed
    // credentials) — the captured user/pass already live on the
    // AttackEntry, and the recorded transcript is more useful when it
    // contains only the shell session itself. Defaults to NOT paused
    // for backwards compatibility; honeypots opt in by calling
    // setPaused(true) right after begin() and setPaused(false) when
    // the shell phase starts.
    void setPaused(bool p) { paused_ = p; }
    bool isPaused() const  { return paused_; }

private:
    void writeEvent_(char kind, const char* data, size_t len);
    void writeEscaped_(const char* data, size_t len);

    File     f_;
    String   path_;
    uint32_t start_us_ = 0;
    uint32_t last_flush_ms_ = 0;
    size_t   bytes_ = 0;
    bool     paused_ = false;
};

} // namespace honeymire
