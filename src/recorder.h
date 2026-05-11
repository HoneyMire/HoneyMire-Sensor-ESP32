#pragma once

// Compile-time selector between the legacy asciicast writer and the
// plain-text Transcript writer. Default-OFF: callers see Asciinema
// exactly as before. Define HONEYMIRE_USE_TRANSCRIPT in the build
// flags to switch the on-disk format. See
// docs/PLAN_PLAINTEXT_TRANSCRIPT.md for the full migration plan.
//
// All call sites (telnet_honeypot.cpp, ssh_honeypot.cpp) reference
// SessionRecorder rather than Asciinema directly. The in()/out()/
// close()/setPaused()/isOpen()/path()/bytes() API is identical
// across both classes; only begin() differs (Asciinema wants
// cols/rows/title/shell; Transcript wants a header struct), so
// the recorder_begin() adapter below handles the difference.

#include <Arduino.h>
#include <time.h>

#if HONEYMIRE_USE_TRANSCRIPT
  #include "transcript.h"
#else
  #include "asciinema.h"
#endif

namespace honeymire {

#if HONEYMIRE_USE_TRANSCRIPT
using SessionRecorder = Transcript;
#else
using SessionRecorder = Asciinema;
#endif

// Unified begin() adapter — both honeypot paths go through this.
// Header fields used only by Transcript (proto / persona / user /
// authenticated / src_ip / src_port / session_id) are silently
// ignored when SessionRecorder is Asciinema. The title and
// shell_cmd fields are used only by Asciinema and ignored by
// Transcript. ts_iso is derived from time() if NTP-synced.
inline bool recorder_begin(SessionRecorder& r,
                           const String& path,
                           uint16_t cols, uint16_t rows,
                           const String& title,
                           const String& shell_cmd,
                           uint32_t session_id,
                           const String& proto,
                           const String& persona,
                           const String& hostname,
                           const String& user,
                           bool authenticated,
                           const String& src_ip,
                           uint16_t src_port) {
#if HONEYMIRE_USE_TRANSCRIPT
    (void)title;
    (void)shell_cmd;
    TranscriptHeader h;
    h.session_id    = session_id;
    h.proto         = proto;
    h.persona       = persona;
    h.hostname      = hostname;
    h.user          = user;
    h.authenticated = authenticated;
    h.src_ip        = src_ip;
    h.src_port      = src_port;
    h.cols          = cols;
    h.rows          = rows;
    time_t t = time(nullptr);
    if (t > 1700000000) {
        struct tm tm;
        gmtime_r(&t, &tm);
        char buf[24];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        h.ts_iso = buf;
    }
    return r.begin(path, h);
#else
    (void)session_id;
    (void)proto;
    (void)persona;
    (void)hostname;
    (void)user;
    (void)authenticated;
    (void)src_ip;
    (void)src_port;
    return r.begin(path, cols, rows, title, shell_cmd);
#endif
}

} // namespace honeymire
