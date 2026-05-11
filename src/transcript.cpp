#include "transcript.h"

namespace honeymire {

// JSON-string body escape — strict-ASCII subset.
//
// This is a verbatim port of Asciinema::writeEscaped_ post-Pass-E:
// every byte < 0x20 OR >= 0x80 escapes to \uXXXX, plus the
// standard JSON \", \\, \b, \f, \n, \r, \t. See the long comment
// in src/asciinema.cpp for the rationale (UTF-8 validity, bot
// fingerprinting via raw 0x80-0xFF bytes, asciinema-player
// rendering of \uXXXX). The transcript inherits the same trade-
// offs because the body is consumed by the same downstream
// parsers (ArduinoJson via serialized() into events[], Postgres
// jsonb, JS JSON.parse).
void Transcript::writeEscapedJsonString_(const char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)data[i];
        switch (c) {
            case '"':  f_.write('\\'); f_.write('"'); break;
            case '\\': f_.write('\\'); f_.write('\\'); break;
            case '\b': f_.write('\\'); f_.write('b'); break;
            case '\f': f_.write('\\'); f_.write('f'); break;
            case '\n': f_.write('\\'); f_.write('n'); break;
            case '\r': f_.write('\\'); f_.write('r'); break;
            case '\t': f_.write('\\'); f_.write('t'); break;
            default:
                if (c < 0x20 || c >= 0x80) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    f_.print(buf);
                } else {
                    f_.write(c);
                }
        }
    }
}

// One body record per call: <DIR>:"<escaped-content>"\n
void Transcript::writeRecord_(char dir, const char* data, size_t len) {
    if (!f_ || paused_) return;
    f_.write((uint8_t)dir);
    f_.write((uint8_t)':');
    f_.write((uint8_t)'"');
    writeEscapedJsonString_(data, len);
    f_.write((uint8_t)'"');
    f_.write((uint8_t)'\n');
    bytes_ += len;
    // Periodic flush so a power loss only loses recent records, not
    // the whole session. Mirrors Asciinema's 500 ms cadence.
    if (millis() - last_flush_ms_ > 500) {
        f_.flush();
        last_flush_ms_ = millis();
    }
}

bool Transcript::begin(const String& path, const TranscriptHeader& hdr) {
    f_ = LittleFS.open(path, "w");
    if (!f_) return false;
    path_ = path;
    bytes_ = 0;
    last_flush_ms_ = millis();
    paused_ = false;

    // Header — strict ASCII, one key:value per line. Order chosen
    // for human-readability when the transcript is opened in a
    // text editor; parsers ignore order.
    f_.print("HONEYMIRE-TRANSCRIPT/1\n");
    f_.print("session:");       f_.print(hdr.session_id);            f_.print('\n');
    f_.print("proto:");         f_.print(hdr.proto);                 f_.print('\n');
    if (hdr.persona.length()) {
        f_.print("persona:");   f_.print(hdr.persona);               f_.print('\n');
    }
    if (hdr.hostname.length()) {
        f_.print("hostname:");  f_.print(hdr.hostname);              f_.print('\n');
    }
    if (hdr.user.length()) {
        f_.print("user:");      f_.print(hdr.user);                  f_.print('\n');
    }
    f_.print("authenticated:"); f_.print(hdr.authenticated ? "true" : "false"); f_.print('\n');
    if (hdr.src_ip.length()) {
        f_.print("src:");
        f_.print(hdr.src_ip);
        f_.print(':');
        f_.print(hdr.src_port);
        f_.print('\n');
    }
    if (hdr.ts_iso.length()) {
        f_.print("ts:");        f_.print(hdr.ts_iso);                f_.print('\n');
    }
    f_.print("cols:");          f_.print(hdr.cols);                  f_.print('\n');
    f_.print("rows:");          f_.print(hdr.rows);                  f_.print('\n');
    // Blank line ends the header.
    f_.print('\n');
    return true;
}

void Transcript::out(const char* data, size_t len) { writeRecord_('S', data, len); }
void Transcript::in (const char* data, size_t len) { writeRecord_('O', data, len); }

void Transcript::close() {
    if (f_) {
        f_.flush();
        f_.close();
    }
}

} // namespace honeymire
