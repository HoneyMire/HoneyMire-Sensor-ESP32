#include "telnet_honeypot.h"
#include "config.h"
#include "telnet_persona.h"
#include "fake_shell.h"
#include "asciinema.h"
#include "attack_log.h"
#include "display.h"
#include "intel.h"
#include "attack_classifier.h"
#include "storage.h"
#include "attacker_gate.h"
#include "restart_reason.h"

#include <WiFi.h>
#include <AsyncTCP.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <time.h>

namespace honeyopus {

static const uint16_t TN_COLS = 80;
static const uint16_t TN_ROWS = 24;
#ifndef HONEYOPUS_TN_MAX
#define HONEYOPUS_TN_MAX 3
#endif
static const uint8_t  TN_MAX_CONCURRENT = HONEYOPUS_TN_MAX; // per-board cap (see platformio.ini)

static AsyncServer*  s_server = nullptr;
static volatile uint8_t s_active = 0;               // updated on connect/disconnect
// Worker queue: AsyncTCP callbacks just push the session here, the worker task
// does the slow LittleFS finalization so the AsyncTCP polling task stays
// responsive (the previous design starved lwIP and triggered TCP asserts).
//
// The same queue also carries CLOSE jobs from telnet_reap(): the reaper
// runs on loopTask, which is subscribed to the task watchdog, and
// AsyncClient::close(true) can block waiting on lwIP/AsyncTCP internals
// — that path was a known WDT trigger (see ESP32 stability review H2).
// Routing close requests through the worker keeps loopTask boring.
struct TnFinalizeJob {
    enum Kind : uint8_t { K_FINALIZE, K_CLOSE };
    Kind kind;
    void* sess;            // valid when kind == K_FINALIZE
    AsyncClient* client;   // valid when kind == K_CLOSE
};
static QueueHandle_t s_finalize_q = nullptr;

// Live-session registry. AsyncTCP's per-client onPoll / onDisconnect
// callbacks are not always invoked when lwIP tears a pcb down under
// memory pressure; we observed a session admitted at boot and then
// pinned for >4 minutes with neither callback ever firing. The reaper
// (telnet_reap) walks this registry from the main loop and force-closes
// anything past the wall-clock cap, independent of AsyncTCP behavior.
struct TnSession;
static portMUX_TYPE  s_reg_mux = portMUX_INITIALIZER_UNLOCKED;
static TnSession*    s_registry[TN_MAX_CONCURRENT] = {nullptr, nullptr, nullptr};

static void registry_add(TnSession* s) {
    portENTER_CRITICAL(&s_reg_mux);
    for (auto& slot : s_registry) {
        if (slot == nullptr) { slot = s; break; }
    }
    portEXIT_CRITICAL(&s_reg_mux);
}
static void registry_remove(TnSession* s) {
    portENTER_CRITICAL(&s_reg_mux);
    for (auto& slot : s_registry) {
        if (slot == s) { slot = nullptr; break; }
    }
    portEXIT_CRITICAL(&s_reg_mux);
}

static String make_session_path(const char* proto) {
    time_t t = time(nullptr);
    char buf[64];
    if (t > 1700000000) {
        struct tm tm; gmtime_r(&t, &tm);
        snprintf(buf, sizeof(buf),
                 "/sessions/%04d%02d%02dT%02d%02d%02d-%s-%lu.cast",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, proto,
                 (unsigned long)(esp_random() & 0xFFFF));
    } else {
        snprintf(buf, sizeof(buf), "/sessions/%010lu-%s.cast",
                 (unsigned long)millis(), proto);
    }
    return String(buf);
}

// Per-connection session state. Lives on the heap; freed in onDisconnect.
struct TnSession {
    AsyncClient* client = nullptr;
    AttackEntry  entry;
    Asciinema    cast;
    FakeShell    shell;
    TelnetPersona persona = TelnetPersona::Ubuntu;

    enum Phase { P_USER, P_PASS, P_SHELL, P_DEAD };
    Phase    phase = P_USER;
    String   line_buf;        // accumulating current line
    String   pending_user;    // captured during P_USER
    int      attempts = 0;
    bool     iac_skip = false; // gobbling 1 byte after IAC cmd
    int      iac_state = 0;    // 0=normal,1=after IAC,2=after IAC+cmd,3=in subneg
    uint32_t t0 = 0;
    uint32_t last_rx_ms = 0;   // millis() of the most recent inbound packet
                               // — drives the idle-timeout / reaper.
    bool     finalized = false;
    bool     stuck_logged = false; // set once when reaper first reports leak
    uint32_t stuck_at_ms = 0;      // millis() when stuck was first detected
    bool     close_attempted = false; // reaper has tried to close() once
};

// Send `n` bytes, looping over short writes. AsyncTCP's add()/write() may
// accept fewer bytes than asked when its internal pbuf chain is full; if we
// don't loop, the tail of any large message (e.g. shell MOTD) is silently lost.
// Send raw bytes to the attacker. If `record` is false the bytes are not
// written to the asciinema cast — used for telnet IAC negotiation, which is
// protocol noise that a real telnet client consumes silently. Recording it
// shows up as U+FFFD replacement chars on playback.
static void tn_send(TnSession* s, const char* data, size_t n, bool record = true) {
    if (!s || !s->client || !data || n == 0) return;
    if (record) s->cast.out(data, n);
    size_t off = 0;
    uint32_t deadline = millis() + 4000;
    while (off < n && s->client->connected() && millis() < deadline) {
        size_t space = s->client->space();
        if (space == 0) {
            vTaskDelay(pdMS_TO_TICKS(2));
            continue;
        }
        size_t chunk = (n - off < space) ? n - off : space;
        size_t added = s->client->add(data + off, chunk, ASYNC_WRITE_FLAG_COPY);
        if (added == 0) { vTaskDelay(pdMS_TO_TICKS(2)); continue; }
        s->client->send();
        off += added;
    }
}

static void tn_send(TnSession* s, const String& str) {
    tn_send(s, str.c_str(), str.length());
}

static void tn_send_iac_neg(TnSession* s) {
    static const char iac[] = {
        (char)255, (char)251, (char)1,    // WILL ECHO
        (char)255, (char)251, (char)3,    // WILL SUPPRESS-GO-AHEAD
        (char)255, (char)254, (char)34,   // DONT LINEMODE
    };
    tn_send(s, iac, sizeof(iac), /*record=*/false);
}

static void tn_prompt_login(TnSession* s) {
    const auto& profile = telnet_persona_profile(s->persona);
    String banner;
    if (profile.banner) {
        banner = String(profile.banner) + "\r\n";
    }
    char prompt[128];
    snprintf(prompt, sizeof(prompt), profile.login_prompt, profile.hostname);
    banner += prompt;
    tn_send(s, banner);
    s->phase = TnSession::P_USER;
    s->line_buf = "";
}

static void tn_prompt_password(TnSession* s) {
    tn_send(s, "Password: ");
    s->phase = TnSession::P_PASS;
    s->line_buf = "";
}

static void tn_handle_complete_line(TnSession* s) {
    auto& cfg = g_config.get();
    String line = s->line_buf;
    s->line_buf = "";

    if (s->phase == TnSession::P_USER) {
        s->pending_user = line;
        tn_prompt_password(s);
        return;
    }
    if (s->phase == TnSession::P_PASS) {
        s->attempts++;
        s->entry.user = s->pending_user;
        s->entry.pass = line;
        s->entry.auth_attempts = s->attempts;
        if (s->attempts >= cfg.login_attempts_before_accept) {
            s->entry.authenticated = true;
            s->phase = TnSession::P_SHELL;
            // Shell phase has begun — start recording the cast.
            s->cast.setPaused(false);
            const auto& profile = telnet_persona_profile(s->persona);
            s->shell.begin(s->pending_user.length() ? s->pending_user : String(profile.fake_user),
                           profile.hostname);
            s->shell.setPersona(s->persona);
            // Telnet drives the shell from inside an AsyncTCP onData
            // callback; a real delay() in `sleep`/payload-realism would
            // block the network task for up to 3 s. Virtual sleep
            // returns immediately while preserving the forensic event
            // log entry. SSH leaves this off — it runs on its own task.
            s->shell.setVirtualSleep(true);
            s->shell.setSessionInfo(s->entry.id, s->entry.ip, s->entry.port,
                                    "telnet", s->entry.cast_path + ".events.jsonl");
            tn_send(s, s->shell.motd());
            tn_send(s, s->shell.prompt());
        } else {
            tn_send(s, "\r\nLogin incorrect\r\n");
            const auto& profile = telnet_persona_profile(s->persona);
            char prompt[128];
            snprintf(prompt, sizeof(prompt), profile.login_prompt, profile.hostname);
            tn_send(s, prompt);
            s->phase = TnSession::P_USER;
        }
        return;
    }
    if (s->phase == TnSession::P_SHELL) {
        String out = s->shell.execute(line);
        if (out.length()) tn_send(s, out);
        if (s->shell.exitRequested() || s->shell.sessionLimitsExceeded()) {
            s->phase = TnSession::P_DEAD;
            s->client->close();
            return;
        }
        tn_send(s, s->shell.prompt());
        return;
    }
}

static void tn_finalize_inline(TnSession* s) {
    s->entry.duration_ms = millis() - s->t0;
    s->entry.commands = s->shell.commandsRun();
    s->entry.telnet_persona = telnet_persona_name(s->persona);
    classify_attack(s->entry, s->shell.commandSummary(), s->shell.firstCmdMs(), s->shell.lastCmdMs());
    s->cast.close();
    g_attack_log.append(s->entry);
    intel_enqueue(s->entry.id);
    // Quota enforcement (formerly here) moved to the AttackLog
    // persister's periodic loop — see ESP32 stability review ST2.
    // Running it on every finalize made each session pay for an
    // /sessions enumeration, sort, and stat() pass; under bursty
    // attacks that latency stacked up on the worker task and made
    // finalize times unbounded.
    Serial.printf("[telnet] session done id=%u ip=%s user=%s pass=%s authed=%d cmds=%u persona=%s\n",
                  (unsigned)s->entry.id, s->entry.ip.c_str(),
                  s->entry.user.c_str(), s->entry.pass.c_str(),
                  (int)s->entry.authenticated, s->entry.commands,
                  s->entry.telnet_persona.c_str());
}

static void tn_worker_task(void*) {
    for (;;) {
        TnFinalizeJob j{};
        if (xQueueReceive(s_finalize_q, &j, portMAX_DELAY) != pdTRUE) continue;
        if (j.kind == TnFinalizeJob::K_CLOSE) {
            // Close request from telnet_reap. Calling close(true) here
            // (rather than from loopTask) means a slow lwIP teardown
            // can't trip the main-loop watchdog — at worst it stalls
            // the worker, which is nobody's WDT subscriber.
            if (j.client) j.client->close(true);
            continue;
        }
        // K_FINALIZE — run the slow forensics path off the AsyncTCP task.
        TnSession* s = (TnSession*)j.sess;
        if (!s) continue;
        tn_finalize_inline(s);
        delete s;
        if (s_active > 0) s_active--;
        g_gate.setTelnetActive(s_active);
    }
}

static void tn_finalize(TnSession* s) {
    if (s->finalized) return;
    s->finalized = true;
    registry_remove(s);
    // Hand the slow FS / intel work off to the worker so we don't block the
    // AsyncTCP poll task (lwIP gets very upset about that under load).
    // We do NOT detach AsyncTCP callbacks here: calling onDisconnect/onError/
    // onPoll(nullptr,nullptr) takes AsyncTCP's internal lock, which deadlocks
    // when this is called from the main-loop reaper while AsyncTCP is itself
    // blocked (e.g. in a slow Serial.printf). Instead, the callbacks
    // themselves check s->finalized and short-circuit.
    TnFinalizeJob j{};
    j.kind   = TnFinalizeJob::K_FINALIZE;
    j.sess   = s;
    j.client = nullptr;
    if (s_finalize_q && xQueueSend(s_finalize_q, &j, 0) == pdTRUE) return;
    // Queue full or not initialized — finalize inline as a fallback.
    tn_finalize_inline(s);
    delete s;
    if (s_active > 0) s_active--;
    g_gate.setTelnetActive(s_active);
}

static void tn_on_data(void* arg, AsyncClient* /*c*/, void* data, size_t len) {
    auto* s = (TnSession*)arg;
    if (!s || s->phase == TnSession::P_DEAD) return;
    // Reset the idle timer on every received packet — even IAC noise counts
    // as the attacker still being on the line. tn_on_poll / telnet_reap
    // compare last_rx_ms (not t0) so an actively-typing session is never
    // closed for "session too long".
    s->last_rx_ms = millis();
    const uint8_t* p = (const uint8_t*)data;

    // Don't bulk-record the raw input: it includes the attacker's IAC
    // replies (e.g. IAC WILL TTYPE) which look like U+FFFD garbage on
    // playback. We record per-byte further down, after IAC stripping.

    for (size_t i = 0; i < len; ++i) {
        uint8_t ch = p[i];

        // RFC 854 IAC handling.
        if (s->iac_state == 1) {        // saw IAC; expect cmd
            if (ch == 250) { s->iac_state = 3; continue; } // SB ... SE
            if (ch >= 251 && ch <= 254) { s->iac_state = 2; continue; } // WILL/WONT/DO/DONT
            s->iac_state = 0; continue; // other IAC commands (e.g. NOP, IP) — skip
        }
        if (s->iac_state == 2) { s->iac_state = 0; continue; }   // option byte
        if (s->iac_state == 3) {        // gobble until IAC SE (255 240)
            if (ch == 240) s->iac_state = 0;
            continue;
        }
        if (ch == 255) { s->iac_state = 1; continue; }

        // Line editing.
        //
        // We record line-grain (not byte-grain) into the asciicast: per-byte
        // recording produces one i-event AND one o-event (the echo) per
        // keystroke, which on the hub boils down to a useless `i,o,i,o,…`
        // alternation that no amount of same-direction coalescing can fix.
        // Instead we accumulate into s->line_buf and emit a single
        // input-direction event when ENTER (or Ctrl-C) commits the line.
        // Echoes are still sent on the wire (so the attacker sees their
        // typing in real time) but with record=false so they don't pollute
        // the cast.
        if (ch == '\r' || ch == '\n') {
            if (ch == '\r' && i + 1 < len && (p[i+1] == '\n' || p[i+1] == '\0')) i++;
            String evt = s->line_buf + "\r\n";
            s->cast.in(evt.c_str(), evt.length());
            tn_send(s, "\r\n", 2, /*record=*/false);
            tn_handle_complete_line(s);
            continue;
        }
        if (ch == 0x7f || ch == 0x08) {
            if (s->line_buf.length()) {
                s->line_buf.remove(s->line_buf.length() - 1);
                if (s->phase != TnSession::P_PASS)
                    tn_send(s, "\b \b", 3, /*record=*/false);
            }
            continue;
        }
        if (ch == 0x03) { // Ctrl-C — record the abandoned line + ^C\r\n as
                          // one forensic input event (attacker's intent
                          // before they bailed).
            String evt = s->line_buf + "^C\r\n";
            s->cast.in(evt.c_str(), evt.length());
            tn_send(s, "^C\r\n", 4, /*record=*/false);
            s->line_buf = "";
            if (s->phase == TnSession::P_SHELL) tn_send(s, s->shell.prompt());
            continue;
        }
        if (ch < 0x20) continue;
        if (s->line_buf.length() > 256) continue;
        s->line_buf += (char)ch;
        if (s->phase == TnSession::P_PASS) {
            tn_send(s, "*", 1, /*record=*/false);
        } else {
            char e = (char)ch;
            tn_send(s, &e, 1, /*record=*/false);
        }
    }
}

static void tn_on_disconnect(void* arg, AsyncClient* /*c*/) {
    auto* s = (TnSession*)arg;
    if (!s) return;
    // Idempotent: if finalize has already run (or is already queued to
    // the worker), do NOT delete s here — the worker owns its lifetime.
    // Deleting from this path while the worker is mid-finalize causes
    // a use-after-free; AsyncTCP can deliver duplicate disconnect
    // callbacks under memory pressure. See ESP32 stability review H1.
    if (s->finalized) return;
    tn_finalize(s);
}

static void tn_on_error(void* arg, AsyncClient* /*c*/, int8_t error) {
    auto* s = (TnSession*)arg;
    if (!s) return;
    if (s->finalized) return;
    Serial.printf("[telnet] error %d on id=%u\n", (int)error, (unsigned)s->entry.id);
    // Don't finalize here — AsyncTCP will fire onDisconnect right after, and
    // doing it here can race with a concurrent reaper. The disconnect path
    // owns the lifecycle.
}

static void tn_on_timeout(void* arg, AsyncClient* c, uint32_t /*time*/) {
    auto* s = (TnSession*)arg;
    if (s && s->finalized) return;
    if (c) c->close();
}

static void tn_on_poll(void* arg, AsyncClient* c) {
    auto* s = (TnSession*)arg;
    if (!s || !c || s->finalized) return;
    // Idle timeout — only close if the attacker has stopped sending bytes
    // for the full window. Resets on every onData (see tn_on_data). An
    // actively-typing session lives for as long as the attacker keeps
    // sending; only true silence closes it.
    constexpr uint32_t kTnIdleTimeoutMs = 15000;
    if (millis() - s->last_rx_ms > kTnIdleTimeoutMs) {
        c->close();
    }
}

static void tn_on_client(void* /*arg*/, AsyncClient* c) {
    if (!c) return;
    if (!g_config.get().telnet_enabled) { c->close(); return; }
    g_gate.incTelnet();
    String peer_ip = c->remoteIP().toString();
    if (!g_gate.admit(peer_ip)) {
        g_gate.incTelnetGated();
        // No per-connection Serial.printf here: a fast attacker can fire 30+
        // gated connections per second, which floods HWCDC and stalls the
        // AsyncTCP task inside Serial.printf. The total/gated counters in
        // the [health] log are sufficient.
        c->close();
        return;
    }
    if (s_active >= TN_MAX_CONCURRENT) {
        Serial.printf("[telnet] refusing connection from %s — at cap %u\n",
                      peer_ip.c_str(), (unsigned)TN_MAX_CONCURRENT);
        c->close();
        return;
    }
    s_active++;
    g_gate.setTelnetActive(s_active);
    g_gate.touch(peer_ip);

    auto* s = new TnSession();
    s->client = c;
    s->t0 = millis();
    s->last_rx_ms = s->t0;
    s->persona = telnet_persona_random();  // Select random persona per connection
    registry_add(s);
    s->entry.id        = g_attack_log.nextId();
    s->entry.ts        = time(nullptr);
    s->entry.protocol  = "telnet";
    s->entry.ip        = c->remoteIP().toString();
    s->entry.port      = c->remotePort();

    String cast_path   = make_session_path("telnet");
    s->cast.begin(cast_path, TN_COLS, TN_ROWS,
                  "Telnet session from " + s->entry.ip,
                  "/bin/login");
    // Suppress recording during the auth dance — login prompts and the
    // typed credentials are noise in the transcript. The captured
    // user/pass live on s->entry.{user,pass} already; the recorded cast
    // is for the actual shell session that follows.
    s->cast.setPaused(true);
    s->entry.cast_path = cast_path;

    g_display.showAttack(AttackKind::Telnet);

    c->setNoDelay(true);
    c->setRxTimeout(15);     // seconds before lwIP gives up if peer goes silent
    c->setAckTimeout(10000);

    c->onDisconnect(tn_on_disconnect, s);
    c->onError(tn_on_error, s);
    c->onTimeout(tn_on_timeout, s);
    c->onData(tn_on_data, s);
    c->onPoll(tn_on_poll, s);

    tn_send_iac_neg(s);
    tn_prompt_login(s);
}

void telnet_begin() {
    if (s_server) return;
    if (!s_finalize_q) {
        s_finalize_q = xQueueCreate(8, sizeof(TnFinalizeJob));
        xTaskCreate(tn_worker_task, "tn_fin", 6144, nullptr, 1, nullptr);
    }
    s_server = new AsyncServer(HONEYOPUS_TELNET_PORT);
    s_server->onClient(tn_on_client, nullptr);
    s_server->begin();
    Serial.printf("[telnet] AsyncTCP listener on port %u (max %u concurrent)\n",
                  (unsigned)HONEYOPUS_TELNET_PORT, (unsigned)TN_MAX_CONCURRENT);
}

void telnet_reap() {
    // Phase 1: 15 s after the last received byte, mark the session "stuck"
    //          and ask AsyncTCP to close it. Idle-based — an actively
    //          typing attacker keeps last_rx_ms fresh and is left alone.
    //          The v3 lwIP-rcv-window patch makes close() from the main
    //          loop safe again; before that, calling close() here could
    //          panic the device.
    // Phase 2: if 30 s after the close attempt the slot is still occupied,
    //          we've truly leaked it. Better to spend a clean reboot than
    //          to limp along with reduced capacity (and possibly all 3
    //          slots gone — at which point Telnet is fully dead anyway).
    constexpr uint32_t kTnIdleTimeoutMs  = 15000;
    constexpr uint32_t kTnRebootAfterMs  = 30000;
    uint32_t now = millis();

    uint32_t log_vids[TN_MAX_CONCURRENT] = {0, 0, 0};
    size_t   log_n = 0;
    AsyncClient* close_victims[TN_MAX_CONCURRENT] = {nullptr, nullptr, nullptr};
    size_t   close_n = 0;
    bool     reboot_needed = false;
    uint32_t reboot_vid = 0;

    portENTER_CRITICAL(&s_reg_mux);
    for (auto& slot : s_registry) {
        if (!slot || slot->finalized) continue;
        if ((now - slot->last_rx_ms) <= kTnIdleTimeoutMs) continue;
        if (!slot->stuck_logged) {
            slot->stuck_logged   = true;
            slot->stuck_at_ms    = now;
            log_vids[log_n++]    = slot->entry.id;
        }
        if (!slot->close_attempted && slot->client) {
            slot->close_attempted    = true;
            close_victims[close_n++] = slot->client;
        } else if (slot->close_attempted &&
                   (now - slot->stuck_at_ms) > kTnRebootAfterMs) {
            reboot_needed = true;
            reboot_vid    = slot->entry.id;
            break;
        }
    }
    portEXIT_CRITICAL(&s_reg_mux);

    // Log once per stuck session — re-logging every 1 Hz pass floods Serial
    // and can re-introduce the HWCDC-TX-saturation deadlock we just fixed.
    for (size_t i = 0; i < log_n; ++i) {
        Serial.printf("[telnet] reaper: session id=%u idle >%us, closing\n",
                      (unsigned)log_vids[i], (unsigned)(kTnIdleTimeoutMs / 1000));
    }
    // Best-effort close — done on the worker task, NOT here on loopTask.
    // close(true) can block waiting for lwIP/AsyncTCP internal state and
    // would otherwise trip the loopTask watchdog (ESP32 stability review
    // H2). The worker is allowed to stall; loopTask is not.
    for (size_t i = 0; i < close_n; ++i) {
        if (!close_victims[i]) continue;
        TnFinalizeJob j{};
        j.kind   = TnFinalizeJob::K_CLOSE;
        j.sess   = nullptr;
        j.client = close_victims[i];
        if (!s_finalize_q || xQueueSend(s_finalize_q, &j, 0) != pdTRUE) {
            // Queue full — fall back to inline close. Better to risk a
            // single watchdog tick than to leak the slot indefinitely.
            close_victims[i]->close(true);
        }
    }
    if (reboot_needed) {
        Serial.printf("[telnet] reaper: session id=%u still stuck after close, rebooting\n",
                      (unsigned)reboot_vid);
        restart::restart_with(restart::kReasonTelnetStuck);
    }
}

} // namespace honeyopus
