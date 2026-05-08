#include "telnet_honeypot.h"
#include "config.h"
#include "telnet_persona.h"
#include "fake_shell.h"
#include "recorder.h"
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
#include <freertos/semphr.h>
#include <atomic>
#include <new>   // std::nothrow for fault-tolerant heap allocations
#include <time.h>

namespace honeyopus {

static const uint16_t TN_COLS = 80;
static const uint16_t TN_ROWS = 24;
#ifndef HONEYOPUS_TN_MAX
#define HONEYOPUS_TN_MAX 3
#endif
static const uint8_t  TN_MAX_CONCURRENT = HONEYOPUS_TN_MAX; // per-board cap (see platformio.ini)

// Per-line input cap (TR-1). Bots routinely paste chained one-liners
// > 256 chars; the prior 256-byte cap silently truncated everything
// past that, losing the forensically interesting tail. 4 KB matches
// a realistic shell readline buffer. With TN_MAX_CONCURRENT ≤ 8 (S3
// boards) and one line_buf per session, worst-case heap footprint is
// ≤ 32 KB.
static constexpr size_t kTnLineMaxBytes = 4096;

static AsyncServer*  s_server = nullptr;
// Concurrent-session counter. Written by:
//   - tn_on_client (AsyncTCP task) on accept
//   - K_FINALIZE / K_STUCK_FINALIZE worker (worker task) on cleanup
//   - tn_finalize_inline + telnet_reap fallback (loopTask) on stuck close
// std::atomic gives us a safe inc/dec across cores without the prior
// TOCTOU race where the AsyncTCP task could miss a decrement that the
// worker had just published. The cap check at admit time uses a CAS
// loop so two simultaneous accepts can't both squeeze past
// TN_MAX_CONCURRENT.
static std::atomic<uint8_t> s_active{0};

// Atomic decrement-if-positive — preserves the prior `if (s_active > 0)
// s_active--;` semantics safely. Underflow guard exists because the
// cleanup path may be reached for sessions that were never admitted
// (e.g. socket-accept races).
static inline void s_active_dec_() {
    uint8_t cur = s_active.load(std::memory_order_relaxed);
    while (cur > 0) {
        if (s_active.compare_exchange_weak(cur, (uint8_t)(cur - 1),
                                           std::memory_order_relaxed,
                                           std::memory_order_relaxed)) {
            return;
        }
    }
}
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
    // K_FINALIZE: clean tn_on_disconnect path. Worker runs forensics
    //   AND deletes the TnSession.
    // K_CLOSE:    reaper's force-close of a stuck client. Worker
    //   issues close(true) on the AsyncClient.
    // K_STUCK_FINALIZE: reaper detected a session whose onDisconnect
    //   never fired (typically because AsyncTCP/lwIP wedged when WiFi
    //   went into NOT_AUTHED). Worker runs forensics and decrements
    //   the active slot count, but DOES NOT delete the TnSession —
    //   AsyncTCP may still hold its void* arg. tn_on_disconnect's
    //   idempotent guard (s->finalized) protects a late callback. The
    //   session struct leaks (~hundreds of bytes), but the cast FD is
    //   freed and the slot opens up. Far better than the old escalate-
    //   to-reboot path. See ESP32 stability review H1/H2 follow-up.
    // K_INPUT_LINE: P_SHELL line ready, defer shell.execute() to the
    //   worker. shell.execute() can take 50-150 ms (parse + simulated
    //   filesystem + payload-realism), and running it inline on
    //   tn_on_data was the residual H3 bottleneck after H4 fixed the
    //   send blocker. Worker calls shell.execute(), then tn_send()s
    //   the response and the next prompt — both via the cross-task-
    //   safe out_buf path. `line` is heap-allocated by tn_handle_
    //   complete_line; the worker frees it.
    enum Kind : uint8_t { K_FINALIZE, K_CLOSE, K_STUCK_FINALIZE, K_INPUT_LINE };
    Kind kind;
    void* sess;            // K_FINALIZE / K_STUCK_FINALIZE / K_INPUT_LINE
    AsyncClient* client;   // K_CLOSE
    String* line;          // K_INPUT_LINE only — owned by the job, worker frees
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
    AsyncClient*    client = nullptr;
    AttackEntry     entry;
    SessionRecorder cast;
    FakeShell       shell;
    TelnetPersona persona = TelnetPersona::Ubuntu;

    enum Phase { P_USER, P_PASS, P_SHELL, P_DEAD };
    Phase    phase = P_USER;
    String   line_buf;        // accumulating current line
    String   pending_user;    // captured during P_USER
    int      attempts = 0;
    bool     iac_skip = false; // gobbling 1 byte after IAC cmd
    int      iac_state = 0;    // 0=normal,1=after IAC,2=after IAC+cmd,3=in subneg
    bool     line_overflow_beeped = false;  // \a sent for current over-cap line
    uint32_t t0 = 0;
    uint32_t last_rx_ms = 0;   // millis() of the most recent inbound packet
                               // — drives the idle-timeout / reaper.
    bool     finalized = false;
    bool     stuck_logged = false; // set once when reaper first reports leak
    uint32_t stuck_at_ms = 0;      // millis() when stuck was first detected
    bool     close_attempted = false; // reaper has tried to close() once

    // Outbound ring (ESP32 stability review H4). Bytes destined for the
    // attacker are appended here by tn_send() and drained by
    // tn_pump_out_() — never inline-blocked. The old loop with
    // vTaskDelay(2) up to 4 s was the worst head-of-line blocker on
    // the AsyncTCP task: a single slow / silent client could hold the
    // whole task for seconds. Capped at kTnOutboundCap so a stuck
    // peer can't grow this unbounded.
    String   out_buf;
    size_t   out_dropped = 0;    // bytes dropped because the cap was hit
    // Guards out_buf for the H3 hand-off: worker task (running
    // shell.execute → tn_send) and AsyncTCP task (onAck/onPoll →
    // tn_pump_out_) both touch it. Created in tn_on_client.
    SemaphoreHandle_t out_mux = nullptr;
    // millis() at the moment forensics finished. Set by
    // tn_finalize_inline. The zombie sweeper uses this to decide
    // when AsyncTCP has had enough time to stop touching us.
    uint32_t finalized_at_ms = 0;

    // Destructor cleans up the FreeRTOS semaphore so deleting a
    // session (whether via the clean-disconnect K_FINALIZE path or
    // the zombie sweeper) doesn't leak a kernel object. Other
    // members (Strings, FakeShell, Asciinema, AttackEntry) destruct
    // automatically; the cast file is closed by tn_finalize_inline
    // before the session ever reaches a delete path.
    ~TnSession() {
        if (out_mux) {
            vSemaphoreDelete(out_mux);
            out_mux = nullptr;
        }
    }
};
static constexpr size_t kTnOutboundCap = 16 * 1024;

// Zombie list — sessions whose forensics ran via the K_STUCK_FINALIZE
// path. They can't be deleted immediately because AsyncTCP may still
// hold the void* arg and could call back into tn_on_data /
// tn_on_disconnect / tn_on_poll. The zombie sweeper (called from
// telnet_reap) walks this list and frees entries whose grace period
// has elapsed — long enough that AsyncTCP has definitely cleaned up
// its side of the connection.
//
// Without this, every stuck session leaked the TnSession struct
// (~few hundred bytes including FakeShell + Asciinema + Strings +
// the FreeRTOS semaphore) until reboot. At ~1/min stuck rate that's
// ~kB/hour — bounded but cumulative on a heap-tight C3.
static const size_t   kTnZombieMax     = 16;
static const uint32_t kTnZombieGraceMs = 5UL * 60UL * 1000UL;  // 5 minutes
static portMUX_TYPE   s_zombie_mux     = portMUX_INITIALIZER_UNLOCKED;
static TnSession*     s_zombies[kTnZombieMax] = {};

// Add a finalized session to the zombie list. Returns true on success.
// Caller has already set s->finalized = true and removed s from the
// active registry. If the zombie list is full we accept the leak
// rather than risk a use-after-free by deleting too early.
static bool zombie_add_(TnSession* s) {
    if (!s) return false;
    bool added = false;
    portENTER_CRITICAL(&s_zombie_mux);
    for (auto& slot : s_zombies) {
        if (slot == nullptr) { slot = s; added = true; break; }
    }
    portEXIT_CRITICAL(&s_zombie_mux);
    return added;
}

// Sweep zombies whose grace period has elapsed. Called from telnet_reap
// once per second.
static void zombie_sweep_(uint32_t now) {
    TnSession* to_free[kTnZombieMax] = {};
    size_t fn = 0;
    portENTER_CRITICAL(&s_zombie_mux);
    for (auto& slot : s_zombies) {
        if (!slot) continue;
        if (now - slot->finalized_at_ms > kTnZombieGraceMs) {
            to_free[fn++] = slot;
            slot = nullptr;
        }
    }
    portEXIT_CRITICAL(&s_zombie_mux);
    // Delete outside the critical section — destructors can take the
    // FreeRTOS scheduler lock (vSemaphoreDelete) which would deadlock
    // under portENTER_CRITICAL.
    for (size_t i = 0; i < fn; ++i) {
        if (to_free[i]) {
            uint32_t id = to_free[i]->entry.id;
            delete to_free[i];
            Serial.printf("[telnet] zombie reaped id=%u (grace %us elapsed)\n",
                          (unsigned)id, (unsigned)(kTnZombieGraceMs / 1000));
        }
    }
}

// Drain bytes from the per-session outbound ring into AsyncTCP. Bounded
// — accepts whatever space() returns this call and returns. The
// AsyncTCP poll callback fires periodically and onAck fires on every
// peer ACK, both of which call this; head-of-line blocking is gone.
//
// The H3 hand-off makes this race-able: the worker task calls tn_send
// (appending to out_buf) while AsyncTCP onAck/onPoll concurrently
// call tn_pump_out_ (reading + removing from out_buf). out_mux
// serializes both. We snapshot bytes under the lock into a small
// stack buffer, drop the lock, call AsyncClient::add (which can take
// tens of µs because it crosses into the lwIP context), then re-take
// the lock to remove the consumed prefix. This keeps the critical
// section short.
static void tn_pump_out_(TnSession* s) {
    if (!s || !s->client) return;
    if (!s->client->connected()) {
        if (s->out_mux) xSemaphoreTake(s->out_mux, portMAX_DELAY);
        s->out_buf = String();
        if (s->out_mux) xSemaphoreGive(s->out_mux);
        return;
    }
    size_t space = s->client->space();
    if (space == 0) return;
    char tmp[1024];
    size_t take = 0;
    if (s->out_mux) xSemaphoreTake(s->out_mux, portMAX_DELAY);
    size_t avail = s->out_buf.length();
    if (avail) {
        take = avail;
        if (take > space)        take = space;
        if (take > sizeof(tmp))  take = sizeof(tmp);
        memcpy(tmp, s->out_buf.c_str(), take);
    }
    if (s->out_mux) xSemaphoreGive(s->out_mux);
    if (!take) return;
    size_t added = s->client->add(tmp, take, ASYNC_WRITE_FLAG_COPY);
    if (added == 0) return;
    s->client->send();
    if (s->out_mux) xSemaphoreTake(s->out_mux, portMAX_DELAY);
    // The buffer can only have grown (concat tail) since we snapshotted;
    // the head bytes we just sent are still at offset 0.
    if (s->out_buf.length() >= added) s->out_buf.remove(0, added);
    else                              s->out_buf = String();
    if (s->out_mux) xSemaphoreGive(s->out_mux);
}

// Append bytes to the outbound ring. Safe to call from either the
// AsyncTCP task (e.g. tn_handle_complete_line for auth phase) or the
// worker task (shell.execute response, prompts). Does NOT call
// tn_pump_out_ inline — to avoid recursive lock acquisition. Drains
// happen via onPoll, onAck, and an explicit pump at the end of
// tn_on_data so latency stays low for the AsyncTCP-driven path.
// record=false suppresses asciinema recording (used for IAC
// negotiation noise + per-char echoes during line editing).
static void tn_send(TnSession* s, const char* data, size_t n, bool record = true) {
    if (!s || !s->client || !data || n == 0) return;
    if (record) s->cast.out(data, n);
    if (s->out_mux) xSemaphoreTake(s->out_mux, portMAX_DELAY);
    size_t cur = s->out_buf.length();
    if (cur >= kTnOutboundCap) {
        s->out_dropped += n;
        if (s->out_mux) xSemaphoreGive(s->out_mux);
        return;
    }
    size_t room = kTnOutboundCap - cur;
    size_t take = (n < room) ? n : room;
    if (take < n) s->out_dropped += (n - take);
    s->out_buf.concat(data, take);
    if (s->out_mux) xSemaphoreGive(s->out_mux);
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
        // H3: defer shell.execute() to the worker so the AsyncTCP
        // task can return promptly. The line text is copied to the
        // heap; the worker frees it.
        String* line_heap = new (std::nothrow) String(line);
        if (line_heap && s_finalize_q) {
            TnFinalizeJob j{};
            j.kind   = TnFinalizeJob::K_INPUT_LINE;
            j.sess   = s;
            j.client = nullptr;
            j.line   = line_heap;
            if (xQueueSend(s_finalize_q, &j, 0) == pdTRUE) return;
        }
        // Heap or queue full — fall back to inline execution. Better
        // a brief AsyncTCP stall than to drop attacker input.
        delete line_heap;
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
        if (j.kind == TnFinalizeJob::K_STUCK_FINALIZE) {
            // Reaper-driven forensics for a session whose
            // onDisconnect never fired. Run the same forensics path
            // (close cast file, persist entry), then hand the session
            // over to the zombie list — the sweeper will delete it
            // after a 5-minute grace period, by which time AsyncTCP
            // has definitely stopped touching the void* arg. The H1
            // idempotent guard in tn_on_disconnect is the safety net
            // for any callback that fires inside the grace window.
            TnSession* s = (TnSession*)j.sess;
            if (!s) continue;
            tn_finalize_inline(s);
            s->finalized_at_ms = millis();
            if (!zombie_add_(s)) {
                Serial.printf("[telnet] zombie list full, leaking TnSession id=%u\n",
                              (unsigned)s->entry.id);
            }
            s_active_dec_();
            g_gate.setTelnetActive(s_active.load(std::memory_order_relaxed));
            continue;
        }
        if (j.kind == TnFinalizeJob::K_INPUT_LINE) {
            // Shell command from a P_SHELL session. shell.execute()
            // synthesizes the response (50-150 ms typical, longer for
            // a payload-realism path); doing it here keeps the
            // AsyncTCP task free for the next packet.
            TnSession* s = (TnSession*)j.sess;
            String* line = j.line;
            if (s && !s->finalized && line) {
                String out = s->shell.execute(*line);
                if (out.length()) tn_send(s, out);
                if (s->shell.exitRequested() || s->shell.sessionLimitsExceeded()) {
                    s->phase = TnSession::P_DEAD;
                    if (s->client) s->client->close();
                } else {
                    tn_send(s, s->shell.prompt());
                }
                // Push whatever we just appended toward the wire so
                // the attacker doesn't wait until the next onPoll.
                tn_pump_out_(s);
            }
            delete line;
            continue;
        }
        // K_FINALIZE — clean disconnect path. Run the slow forensics
        // off the AsyncTCP task and free the session.
        TnSession* s = (TnSession*)j.sess;
        if (!s) continue;
        tn_finalize_inline(s);
        delete s;
        s_active_dec_();
        g_gate.setTelnetActive(s_active.load(std::memory_order_relaxed));
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
    s_active_dec_();
    g_gate.setTelnetActive(s_active.load(std::memory_order_relaxed));
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
            s->line_overflow_beeped = false;
            continue;
        }
        if (ch == 0x7f || ch == 0x08) {
            if (s->line_buf.length()) {
                s->line_buf.remove(s->line_buf.length() - 1);
                if (s->phase != TnSession::P_PASS)
                    tn_send(s, "\b \b", 3, /*record=*/false);
            }
            // Trailing edit drops below cap → re-arm the bell for further
            // overflow on this same line.
            if (s->line_buf.length() < kTnLineMaxBytes)
                s->line_overflow_beeped = false;
            continue;
        }
        if (ch == 0x03) { // Ctrl-C — record the abandoned line + ^C\r\n as
                          // one forensic input event (attacker's intent
                          // before they bailed).
            String evt = s->line_buf + "^C\r\n";
            s->cast.in(evt.c_str(), evt.length());
            tn_send(s, "^C\r\n", 4, /*record=*/false);
            s->line_buf = "";
            s->line_overflow_beeped = false;
            if (s->phase == TnSession::P_SHELL) tn_send(s, s->shell.prompt());
            continue;
        }
        if (ch < 0x20) continue;
        // Per-line input cap. Bumped from 256 → 4096 (TR-1): bots routinely
        // paste chained one-liners > 256 chars (`for pid in /proc/[0-9]*; do
        // …`-style multi-stage payloads), and silent truncation past 256
        // tossed the most forensically interesting tail. 4 KB matches a
        // realistic shell readline buffer; with TN_MAX_CONCURRENT≤8 the
        // worst-case heap footprint is ≤32 KB. On the first byte that
        // exceeds the cap, ring the terminal bell once (real shells do
        // similar via readline) so the attacker sees a signal instead of
        // their input being silently swallowed; further chars drop
        // silently until the line resets.
        if (s->line_buf.length() >= kTnLineMaxBytes) {
            if (!s->line_overflow_beeped) {
                s->line_overflow_beeped = true;
                tn_send(s, "\a", 1, /*record=*/false);
            }
            continue;
        }
        s->line_buf += (char)ch;
        if (s->phase == TnSession::P_PASS) {
            tn_send(s, "*", 1, /*record=*/false);
        } else {
            char e = (char)ch;
            tn_send(s, &e, 1, /*record=*/false);
        }
    }
    // Drain whatever the auth-phase sends (and now-deferred shell
    // responses that may have landed before us) accumulated. tn_send
    // no longer pumps inline — see its comment block.
    tn_pump_out_(s);
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
    // Outbound drain — fires periodically (~1 Hz default) without
    // blocking. The combination of this + tn_on_ack means
    // out_buf empties promptly without tn_send ever blocking the
    // AsyncTCP task.
    tn_pump_out_(s);
    // Idle close is owned by telnet_reap (loopTask). Both paths used
    // to fire at the 15 s mark, racing each other: tn_on_poll's plain
    // c->close() vs the reaper's K_CLOSE worker job. Both are
    // currently safe (the H1 idempotent guard + close_attempted flag
    // make a double-close benign), but having two paths fight for
    // the same close muddied the Serial log and made WDT triage
    // harder. The reaper owns idle-close exclusively now: it tracks
    // stuck_logged / close_attempted, frees the registry slot under
    // the critical section, and routes close(true) through the
    // worker so loopTask never blocks on AsyncTCP/lwIP teardown.
    // tn_on_timeout (AsyncTCP's own idle hook) is still wired and
    // still drives c->close() on libssh-style TCP timeout — that
    // path remains the AsyncTCP-internal one, not duplicating the
    // reaper.
}

static void tn_on_ack(void* arg, AsyncClient* /*c*/, size_t /*len*/, uint32_t /*time*/) {
    auto* s = (TnSession*)arg;
    if (!s || s->finalized) return;
    // Peer ACKed bytes → space() just got bigger → drain.
    tn_pump_out_(s);
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
    // Atomic check-and-increment — closes the prior TOCTOU window where
    // two simultaneous accepts could both pass the cap test and both
    // increment, putting s_active over TN_MAX_CONCURRENT.
    uint8_t prev = s_active.load(std::memory_order_relaxed);
    while (true) {
        if (prev >= TN_MAX_CONCURRENT) {
            Serial.printf("[telnet] refusing connection from %s — at cap %u\n",
                          peer_ip.c_str(), (unsigned)TN_MAX_CONCURRENT);
            c->close();
            return;
        }
        if (s_active.compare_exchange_weak(prev, (uint8_t)(prev + 1),
                                           std::memory_order_relaxed,
                                           std::memory_order_relaxed)) {
            break;
        }
    }
    g_gate.setTelnetActive((uint8_t)(prev + 1));
    g_gate.touch(peer_ip);

    auto* s = new TnSession();
    s->client = c;
    s->t0 = millis();
    s->last_rx_ms = s->t0;
    s->persona = telnet_persona_random();  // Select random persona per connection
    s->out_mux = xSemaphoreCreateMutex();   // guards out_buf across worker / AsyncTCP
    registry_add(s);
    s->entry.id        = g_attack_log.nextId();
    s->entry.ts        = time(nullptr);
    s->entry.protocol  = "telnet";
    s->entry.ip        = c->remoteIP().toString();
    s->entry.port      = c->remotePort();

    String cast_path   = make_session_path("telnet");
    const auto& tn_profile = telnet_persona_profile(s->persona);
    bool cast_open = recorder_begin(s->cast, cast_path, TN_COLS, TN_ROWS,
                                    "Telnet session from " + s->entry.ip,
                                    "/bin/login",
                                    s->entry.id, "telnet",
                                    telnet_persona_name(s->persona),
                                    tn_profile.hostname,
                                    /* user */ String(),
                                    /* authenticated */ false,
                                    s->entry.ip, s->entry.port);
    // Suppress recording during the auth dance — login prompts and the
    // typed credentials are noise in the transcript. The captured
    // user/pass live on s->entry.{user,pass} already; the recorded cast
    // is for the actual shell session that follows.
    s->cast.setPaused(true);
    if (cast_open) {
        s->entry.cast_path = cast_path;
    } else {
        // LittleFS pressure or transient open failure. Leave
        // entry.cast_path empty so the hub reporter and the local
        // dashboard skip the recording cleanly instead of probing for
        // a file that isn't there.
        Serial.printf("[telnet] cast open failed for id=%u path=%s — recording disabled for this session\n",
                      (unsigned)s->entry.id, cast_path.c_str());
    }

    g_display.showAttack(AttackKind::Telnet);

    c->setNoDelay(true);
    c->setRxTimeout(15);     // seconds before lwIP gives up if peer goes silent
    c->setAckTimeout(10000);

    c->onDisconnect(tn_on_disconnect, s);
    c->onError(tn_on_error, s);
    c->onTimeout(tn_on_timeout, s);
    c->onData(tn_on_data, s);
    c->onPoll(tn_on_poll, s);
    c->onAck(tn_on_ack, s);

    tn_send_iac_neg(s);
    tn_prompt_login(s);
}

void telnet_begin() {
    if (s_server) return;
    if (!s_finalize_q) {
        s_finalize_q = xQueueCreate(8, sizeof(TnFinalizeJob));
        // Bumped from 6144 → 8192. The worker now also runs
        // shell.execute() (H3) which uses several stacked Strings,
        // ArduinoJson StaticJsonDocs, and recursive command handlers.
        xTaskCreate(tn_worker_task, "tn_fin", 8192, nullptr, 1, nullptr);
    }
    s_server = new AsyncServer(HONEYOPUS_TELNET_PORT);
    s_server->onClient(tn_on_client, nullptr);
    s_server->begin();
    Serial.printf("[telnet] AsyncTCP listener on port %u (max %u concurrent)\n",
                  (unsigned)HONEYOPUS_TELNET_PORT, (unsigned)TN_MAX_CONCURRENT);
}

void telnet_reap() {
    // 15 s after the last received byte, mark the session stuck and
    // immediately drive it through forensics + slot release. Idle-based
    // — an actively typing attacker keeps last_rx_ms fresh and is left
    // alone.
    //
    // The previous escalation chain (close → wait 30 s → reboot if
    // still stuck) was the wrong shape: it depended on AsyncTCP's
    // onDisconnect actually firing to run forensics, and when it
    // didn't (typically because lwIP/AsyncTCP wedged after a WiFi
    // NOT_AUTHED deauth) the cast file FD stayed open, the next
    // /sessions quota pass failed to unlink it, and the device fell
    // off into a reboot. Now the reaper queues the forensics
    // directly to the worker as K_STUCK_FINALIZE — closes the cast,
    // persists the entry, frees the slot — and AsyncTCP's eventual
    // (or never) onDisconnect is harmless because the H1 idempotent
    // guard makes it a no-op.
    constexpr uint32_t kTnIdleTimeoutMs  = 15000;
    uint32_t now = millis();

    uint32_t log_vids[TN_MAX_CONCURRENT] = {0, 0, 0};
    size_t   log_n = 0;
    AsyncClient* close_victims[TN_MAX_CONCURRENT] = {nullptr, nullptr, nullptr};
    size_t   close_n = 0;
    TnSession* finalize_victims[TN_MAX_CONCURRENT] = {nullptr, nullptr, nullptr};
    size_t   finalize_n = 0;

    portENTER_CRITICAL(&s_reg_mux);
    for (auto& slot : s_registry) {
        if (!slot || slot->finalized) continue;
        if ((now - slot->last_rx_ms) <= kTnIdleTimeoutMs) continue;
        if (!slot->stuck_logged) {
            slot->stuck_logged   = true;
            slot->stuck_at_ms    = now;
            log_vids[log_n++]    = slot->entry.id;
        }
        if (!slot->close_attempted) {
            slot->close_attempted = true;
            // Mark finalized + remove from registry NOW so a second
            // reaper pass doesn't double-queue work for this slot.
            // The H1 idempotent guard keeps tn_on_disconnect safe.
            slot->finalized = true;
            if (slot->client) close_victims[close_n++] = slot->client;
            finalize_victims[finalize_n++] = slot;
            slot = nullptr;   // release the registry slot for new sessions
        }
    }
    portEXIT_CRITICAL(&s_reg_mux);

    // Log once per stuck session — re-logging every 1 Hz pass floods Serial
    // and can re-introduce the HWCDC-TX-saturation deadlock we just fixed.
    for (size_t i = 0; i < log_n; ++i) {
        Serial.printf("[telnet] reaper: session id=%u idle >%us, finalizing\n",
                      (unsigned)log_vids[i], (unsigned)(kTnIdleTimeoutMs / 1000));
    }

    // Drive forensics + slot release for each stuck session via the
    // worker task. Off loopTask so a slow LFS close can't trip the
    // watchdog (H2). The worker runs tn_finalize_inline (closes cast
    // file → frees the FD that the quota enforcer was tripping on)
    // and decrements s_active. It does NOT delete the TnSession,
    // because AsyncTCP may still hold its arg pointer; H1's
    // idempotent tn_on_disconnect makes a late callback safe.
    for (size_t i = 0; i < finalize_n; ++i) {
        if (!finalize_victims[i]) continue;
        TnFinalizeJob jf{};
        jf.kind   = TnFinalizeJob::K_STUCK_FINALIZE;
        jf.sess   = finalize_victims[i];
        jf.client = nullptr;
        if (!s_finalize_q || xQueueSend(s_finalize_q, &jf, 0) != pdTRUE) {
            // Queue full — run forensics inline as a last resort. The
            // small risk of a watchdog tick is preferable to leaving
            // the cast FD open and the slot occupied.
            tn_finalize_inline(finalize_victims[i]);
            finalize_victims[i]->finalized_at_ms = millis();
            if (!zombie_add_(finalize_victims[i])) {
                Serial.printf("[telnet] zombie list full (inline path), leaking id=%u\n",
                              (unsigned)finalize_victims[i]->entry.id);
            }
            s_active_dec_();
            g_gate.setTelnetActive(s_active.load(std::memory_order_relaxed));
        }
    }
    // Best-effort close — also queued to the worker, NOT here on
    // loopTask. close(true) can block on lwIP/AsyncTCP internals
    // (review H2). With forensics already queued above, even if
    // close(true) wedges forever, file resources and the slot are
    // already released.
    for (size_t i = 0; i < close_n; ++i) {
        if (!close_victims[i]) continue;
        TnFinalizeJob j{};
        j.kind   = TnFinalizeJob::K_CLOSE;
        j.sess   = nullptr;
        j.client = close_victims[i];
        if (!s_finalize_q || xQueueSend(s_finalize_q, &j, 0) != pdTRUE) {
            // Queue full — fall back to inline close.
            close_victims[i]->close(true);
        }
    }
    // The old "reboot if still stuck after 30 s" escalation is gone.
    // Forensics + slot release are now eager (queued above), so the
    // device keeps running instead of bouncing every minute when
    // AsyncTCP/lwIP wedges. The kReasonTelnetStuck restart bucket is
    // retained in restart_reason.h for any future use.

    // Sweep zombies whose 5-minute grace has elapsed. AsyncTCP has
    // had ample time to drop its callback args by then; safe to
    // delete now and reclaim the per-session heap (~few hundred
    // bytes including FakeShell + Asciinema + Strings + the
    // FreeRTOS semaphore the destructor cleans up).
    zombie_sweep_(now);
}

} // namespace honeyopus
