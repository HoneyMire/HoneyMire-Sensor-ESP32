#include "ssh_honeypot.h"
#include "config.h"
#include "fake_shell.h"
#include "recorder.h"
#include "attack_log.h"
#include "display.h"
#include "intel.h"
#include "attack_classifier.h"
#include "storage.h"
#include "attacker_gate.h"

#if HONEYMIRE_ENABLE_SSH

#include <WiFi.h>
#include <LittleFS.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <time.h>
#include <sys/socket.h>
#include <lwip/sockets.h>

#include <libssh_esp32.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

namespace honeymire {

// Per-session inactivity ceiling. libssh's blocking ssh_message_get / recv
// has no built-in timeout, so a slow-loris attacker (TCP connect, finish
// KEX, then sit silent) would pin the SSH listener forever — and on
// ESP32-C3 each live libssh session occupies ~100 KB of heap.
//
// SO_RCVTIMEO/SO_SNDTIMEO on the session FD makes blocking recv/send
// inside libssh return EAGAIN promptly so our wall-clock deadline checks
// can actually fire.
static const int      kSshSocketTimeoutSec = 5;
// Idle timeout: drop the session after this much wall-clock with no
// attacker activity. The clock RESETS on every received SSH message and
// on every byte read inside the fake shell, so a bot or human that's
// actively poking around keeps the session alive indefinitely. Only true
// silence (slow-loris, dead TCP, attacker walked away) trips it. We'd
// rather drop a quiet socket and free the ~100 KB libssh footprint for
// the next attacker than hold the slot open for a peer who's gone.
static const uint32_t kSshIdleTimeoutMs   = 15000;

// LittleFS in Arduino-ESP32 mounts at the VFS base "/littlefs". libssh fopen()s
// from this VFS path; the Arduino LittleFS API uses paths *without* the prefix.
static const char* HOSTKEY_VFS = "/littlefs/etc/host_rsa";
static const char* HOSTKEY_FS  = "/etc/host_rsa";

static const uint16_t SSH_COLS = 80;
static const uint16_t SSH_ROWS = 24;

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

static volatile bool s_hostkey_ready = false;
static volatile bool s_hostkey_generating = false;
static volatile bool s_listener_running = false;

bool ssh_hostkey_ready()    { return s_hostkey_ready; }
bool ssh_listener_running() { return s_listener_running; }

static bool ensure_host_key() {
    if (fs_exists_silent(HOSTKEY_FS)) { s_hostkey_ready = true; return true; }
    if (!fs_exists_silent("/etc")) LittleFS.mkdir("/etc");
    Serial.println("[ssh] generating RSA-2048 host key — this takes ~30s on C3...");
    ssh_key k = nullptr;
    int rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &k);
    if (rc != SSH_OK || !k) {
        Serial.printf("[ssh] ssh_pki_generate failed rc=%d\n", rc);
        return false;
    }
    rc = ssh_pki_export_privkey_file(k, NULL, NULL, NULL, HOSTKEY_VFS);
    ssh_key_free(k);
    if (rc != SSH_OK) {
        Serial.printf("[ssh] export_privkey_file failed rc=%d  (vfs=%s)\n", rc, HOSTKEY_VFS);
        return false;
    }
    Serial.println("[ssh] host key generated");
    s_hostkey_ready = true;
    return true;
}

// One-shot keygen task. Must run after LittleFS is mounted. We yield often by
// not blocking anything else: this task simply blocks while libssh crunches RSA
// primes, but the FreeRTOS scheduler keeps AsyncTCP, web, and the OLED state
// machine happy because we run at the lowest priority.
static void ssh_keygen_task(void*) {
    // libssh init must happen before any pki call; safe to call repeatedly.
    libssh_begin();
    ssh_init();
    ensure_host_key();
    s_hostkey_generating = false;
    vTaskDelete(nullptr);
}

static void chan_write(ssh_channel chan, SessionRecorder& cast, const char* s, size_t n) {
    if (!chan || !s || n == 0) return;
    ssh_channel_write(chan, s, n);
    cast.out(s, n);
}
static void chan_write(ssh_channel chan, SessionRecorder& cast, const String& s) {
    chan_write(chan, cast, s.c_str(), s.length());
}

// Send bytes to the attacker WITHOUT recording into the asciicast — used
// for per-char echoes during line editing. We record line-grain into the
// cast (one input event per completed line); per-char echoes would
// pollute the stream with a useless `i,o,i,o,…` alternation that no
// hub-side coalescing can fix.
static void chan_write_norec(ssh_channel chan, const char* s, size_t n) {
    if (!chan || !s || n == 0) return;
    ssh_channel_write(chan, s, n);
}

static void run_fake_shell(ssh_session sess, ssh_channel chan, AttackEntry& entry, SessionRecorder& cast) {
    auto& cfg = g_config.get();
    FakeShell shell;
    shell.begin(entry.user.length() ? entry.user : String(cfg.fake_user), cfg.fake_hostname);
    shell.setSessionInfo(entry.id, entry.ip, entry.port, "ssh",
                         entry.cast_path + ".events.jsonl");
    // Shell phase: start recording the cast.
    cast.setPaused(false);
    chan_write(chan, cast, shell.motd());
    chan_write(chan, cast, shell.prompt());

    String line;
    char buf[128];
    // Idle timer: reset on every byte the attacker sends. An actively
    // typing session lives indefinitely; only true silence trips the cap.
    uint32_t last_activity_ms = millis();
    while (!shell.exitRequested() && !shell.sessionLimitsExceeded() &&
           ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan) &&
           (millis() - last_activity_ms) < kSshIdleTimeoutMs) {
        int n = ssh_channel_read_nonblocking(chan, buf, sizeof(buf), 0);
        if (n == SSH_ERROR) break;
        if (n == 0) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        last_activity_ms = millis();
        // Don't record the raw recv chunk — we record line-grain at ENTER
        // below so input events are one-per-line, not one-per-keystroke.
        for (int i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)buf[i];
            if (c == '\r' || c == '\n') {
                // Record the completed line + CRLF as a single input event.
                String evt = line + "\r\n";
                cast.in(evt.c_str(), evt.length());
                chan_write_norec(chan, "\r\n", 2);
                String out = shell.execute(line);
                line = "";
                if (out.length()) chan_write(chan, cast, out);
                if (shell.exitRequested()) break;
                chan_write(chan, cast, shell.prompt());
                continue;
            }
            if (c == 0x7f || c == 0x08) {
                if (line.length()) {
                    line.remove(line.length() - 1);
                    chan_write_norec(chan, "\b \b", 3);
                }
                continue;
            }
            if (c == 0x03) { // Ctrl-C — record the abandoned line + ^C\r\n
                             // as one forensic input event.
                String evt = line + "^C\r\n";
                cast.in(evt.c_str(), evt.length());
                chan_write_norec(chan, "^C\r\n", 4);
                line = "";
                chan_write(chan, cast, shell.prompt());
                continue;
            }
            if (c == 0x04) { // Ctrl-D on empty -> exit
                if (line.length() == 0) { shell.execute("exit"); break; }
                continue;
            }
            if (c < 0x20) continue;
            if (line.length() < 256) {
                line += (char)c;
                char e = (char)c;
                chan_write_norec(chan, &e, 1);
            }
        }
    }
    entry.commands = shell.commandsRun();
    classify_attack(entry, shell.commandSummary(), shell.firstCmdMs(), shell.lastCmdMs());
}

static void handle_session(ssh_session sess) {
    auto& cfg = g_config.get();
    g_display.showAttack(AttackKind::SSH);

    AttackEntry entry;
    entry.id = g_attack_log.nextId();
    entry.ts = time(nullptr);
    entry.protocol = "ssh";
    char ipbuf[64] = {0};
    int port_int = 0;
    {
        socket_t fd = ssh_get_fd(sess);
        if (fd >= 0) {
            struct sockaddr_in sa; socklen_t sl = sizeof(sa);
            if (getpeername(fd, (struct sockaddr*)&sa, &sl) == 0) {
                inet_ntoa_r(sa.sin_addr, ipbuf, sizeof(ipbuf));
                port_int = ntohs(sa.sin_port);
            }
        }
    }
    entry.ip = ipbuf[0] ? String(ipbuf) : String("0.0.0.0");
    entry.port = (uint16_t)port_int;

    SessionRecorder cast;
    String cast_path = make_session_path("ssh");
    bool cast_open = recorder_begin(cast, cast_path, SSH_COLS, SSH_ROWS,
                                    "SSH session from " + entry.ip,
                                    "/bin/bash",
                                    entry.id, "ssh",
                                    /* persona */ String("ssh"),
                                    /* hostname */ String(),
                                    /* user */ String(),
                                    /* authenticated */ false,
                                    entry.ip, entry.port);
    // Suppress recording until the shell phase starts. SSH auth happens
    // via libssh messages (not through the cast pipeline), so this is
    // mostly defensive — but it also means a session that gets accepted
    // but then sends junk channel-requests writes nothing to the cast.
    // run_fake_shell / the exec-mode branch flip paused→false.
    cast.setPaused(true);
    if (cast_open) {
        entry.cast_path = cast_path;
    } else {
        Serial.printf("[ssh] cast open failed for id=%u path=%s — recording disabled\n",
                      (unsigned)entry.id, cast_path.c_str());
    }
    uint32_t t0 = millis();

    if (ssh_handle_key_exchange(sess) != SSH_OK) {
        Serial.printf("[ssh] kex failed: %s\n", ssh_get_error(sess));
        cast.close();
        entry.duration_ms = millis() - t0;
        g_attack_log.append(entry);
        intel_enqueue(entry.id);
        return;
    }

    // Auth loop.
    bool authed = false;
    int attempts = 0;
    String last_user, last_pass;
    String collected_pubkeys;
    // Cap pubkey collection so an attacker spamming `ssh -i key1 -i key2 …`
    // can't blow up heap before the password fallback kicks in. Each
    // captured line is "<type> <SHA256:fp> <base64>"; a single 4096-bit
    // RSA key serializes to ~720 bytes, so 8 keys / 4 KB covers the
    // realistic max while keeping the worst-case heap footprint bounded.
    constexpr int    kMaxCollectedPubkeys     = 8;
    constexpr size_t kMaxCollectedPubkeyBytes = 4 * 1024;
    int  pubkey_count       = 0;
    bool pubkey_cap_logged  = false;
    // Idle timer: reset on every SSH message we receive from the peer.
    // An actively-typing attacker keeps last_activity_ms fresh and is
    // never closed for "session too long".
    uint32_t last_activity_ms = millis();
    auto idle_alive = [&]() {
        return (millis() - last_activity_ms) < kSshIdleTimeoutMs;
    };
    // Cap total password tries at login_attempts_before_accept + 3 so the
    // wall (default 3 + 3 = 6) matches real OpenSSH's MaxAuthTries default
    // of 6. The previous +5 (cap=8) was a fingerprintable tell vs a real
    // sshd; bots that count rejection responses see a difference.
    while (!authed && attempts < cfg.login_attempts_before_accept + 3 &&
           ssh_is_connected(sess) && idle_alive()) {
        ssh_message msg = ssh_message_get(sess);
        if (!msg) break;
        last_activity_ms = millis();
        int type = ssh_message_type(msg);
        int sub  = ssh_message_subtype(msg);
        if (type == SSH_REQUEST_AUTH) {
            const char* u = ssh_message_auth_user(msg);
            if (u) last_user = u;
            if (sub == SSH_AUTH_METHOD_PASSWORD) {
                #pragma GCC diagnostic push
                #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                const char* p = ssh_message_auth_password(msg);
                #pragma GCC diagnostic pop
                if (p) last_pass = p;
                attempts++;
                Serial.printf("[ssh] auth try #%d user=%s pass=%s\n",
                              attempts, last_user.c_str(), last_pass.c_str());
                if (attempts >= cfg.login_attempts_before_accept) {
                    ssh_message_auth_reply_success(msg, 0);
                    authed = true;
                } else {
                    ssh_message_auth_set_methods(msg,
                        SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
                    ssh_message_reply_default(msg);
                }
            } else if (sub == SSH_AUTH_METHOD_PUBLICKEY) {
                // Capture the offered key, then always reject so the attacker
                // falls back to password auth (where we let them in).
                #pragma GCC diagnostic push
                #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                ssh_key k = ssh_message_auth_pubkey(msg);
                #pragma GCC diagnostic pop
                if (k) {
                    const char* tname = ssh_key_type_to_char(ssh_key_type(k));
                    char* b64 = nullptr;
                    ssh_pki_export_pubkey_base64(k, &b64);
                    unsigned char* hash = nullptr;
                    size_t hlen = 0;
                    char* fp = nullptr;
                    if (ssh_get_publickey_hash(k, SSH_PUBLICKEY_HASH_SHA256, &hash, &hlen) == 0) {
                        fp = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
                    }
                    String line;
                    line.reserve(96 + (b64 ? strlen(b64) : 0));
                    line += (tname ? tname : "ssh-key");
                    line += ' ';
                    line += (fp ? fp : "");
                    line += ' ';
                    line += (b64 ? b64 : "");
                    // Cap-aware append: drop the line if either bound is
                    // crossed, but keep counting so the Serial log still
                    // shows the attacker is spamming pubkeys. Logged once
                    // per session so we don't flood HWCDC.
                    bool over_cap = (pubkey_count >= kMaxCollectedPubkeys) ||
                                    (collected_pubkeys.length() + 1 + line.length()
                                     > kMaxCollectedPubkeyBytes);
                    if (!over_cap) {
                        if (collected_pubkeys.length()) collected_pubkeys += '\n';
                        collected_pubkeys += line;
                        pubkey_count++;
                    } else if (!pubkey_cap_logged) {
                        pubkey_cap_logged = true;
                        Serial.printf("[ssh] pubkey cap hit (%d keys / %u bytes), "
                                      "dropping further offers from user=%s\n",
                                      kMaxCollectedPubkeys,
                                      (unsigned)kMaxCollectedPubkeyBytes,
                                      last_user.c_str());
                    }
                    Serial.printf("[ssh] pubkey offered user=%s %s %s\n",
                                  last_user.c_str(), (tname ? tname : "?"), (fp ? fp : "?"));
                    if (fp)   ssh_string_free_char(fp);
                    if (b64)  ssh_string_free_char(b64);
                    if (hash) ssh_clean_pubkey_hash(&hash);
                }
                ssh_message_auth_set_methods(msg,
                    SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
                ssh_message_reply_default(msg);
            } else if (sub == SSH_AUTH_METHOD_NONE) {
                ssh_message_auth_set_methods(msg,
                    SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
                ssh_message_reply_default(msg);
            } else {
                ssh_message_auth_set_methods(msg,
                    SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
                ssh_message_reply_default(msg);
            }
        } else {
            ssh_message_reply_default(msg);
        }
        ssh_message_free(msg);
    }

    entry.user = last_user;
    entry.pass = last_pass;
    entry.pubkeys = collected_pubkeys;
    entry.authenticated = authed;
    entry.auth_attempts = (uint16_t)attempts;

    ssh_channel chan = nullptr;
    bool abuse_seen = false;  // attacker tried tunnel/x11/agent/sftp — surfaces in Serial log
    if (authed) {
        // Wait for a session channel — bounded by the idle timer (resets
        // on each message received). Anything other than SSH_CHANNEL_SESSION
        // is denied. This explicitly blocks `direct-tcpip` (used by `ssh -L`
        // / dynamic SOCKS tunnels) and `x11`/`auth-agent` channels at the
        // channel-open layer; libssh's default reply sends
        // SSH_MSG_CHANNEL_OPEN_FAILURE.
        last_activity_ms = millis();
        while (!chan && idle_alive() && ssh_is_connected(sess)) {
            ssh_message msg = ssh_message_get(sess);
            if (!msg) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }
            last_activity_ms = millis();
            int type = ssh_message_type(msg);
            int sub  = ssh_message_subtype(msg);
            if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_SESSION) {
                chan = ssh_message_channel_request_open_reply_accept(msg);
            } else {
                if (type == SSH_REQUEST_CHANNEL_OPEN) {
                    abuse_seen = true;
                    const char* what =
                        (sub == SSH_CHANNEL_DIRECT_TCPIP)    ? "direct-tcpip (-L tunnel)" :
                        (sub == SSH_CHANNEL_FORWARDED_TCPIP) ? "forwarded-tcpip" :
                        (sub == SSH_CHANNEL_X11)             ? "x11" :
                        (sub == SSH_CHANNEL_AUTH_AGENT)      ? "auth-agent" :
                                                               "unknown";
                    Serial.printf("[ssh] denied channel-open type=%s ip=%s\n",
                                  what, entry.ip.c_str());
                } else if (type == SSH_REQUEST_GLOBAL) {
                    // tcpip-forward (-R reverse tunnel) lives here.
                    abuse_seen = true;
                    const char* what =
                        (sub == SSH_GLOBAL_REQUEST_TCPIP_FORWARD)        ? "tcpip-forward (-R tunnel)" :
                        (sub == SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD) ? "cancel-tcpip-forward" :
                                                                           "global";
                    Serial.printf("[ssh] denied global request=%s ip=%s\n",
                                  what, entry.ip.c_str());
                }
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }
        // Wait for pty/shell/exec.
        bool ready = false;
        bool exec_run = false;
        String exec_cmd;
        last_activity_ms = millis();
        while (chan && !ready && idle_alive() && ssh_is_connected(sess)) {
            ssh_message msg = ssh_message_get(sess);
            if (!msg) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }
            last_activity_ms = millis();
            int type = ssh_message_type(msg);
            int sub  = ssh_message_subtype(msg);
            if (type == SSH_REQUEST_CHANNEL) {
                if (sub == SSH_CHANNEL_REQUEST_PTY) {
                    ssh_message_channel_request_reply_success(msg);
                } else if (sub == SSH_CHANNEL_REQUEST_SHELL) {
                    ssh_message_channel_request_reply_success(msg);
                    ready = true;
                } else if (sub == SSH_CHANNEL_REQUEST_EXEC) {
                    const char* c = ssh_message_channel_request_command(msg);
                    if (c) {
                        // Cap defensively — fake_shell bounds command length to 4096
                        // and an unbounded exec string would just inflate heap.
                        size_t n = strlen(c);
                        if (n > 4096) n = 4096;
                        exec_cmd = String();
                        exec_cmd.reserve(n);
                        for (size_t i = 0; i < n; ++i) exec_cmd += c[i];
                    }
                    ssh_message_channel_request_reply_success(msg);
                    ready = true;
                    exec_run = true;
                } else if (sub == SSH_CHANNEL_REQUEST_ENV) {
                    // Accepted but ignored — lets `ssh -o SendEnv=...` succeed
                    // without giving the attacker any real influence.
                    ssh_message_channel_request_reply_success(msg);
                } else {
                    // Explicitly denies subsystem (sftp/netconf), x11-req,
                    // auth-agent-req@openssh.com, signal, window-change, etc.
                    abuse_seen = true;
                    const char* what =
                        (sub == SSH_CHANNEL_REQUEST_SUBSYSTEM) ? "subsystem (sftp?)" :
                        (sub == SSH_CHANNEL_REQUEST_X11)       ? "x11-req" :
                                                                 "unknown channel-req";
                    Serial.printf("[ssh] denied channel-req=%s ip=%s\n",
                                  what, entry.ip.c_str());
                    ssh_message_reply_default(msg);
                }
            } else {
                if (type == SSH_REQUEST_GLOBAL) {
                    abuse_seen = true;
                    Serial.printf("[ssh] denied late global-req sub=%d ip=%s\n",
                                  sub, entry.ip.c_str());
                }
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }

        if (chan && ready) {
            if (exec_run) {
                FakeShell shell;
                shell.begin(entry.user.length() ? entry.user : String(cfg.fake_user), cfg.fake_hostname);
                shell.setSessionInfo(entry.id, entry.ip, entry.port, "ssh",
                                     entry.cast_path + ".events.jsonl");
                // Exec-mode: a one-shot command is the entire shell phase
                // for this session. Start recording.
                cast.setPaused(false);
                cast.in(exec_cmd.c_str(), exec_cmd.length());
                String out = shell.execute(exec_cmd);
                if (out.length()) chan_write(chan, cast, out);
                entry.commands = shell.commandsRun();
                classify_attack(entry, exec_cmd, millis(), millis());
            } else {
                run_fake_shell(sess, chan, entry, cast);
            }
            ssh_channel_send_eof(chan);
            ssh_channel_close(chan);
            ssh_channel_free(chan);
        }
    }

    entry.duration_ms = millis() - t0;
    cast.close();

    if (ssh_is_connected(sess)) ssh_disconnect(sess);

    if (entry.profile.length() == 0) {
        // No shell ever ran (auth failed, no channel opened, etc.). Still classify
        // so the dashboard can show "creds-probe" or similar.
        classify_attack(entry, String(), 0, 0);
    }
    g_attack_log.append(entry);
    intel_enqueue(entry.id);
    // Quota enforcement moved to the AttackLog persister's periodic
    // loop — ESP32 stability review ST2.

    Serial.printf("[ssh] session done id=%u ip=%s user=%s pass=%s authed=%d cmds=%u%s\n",
                  (unsigned)entry.id, entry.ip.c_str(),
                  entry.user.c_str(), entry.pass.c_str(),
                  (int)entry.authenticated, entry.commands,
                  abuse_seen ? " ABUSE_DENIED" : "");
}

static void ssh_listener_task(void*) {
    // Wait for WiFi STA before initializing libssh.
    while (WiFi.status() != WL_CONNECTED) vTaskDelay(pdMS_TO_TICKS(500));

    // Kick off host-key generation as a low-priority background task so it
    // doesn't starve AsyncTCP's poll task while RSA primes are being crunched.
    if (!s_hostkey_ready && !s_hostkey_generating) {
        s_hostkey_generating = true;
        xTaskCreate(ssh_keygen_task, "ssh_kg", 16384, nullptr, 1, nullptr);
    }
    while (!s_hostkey_ready) vTaskDelay(pdMS_TO_TICKS(500));

    if (!g_config.get().ssh_enabled) {
        while (!g_config.get().ssh_enabled) vTaskDelay(pdMS_TO_TICKS(2000));
    }

    // libssh_begin/ssh_init were called from the keygen task; safe to reinvoke.
    libssh_begin();
    ssh_init();

    ssh_bind sshbind = ssh_bind_new();
    int port = HONEYMIRE_SSH_PORT;
    int log_verb = SSH_LOG_WARNING;
    int process_config = 0;   // do NOT try to read /etc/ssh/libssh_server_config
    auto& cfg = g_config.get();
    String banner = cfg.ssh_banner;
    if (banner.startsWith("SSH-2.0-")) banner = banner.substring(8);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &process_config);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, HOSTKEY_VFS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, banner.c_str());
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &log_verb);

    if (ssh_bind_listen(sshbind) < 0) {
        Serial.printf("[ssh] bind/listen failed: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        vTaskDelete(nullptr);
        return;
    }
    s_listener_running = true;
    Serial.printf("[ssh] listening on %s:%d\n",
                  WiFi.localIP().toString().c_str(), port);

    // Underlying listen socket. select()ing on it with a 1 s timeout
    // lets the loop notice WiFi loss / config toggles even when no
    // attacker is connecting — without that, ssh_bind_accept blocks
    // indefinitely and the listener can outlive the WiFi connection
    // it was bound to. See ESP32 stability review S2.
    const int listen_fd = ssh_bind_get_fd(sshbind);

    for (;;) {
        if (!g_config.get().ssh_enabled || WiFi.status() != WL_CONNECTED) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        struct timeval tv = {};
        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        int sel = select(listen_fd + 1, &rfds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;  // timeout or error: re-check gates

        ssh_session sess = ssh_new();
        if (!sess) { vTaskDelay(pdMS_TO_TICKS(500)); continue; }
        if (ssh_bind_accept(sshbind, sess) != SSH_OK) {
            ssh_free(sess);
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        // Heap gate: a libssh KEX needs ~32-60 KB of contiguous heap for
        // the asymmetric crypto (mbedtls). If the largest free block is
        // below ~55 KB, the KEX will malloc-fail mid-handshake and leave
        // the heap fragmented further. Reject early instead — the peer
        // sees a TCP RST rather than a half-broken SSH banner.
        //
        // On boards with PSRAM (S3 N16R8 / T-QT Pro) the gate is unnecessary:
        // libssh+mbedtls allocate from the unified heap which is plenty
        // large. We skip the check entirely there.
#if !HONEYMIRE_HAS_PSRAM
        {
            size_t largest = ESP.getMaxAllocHeap();
            if (largest < 55 * 1024) {
                ssh_disconnect(sess);
                ssh_free(sess);
                // No Serial print: under fragmentation we'd flood UART.
                vTaskDelay(pdMS_TO_TICKS(200));
                continue;
            }
        }
#endif
        // Cap blocking time inside libssh. Without these, a peer that
        // completes the TCP handshake and then never sends another byte
        // wedges the listener forever (and pins ~100 KB of libssh heap).
        {
            socket_t fd = ssh_get_fd(sess);
            if (fd >= 0) {
                struct timeval tv;
                tv.tv_sec  = kSshSocketTimeoutSec;
                tv.tv_usec = 0;
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                // Enable TCP keepalive on the accepted socket. The 15 s
                // application-level idle timer already covers the
                // common slow-loris case (peer completes TCP, then sends
                // nothing), but keepalive layers on a kernel-level dead-
                // peer detector for the case where the listener task
                // wedges briefly: 60 s idle → first probe, 15 s intervals,
                // give up after 4 misses → connection closed in ~2 min
                // even if the app loop never gets back to it. Default
                // lwIP keepalive (without tuning) is 2 hours, which is
                // useless for a honeypot.
                int on = 1;
                setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
                int idle = 60, intvl = 15, cnt = 4;
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle));
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
                setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
            }
        }
        // Gate at the door: drop repeat attackers BEFORE letting libssh
        // start KEX. Each KEX leaves ~50 KB of residual heap, so letting
        // the same bot bang on us every few seconds bleeds the device.
        {
            String peer_ip;
            socket_t fd = ssh_get_fd(sess);
            if (fd >= 0) {
                struct sockaddr_storage ss; socklen_t sl = sizeof(ss);
                if (getpeername(fd, (struct sockaddr*)&ss, &sl) == 0) {
                    if (ss.ss_family == AF_INET) {
                        char buf[16];
                        auto* sin = (struct sockaddr_in*)&ss;
                        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
                        peer_ip = buf;
                    }
                }
            }
            g_gate.incSsh();
            if (peer_ip.length() && !g_gate.admit(peer_ip)) {
                g_gate.incSshGated();
                // Silent gate — Serial flooding stalls the listener.
                ssh_disconnect(sess);
                ssh_free(sess);
                continue;
            }
            if (peer_ip.length()) g_gate.touch(peer_ip);
        }
        // Single-session policy on ESP32-C3 to keep RAM under control.
        handle_session(sess);
        ssh_free(sess);
    }
}

void ssh_begin() {
    // Larger stack — libssh KEX uses a lot.
    xTaskCreatePinnedToCore(ssh_listener_task, "ssh", 16384, nullptr, 1, nullptr, tskNO_AFFINITY);
}

} // namespace honeymire

#else // HONEYMIRE_ENABLE_SSH

namespace honeymire {
void ssh_begin() {}
bool ssh_hostkey_ready()    { return false; }
bool ssh_listener_running() { return false; }
}

#endif
