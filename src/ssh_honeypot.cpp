#include "ssh_honeypot.h"
#include "config.h"
#include "fake_shell.h"
#include "asciinema.h"
#include "attack_log.h"
#include "display.h"
#include "intel.h"
#include "attack_classifier.h"
#include "storage.h"

#if HONEYOPUS_ENABLE_SSH

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

namespace honeyopus {

// Per-session inactivity ceiling. libssh's blocking ssh_message_get / recv
// has no built-in timeout, so a slow-loris attacker (TCP connect, finish
// KEX, then sit silent) would pin the SSH listener forever — and on
// ESP32-C3 each live libssh session occupies ~100 KB of heap. We've seen
// largest-block collapse from ~104 KB to ~9 KB the moment one such peer
// arrives, fragmenting the heap badly enough that AsyncWebServer can no
// longer accept new connections.
//
// SO_RCVTIMEO/SO_SNDTIMEO on the session FD makes recv/send return
// EAGAIN, which libssh propagates as a session error so handle_session
// exits cleanly and frees the buffers.
static const int kSshSocketTimeoutSec = 60;

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

static void chan_write(ssh_channel chan, Asciinema& cast, const char* s, size_t n) {
    if (!chan || !s || n == 0) return;
    ssh_channel_write(chan, s, n);
    cast.out(s, n);
}
static void chan_write(ssh_channel chan, Asciinema& cast, const String& s) {
    chan_write(chan, cast, s.c_str(), s.length());
}

static void run_fake_shell(ssh_session sess, ssh_channel chan, AttackEntry& entry, Asciinema& cast) {
    auto& cfg = g_config.get();
    FakeShell shell;
    shell.begin(entry.user.length() ? entry.user : String(cfg.fake_user), cfg.fake_hostname);
    shell.setSessionInfo(entry.id, entry.ip, entry.port, "ssh",
                         entry.cast_path + ".events.jsonl");
    chan_write(chan, cast, shell.motd());
    chan_write(chan, cast, shell.prompt());

    String line;
    char buf[128];
    uint32_t idle_deadline = millis() + 120000;
    while (!shell.exitRequested() && !shell.sessionLimitsExceeded() &&
           ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan)) {
        int n = ssh_channel_read_nonblocking(chan, buf, sizeof(buf), 0);
        if (n == SSH_ERROR) break;
        if (n == 0) {
            if (millis() > idle_deadline) break;
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        cast.in(buf, n);
        idle_deadline = millis() + 120000;
        for (int i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)buf[i];
            if (c == '\r' || c == '\n') {
                chan_write(chan, cast, "\r\n", 2);
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
                    chan_write(chan, cast, "\b \b", 3);
                }
                continue;
            }
            if (c == 0x03) { // Ctrl-C
                chan_write(chan, cast, "^C\r\n", 4);
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
                chan_write(chan, cast, &e, 1);
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

    Asciinema cast;
    String cast_path = make_session_path("ssh");
    cast.begin(cast_path, SSH_COLS, SSH_ROWS,
               "SSH session from " + entry.ip,
               "/bin/bash");
    entry.cast_path = cast_path;
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
    while (!authed && attempts < cfg.login_attempts_before_accept + 5 && ssh_is_connected(sess)) {
        ssh_message msg = ssh_message_get(sess);
        if (!msg) break;
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
                    if (collected_pubkeys.length()) collected_pubkeys += '\n';
                    collected_pubkeys += line;
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

    ssh_channel chan = nullptr;
    if (authed) {
        // Wait for a session channel.
        uint32_t deadline = millis() + 8000;
        while (!chan && millis() < deadline && ssh_is_connected(sess)) {
            ssh_message msg = ssh_message_get(sess);
            if (!msg) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }
            if (ssh_message_type(msg) == SSH_REQUEST_CHANNEL_OPEN &&
                ssh_message_subtype(msg) == SSH_CHANNEL_SESSION) {
                chan = ssh_message_channel_request_open_reply_accept(msg);
            } else {
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }
        // Wait for pty/shell/exec.
        bool ready = false;
        bool exec_run = false;
        String exec_cmd;
        deadline = millis() + 8000;
        while (chan && !ready && millis() < deadline && ssh_is_connected(sess)) {
            ssh_message msg = ssh_message_get(sess);
            if (!msg) { vTaskDelay(pdMS_TO_TICKS(10)); continue; }
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
                    if (c) exec_cmd = c;
                    ssh_message_channel_request_reply_success(msg);
                    ready = true;
                    exec_run = true;
                } else if (sub == SSH_CHANNEL_REQUEST_ENV) {
                    ssh_message_channel_request_reply_success(msg);
                } else {
                    ssh_message_reply_default(msg);
                }
            } else {
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
                cast.in(exec_cmd.c_str(), exec_cmd.length());
                String out = shell.execute(exec_cmd);
                if (out.length()) chan_write(chan, cast, out);
                entry.commands = 1;
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
    {
        auto& c = g_config.get();
        storage_enforce_session_quota(c.max_sessions, (size_t)c.max_session_dir_kb * 1024);
    }

    Serial.printf("[ssh] session done id=%u ip=%s user=%s pass=%s authed=%d cmds=%u\n",
                  (unsigned)entry.id, entry.ip.c_str(),
                  entry.user.c_str(), entry.pass.c_str(),
                  (int)entry.authenticated, entry.commands);
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
    int port = HONEYOPUS_SSH_PORT;
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

    for (;;) {
        if (!g_config.get().ssh_enabled || WiFi.status() != WL_CONNECTED) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        ssh_session sess = ssh_new();
        if (!sess) { vTaskDelay(pdMS_TO_TICKS(500)); continue; }
        if (ssh_bind_accept(sshbind, sess) != SSH_OK) {
            ssh_free(sess);
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
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
            }
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

} // namespace honeyopus

#else // HONEYOPUS_ENABLE_SSH

namespace honeyopus {
void ssh_begin() {}
bool ssh_hostkey_ready()    { return false; }
bool ssh_listener_running() { return false; }
}

#endif
