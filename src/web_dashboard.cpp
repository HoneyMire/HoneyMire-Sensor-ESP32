#include "web_dashboard.h"
#include "config.h"
#include "wifi_manager.h"
#include "attack_log.h"
#include "storage.h"
#include "ssh_honeypot.h"
#include "intel.h"
#include "attack_classifier.h"
#include "attacker_gate.h"
#include "restart_reason.h"

#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <memory>
#include <vector>
#include <functional>

namespace honeyopus {

static AsyncWebServer s_server(HONEYOPUS_HTTP_PORT);

// ------------------- Page assets (embedded) -------------------

static const char PAGE_HEAD[] PROGMEM = R"HTML(
<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>HoneyOpus</title>
<style>
:root{--bg:#0e0f13;--fg:#e7e9ee;--mut:#9098a8;--card:#171a21;--acc:#f0b429;--bad:#e94560;--good:#41d693;--bord:#262a35}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 -apple-system,Segoe UI,Roboto,Helvetica,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:14px 18px;border-bottom:1px solid var(--bord);display:flex;justify-content:space-between;align-items:center}
header h1{margin:0;font-size:18px;color:var(--acc)}
nav a{color:var(--fg);text-decoration:none;margin-left:14px;padding:6px 10px;border-radius:6px}
nav a.active{background:#222633}
main{padding:18px;max-width:1400px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--bord);border-radius:10px;padding:14px;margin-bottom:14px;overflow-x:auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.kpi{background:#1c2029;border:1px solid var(--bord);border-radius:8px;padding:10px}
.kpi b{display:block;font-size:22px;color:var(--acc)}
.kpi span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid var(--bord);text-align:left;vertical-align:top}
td.when,td.nowrap,td.creds,td.rep,td.src{white-space:nowrap}
td.when{cursor:help}
.trunc{display:inline-block;overflow:hidden;text-overflow:ellipsis;vertical-align:bottom;white-space:nowrap;max-width:100%}
.trunc.user{max-width:12ch}
.trunc.pass{max-width:18ch}
.trunc.ip{max-width:40ch}
.trunc.cmd{max-width:32ch}
th.c,td.c{text-align:center}
th{color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.05em;font-size:11px}
tr:hover td{background:#1b1f29}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;color:#0e0f13}
.badge.tn{background:#7ad9ff}.badge.ssh{background:var(--acc)}
.badge.ok{background:var(--good)}.badge.no{background:var(--bad);color:#fff}
form .row{display:grid;grid-template-columns:200px 1fr;gap:10px;align-items:center;margin-bottom:8px}
input,select,textarea{width:100%;background:#0c0d12;color:var(--fg);border:1px solid var(--bord);border-radius:6px;padding:8px 10px;font:13px ui-monospace,Menlo,monospace}
button{background:var(--acc);border:none;color:#0e0f13;font-weight:600;padding:9px 14px;border-radius:6px;cursor:pointer}
button.alt{background:#2a3142;color:var(--fg)}
.meta{color:var(--mut);font-size:12px}
a{color:#7ad9ff}
.flag{font-size:16px;margin-right:6px}
.iconlink{font-size:18px;text-decoration:none;margin-right:8px;line-height:1}
.iconlink:hover{filter:brightness(1.4)}
.repicon{font-size:16px;margin-right:6px;cursor:help}
.repicon.off{filter:grayscale(1) opacity(0.35)}
button.danger{background:var(--bad);color:#fff}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.6);display:none;align-items:center;justify-content:center;z-index:50;backdrop-filter:blur(2px)}
.modal-bg.show{display:flex}
.modal{background:var(--card);border:1px solid var(--bord);border-radius:10px;padding:20px 22px;max-width:460px;width:90%;box-shadow:0 8px 30px rgba(0,0,0,.5)}
.modal h3{margin:0 0 10px;color:var(--bad)}
.modal p{margin:6px 0 16px;color:var(--fg)}
.modal .actions{display:flex;justify-content:flex-end;gap:8px}
.toast{position:fixed;top:14px;left:50%;transform:translateX(-50%);background:var(--good);color:#0e0f13;font-weight:600;padding:10px 18px;border-radius:8px;z-index:60;box-shadow:0 4px 16px rgba(0,0,0,.4)}
details.section{background:#1c2029;border:1px solid var(--bord);border-radius:8px;margin-bottom:10px;overflow:hidden}
details.section>summary{cursor:pointer;padding:12px 14px;font-weight:600;color:var(--acc);list-style:none;display:flex;align-items:center;justify-content:space-between;user-select:none}
details.section>summary::-webkit-details-marker{display:none}
details.section>summary::after{content:'▾';color:var(--mut);transition:transform .2s;font-size:12px;margin-left:8px}
details.section[open]>summary::after{transform:rotate(180deg)}
details.section>.body{padding:12px 14px;border-top:1px solid var(--bord)}
.switch{position:relative;display:inline-block;width:46px;height:24px;cursor:pointer;flex:none}
.switch input{opacity:0;width:0;height:0;position:absolute;margin:0}
.switch .slider{position:absolute;inset:0;background:#3a4055;border-radius:24px;transition:background .15s}
.switch .slider:before{content:'';position:absolute;height:18px;width:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:transform .15s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.switch input[type=checkbox]:checked + .slider{background:var(--good)}
.switch input[type=checkbox]:checked + .slider:before{transform:translateX(22px)}
code{font-family:ui-monospace,Menlo,monospace;background:#0c0d12;padding:2px 5px;border-radius:4px}
</style></head><body>
)HTML";

static const char PAGE_NAV[] PROGMEM = R"HTML(
<header>
  <h1><a href="/" style="color:inherit;text-decoration:none">&#127855; HoneyOpus</a></h1>
  <nav>
    <a href="/" id="navHome">Dashboard</a>
    <a href="/config" id="navCfg">Config</a>
    <a href="/sessions" id="navSes">Sessions</a>
  </nav>
</header><main>
)HTML";

static const char PAGE_FOOT[] PROGMEM = R"HTML(
</main></body></html>
)HTML";

// ----------- helpers ------------

static bool authed(AsyncWebServerRequest* req) {
    auto& c = g_config.get();
    if (!c.dashboard_auth_enabled) return true;
    if (c.dashboard_user.length() == 0) return true;
    // Skip basic-auth for clients on the local network — owners poking at
    // HoneyOpus from their LAN shouldn't have to enter credentials, and the
    // browser's auth dialog also breaks <a download> + asciinema fetch().
    // Disable dashboard_lan_bypass on untrusted LANs (campus/conference
    // Wi-Fi, hotel networks). See ESP32 stability review WEB2.
    if (c.dashboard_lan_bypass &&
        intel_ip_is_private(req->client()->remoteIP().toString())) return true;
    return req->authenticate(c.dashboard_user.c_str(), c.dashboard_pass.c_str());
}

static String flag_emoji(const String& cc) {
    if (cc.length() != 2) return "";
    String out;
    char a = toupper(cc[0]);
    char b = toupper(cc[1]);
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return "";
    // Regional indicator A=0x1F1E6
    auto append = [&](uint32_t cp) {
        out += (char)(0xF0);
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    };
    append(0x1F1E6 + (a - 'A'));
    append(0x1F1E6 + (b - 'A'));
    return out;
}

static String html_escape(const String& s) {
    String out; out.reserve(s.length());
    for (size_t i = 0; i < s.length(); ++i) {
        char c = s[i];
        switch (c) {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

static String fmt_ts(time_t t) {
    if (t < 1700000000) return "—";
    struct tm tm; localtime_r(&t, &tm);   // honours configTzTime() / cfg.tz
    char buf[48];
    // %z gives the numeric offset (e.g. +0200) so the rendered time is
    // unambiguous even if the user changes TZ later.
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %z", &tm);
    return String(buf);
}

// Compact relative form ("15s ago", "3m ago", "2h ago", "4d ago") for the
// dashboard's When column. The full ISO string still goes into the cell's
// title= attribute so hovering reveals the exact timestamp. Saves enough
// horizontal room that the Source column can fit a full IPv4 / IPv6
// address without ellipsis.
static String fmt_ts_relative(time_t t) {
    if (t < 1700000000) return "—";          // NTP not synced yet
    time_t now = time(nullptr);
    if (now < 1700000000) return "—";
    long delta = (long)now - (long)t;
    if (delta < 0) delta = 0;                // small clock skew → "0s"
    char buf[16];
    if (delta < 60)              snprintf(buf, sizeof(buf), "%lds ago",  delta);
    else if (delta < 3600)       snprintf(buf, sizeof(buf), "%ldm ago",  delta / 60);
    else if (delta < 86400)      snprintf(buf, sizeof(buf), "%ldh ago",  delta / 3600);
    else if (delta < 30 * 86400) snprintf(buf, sizeof(buf), "%ldd ago",  delta / 86400);
    else                         snprintf(buf, sizeof(buf), "30d+ ago");
    return String(buf);
}

// ---------- chunked response helper ----------
//
// AsyncResponseStream/String-based responses buffer the *entire* page in a
// growing cbuf in RAM until req->send() — for big pages (dashboard with 50
// rows, config with accordions+modal) that easily exceeds the free heap on
// ESP32-C3, throws std::bad_alloc inside the parser and __terminate aborts.
//
// beginChunkedResponse() instead asks our callback for ~1.4 KB at a time and
// writes each chunk straight to TCP, so peak heap is bounded.
//
// We model each page as a list of String segments and drain them across
// callback invocations.
struct SegPage {
    std::vector<String> segs;
    size_t seg_idx = 0;
    size_t pos = 0;     // bytes already copied from segs[seg_idx]
};

static AwsResponseFiller make_seg_filler(std::shared_ptr<SegPage> p) {
    return [p](uint8_t* buf, size_t maxLen, size_t /*index*/) -> size_t {
        size_t written = 0;
        while (written < maxLen && p->seg_idx < p->segs.size()) {
            const String& s = p->segs[p->seg_idx];
            size_t avail = s.length() - p->pos;
            if (avail == 0) { p->seg_idx++; p->pos = 0; continue; }
            size_t take = std::min(avail, maxLen - written);
            memcpy(buf + written, s.c_str() + p->pos, take);
            written += take;
            p->pos += take;
            if (p->pos == s.length()) {
                // Free this segment's string immediately to release heap as we go.
                p->segs[p->seg_idx] = String();
                p->seg_idx++;
                p->pos = 0;
            }
        }
        return written;
    };
}

// Heap-watermark below which we refuse to start a chunked response. The
// AsyncWebServer's beginChunkedResponse internally allocates a response
// object containing two std::function instances (~88 B each on this
// toolchain), and an underlying TCP buffer. Under heap pressure
// `operator new` throws std::bad_alloc, which propagates out of the
// async_tcp callback and __terminate aborts the device. Bail out early
// with a 503 in that case — clients can retry.
static const size_t kWebMinHeap        = 20 * 1024;
static const size_t kWebMinLargestBlk  = 6 * 1024;

static bool web_heap_ok_(AsyncWebServerRequest* req, const char* tag) {
    g_gate.incWeb();
    size_t free_heap = ESP.getFreeHeap();
    size_t largest   = ESP.getMaxAllocHeap();
    if (free_heap < kWebMinHeap || largest < kWebMinLargestBlk) {
        Serial.printf("[web] 503 %s — heap low (free=%u largest=%u min=%u/%u)\n",
                      tag, (unsigned)free_heap, (unsigned)largest,
                      (unsigned)kWebMinHeap, (unsigned)kWebMinLargestBlk);
        auto* r = req->beginResponse(503, "text/plain",
            "HoneyOpus is low on RAM, please retry in a few seconds.\n");
        if (r) {
            r->addHeader("Retry-After", "5");
            req->send(r);
        } else {
            req->send(503);
        }
        return false;
    }
    return true;
}

static void send_dashboard(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!web_heap_ok_(req, "/")) return;

    // KPI pass: count under the lock without copying entries. The previous
    // implementation copied the entire recent vector (50 × ~16 String fields)
    // which produced a flurry of small mallocs that catastrophically
    // fragmented the heap and aborted lock_init_generic on the next mutex
    // creation. forEachRecent iterates by const-reference under the lock.
    size_t v_size = 0, ssh_n = 0, tn_n = 0, authed_n = 0;
    g_attack_log.forEachRecent(50, [&](const AttackEntry& e) {
        ++v_size;
        if (e.protocol == "ssh") ssh_n++; else tn_n++;
        if (e.auth_attempts > 0) authed_n++;
        return true;
    });
    size_t total = g_attack_log.count();
    bool ssh_enabled = g_config.get().ssh_enabled;
    bool ssh_running = ssh_listener_running();
    bool wifi_ok     = wifi_mode() == NetMode::OnlineSTA;
    bool initializing = (ssh_enabled && !ssh_running) || !wifi_ok;
    size_t total_b = storage_total_bytes();
    size_t used_b  = storage_used_bytes();
    size_t free_kb = (total_b > used_b) ? (total_b - used_b) / 1024 : 0;

    auto pg = std::make_shared<SegPage>();
    pg->segs.reserve(16 + v_size);

    pg->segs.emplace_back(FPSTR(PAGE_HEAD));
    pg->segs.emplace_back(FPSTR(PAGE_NAV));

    // ---- init banner ----
    if (ssh_enabled && !ssh_running) {
        String s;
        s.reserve(420);
        s += F("<div class='card' style='border-left:4px solid #f0b429'><b>HoneyOpus is still initializing.</b> ");
        s += ssh_hostkey_ready()
            ? F("SSH host key ready, the listener is binding. ")
            : F("Generating the SSH host key on first boot &mdash; this can take up to ~30 s. ");
        s += F("Telnet captures and the dashboard work right now; SSH will accept connections in a few seconds. "
               "<span class='meta'>(this page auto-refreshes)</span></div>");
        pg->segs.push_back(std::move(s));
    } else if (!wifi_ok) {
        pg->segs.emplace_back(F("<div class='card' style='border-left:4px solid #e94560'>"
                                "<b>Wi-Fi not in STA mode.</b> Honeypot listeners only run while connected to a real network.</div>"));
    }

    // ---- KPIs ----
    {
        char tmp[600];
        snprintf(tmp, sizeof(tmp),
            "<div class='card'><div class='kpis'>"
            "<div class='kpi'><span>Attacks</span><b>%u</b></div>"
            "<div class='kpi'><span>Telnet</span><b>%u</b></div>"
            "<div class='kpi'><span>SSH</span><b>%u</b></div>"
            "<div class='kpi'><span>Logged-in</span><b>%u</b></div>"
            "<div class='kpi'><span>Free flash</span><b>%u KB</b></div>"
            "<div class='kpi'><span>Free heap</span><b>%u KB</b></div>"
            "</div></div>",
            (unsigned)total, (unsigned)tn_n, (unsigned)ssh_n,
            (unsigned)authed_n, (unsigned)free_kb,
            (unsigned)(ESP.getFreeHeap() / 1024));
        pg->segs.emplace_back(tmp);
    }

    // ---- recent attacks card ----
    pg->segs.emplace_back(F("<div class='card'><h3 style='margin:4px 0 12px'>Recent attacks</h3>"));
    if (v_size == 0) {
        pg->segs.emplace_back(F("<p class='meta'>No attacks captured yet. Telnet listener is on port 23, SSH on port 22. "
                                "Forward those ports from your edge router to this device's IP to start collecting.</p>"));
    } else {
        pg->segs.emplace_back(F("<table><thead><tr><th class='c'>#</th><th>When</th><th class='c'>Proto</th>"
                                "<th>Source</th><th>Geo</th><th class='c'>Profile</th>"
                                "<th>Creds</th><th class='c'>Auth</th><th class='c'>Cmds</th>"
                                "<th class='c'>Recording</th><th class='c'>Reported</th></tr></thead><tbody>"));
        g_attack_log.forEachRecent(50, [&](const AttackEntry& e) {
            String row;
            row.reserve(720);
            char hdr[200];
            // Compact relative time in the cell, full ISO timestamp in the
            // tooltip — saves space for the Source column. Both strings
            // are produced by fmt_ts*/strftime; neither contains HTML
            // metacharacters, so embedding into the static format is safe.
            String full_ts = fmt_ts(e.ts);
            String rel_ts  = fmt_ts_relative(e.ts);
            snprintf(hdr, sizeof(hdr),
                     "<tr><td class='c'>#%u</td><td class='when' title='%s'>",
                     (unsigned)e.id, full_ts.c_str());
            row += hdr;
            row += rel_ts;
            row += "</td><td class='c'><span class='badge ";
            row += (e.protocol == "ssh" ? "ssh" : "tn");
            row += "'>";
            row += e.protocol;
            row += "</span></td><td class='src'><code class='trunc ip' title='";
            row += html_escape(e.ip);
            row += "'>";
            row += html_escape(e.ip);
            row += "</code></td><td>";
            if (intel_ip_is_private(e.ip)) {
                row += F("<span class='flag' title='LAN / private network' aria-label='LAN'>&#x1F3E0;</span>");
            } else if (e.country_code.length()) {
                String cc = e.country_code; cc.toUpperCase();
                String tip = e.country.length() ? e.country : cc;
                if (e.city.length())   { tip += " · "; tip += e.city; }
                if (e.region.length()) { tip += " · "; tip += e.region; }
                if (e.isp.length())    { tip += " · "; tip += e.isp; }
                row += "<span class='flag' title='";
                row += html_escape(tip);
                row += "' aria-label='";
                row += html_escape(cc);
                row += "'>";
                row += flag_emoji(e.country_code);
                row += "</span>";
            } else if (e.country.length()) {
                row += "<span class='flag' title='";
                row += html_escape(e.country);
                row += "'>?</span>";
            }
            row += "</td>";
            auto pv = profile_visual(e.profile);
            row += "<td class='c'><span class='flag' title='";
            row += pv.alt;
            row += "' aria-label='";
            row += pv.alt;
            row += "'>";
            row += pv.icon;
            row += "</span></td><td class='creds'><code class='trunc user' title='";
            row += html_escape(e.user);
            row += "'>";
            row += html_escape(e.user);
            row += "</code> / <code class='trunc pass' title='";
            row += html_escape(e.pass);
            row += "'>";
            row += html_escape(e.pass);
            row += "</code></td>";
            if (e.auth_attempts > 0) {
                String tip = String((unsigned)e.auth_attempts) + " credential attempt" +
                             (e.auth_attempts == 1 ? "" : "s") + " captured" +
                             (e.authenticated ? "; shell granted" : "");
                row += F("<td class='c'><span class='badge ok' title='");
                row += tip;
                row += F("'>yes");
                if (e.auth_attempts > 1) {
                    row += F(" &times;");
                    row += String((unsigned)e.auth_attempts);
                }
                row += F("</span></td>");
            } else {
                row += F("<td class='c'><span class='badge no' title='no credential attempt'>no</span></td>");
            }
            char cmds[48];
            snprintf(cmds, sizeof(cmds), "<td class='c'>%u</td>", (unsigned)e.commands);
            row += cmds;
            row += "<td class='c'>";
            if (e.cast_path.length()) {
                char rec[320];
                snprintf(rec, sizeof(rec),
                    "<a class='iconlink' href='/play?id=%u' title='Play recording in browser' aria-label='Play recording'>&#x25B6;&#xFE0F;</a> "
                    "<a class='iconlink' href='/cast?id=%u' download title='Download asciinema .cast file' aria-label='Download .cast'>&#x2B07;&#xFE0F;</a>",
                    (unsigned)e.id, (unsigned)e.id);
                row += rec;
            } else row += "—";
            row += "</td><td class='c rep'>";
            row += e.reported_abuseipdb
                ? F("<span class='repicon' title='AbuseIPDB reported' aria-label='AbuseIPDB reported'>&#x1F6E1;&#xFE0F;</span>")
                : F("<span class='repicon off' title='AbuseIPDB not reported' aria-label='AbuseIPDB not reported'>&#x1F6E1;&#xFE0F;</span>");
            row += e.reported_otx
                ? F("<span class='repicon' title='AlienVault OTX reported' aria-label='OTX reported'>&#x1F989;</span>")
                : F("<span class='repicon off' title='AlienVault OTX not reported' aria-label='AlienVault OTX not reported'>&#x1F989;</span>");
            row += e.reported_dshield
                ? F("<span class='repicon' title='DShield reported' aria-label='DShield reported'>&#x1F30A;</span>")
                : F("<span class='repicon off' title='DShield not reported' aria-label='DShield not reported'>&#x1F30A;</span>");
            row += e.reported_hub
                ? F("<span class='repicon' title='HoneyOpus Hub reported' aria-label='Hub reported'>&#x1F36F;</span>")
                : F("<span class='repicon off' title='HoneyOpus Hub not reported' aria-label='Hub not reported'>&#x1F36F;</span>");
            row += "</td></tr>";
            pg->segs.push_back(std::move(row));
            return true;
        });
        pg->segs.emplace_back(F("</tbody></table>"));
    }
    pg->segs.emplace_back(F("</div>"));

    {
        char foot[256];
        snprintf(foot, sizeof(foot),
            "<p class='meta'>HoneyOpus on " HONEYOPUS_BOARD_NAME " · IP %s · uptime %us · Telnet %s · SSH %s</p>",
            wifi_ip_string().c_str(),
            (unsigned)(millis() / 1000),
            g_config.get().telnet_enabled ? "on" : "off",
            !ssh_enabled ? "off" : (ssh_running ? "on" : "starting"));
        pg->segs.emplace_back(foot);
    }
    pg->segs.emplace_back(FPSTR(PAGE_FOOT));

    AsyncWebServerResponse* resp = req->beginChunkedResponse("text/html; charset=utf-8",
                                                             make_seg_filler(pg));
    resp->addHeader("Cache-Control", "no-store");
    if (initializing) resp->addHeader("Refresh", "5");
    req->send(resp);
}

static void send_config_page(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!web_heap_ok_(req, "/config")) return;
    auto& c = g_config.get();
    auto pg = std::make_shared<SegPage>();
    pg->segs.reserve(80);
    auto add = [&](const String& s) { pg->segs.push_back(s); };
    auto addF = [&](const __FlashStringHelper* f) { pg->segs.emplace_back(f); };

    addF(FPSTR(PAGE_HEAD));
    addF(FPSTR(PAGE_NAV));
    addF(F("<div class='card'><h3>Configuration</h3>"));
    if (req->hasParam("web_blocked")) {
        addF(F("<div style='padding:10px 14px;border:1px solid #e94560;border-radius:8px;"
               "background:#3a1424;color:#ffd2db;margin-bottom:12px'>"
               "&#x26A0;&#xFE0F; Refused to disable the web dashboard: no threat-intel "
               "reporter (AbuseIPDB / OTX / Hub) is enabled and credentialled. "
               "Configure one first — otherwise the device would have no remote visibility.</div>"));
    } else if (req->hasParam("web_off")) {
        addF(F("<div style='padding:10px 14px;border:1px solid #f5a623;border-radius:8px;"
               "background:#3a2814;color:#ffe5b8;margin-bottom:12px'>"
               "&#x2705; Web dashboard will be <b>disabled at the next reboot</b>. "
               "Re-enable from the serial menu (key <code>w</code>) or by reflashing.</div>"));
    } else if (req->hasParam("saved")) {
        addF(F("<div style='padding:10px 14px;border:1px solid #2ecc71;border-radius:8px;"
               "background:#143a24;color:#c8f7d4;margin-bottom:12px'>"
               "&#x2705; Saved.</div>"));
    }
    addF(F("<form method='POST' action='/config'>"));

    auto field = [&](const char* label, const char* name, const String& val, const char* type = "text") {
        String s; s.reserve(160 + val.length());
        s += "<div class='row'><label>"; s += label; s += "</label><input type='";
        s += type; s += "' name='"; s += name; s += "' value='";
        s += html_escape(val); s += "'/></div>";
        add(s);
    };
    auto checkbox = [&](const char* label, const char* name, bool val) {
        String s; s.reserve(220);
        s += "<div class='row'><label>"; s += label; s += "</label>"
             "<label class='switch'><input type='hidden' name='"; s += name;
        s += "' value='0'/><input type='checkbox' name='"; s += name;
        s += "' value='1'"; if (val) s += " checked";
        s += "/><span class='slider'></span></label></div>";
        add(s);
    };
    auto sec_open  = [&](const char* title, bool open = true) {
        String s; s.reserve(80 + strlen(title));
        s += "<details class='section'"; if (open) s += " open";
        s += "><summary>"; s += title; s += "</summary><div class='body'>";
        add(s);
    };
    auto sec_close = [&]() { addF(F("</div></details>")); };

    sec_open("\xF0\x9F\x93\xB6 Wi-Fi");
    field("WiFi SSID", "wifi_ssid", c.wifi_ssid);
    field("WiFi password", "wifi_pass", c.wifi_pass, "password");
    field("Hostname", "hostname", c.hostname);
    sec_close();

    sec_open("\xF0\x9F\x95\xB7\xEF\xB8\x8F Honeypot");
    checkbox("Telnet enabled", "telnet_enabled", c.telnet_enabled);
    checkbox("SSH enabled", "ssh_enabled", c.ssh_enabled);
    field("Telnet banner", "telnet_banner", c.telnet_banner);
    field("SSH banner", "ssh_banner", c.ssh_banner);
    field("Fake hostname", "fake_hostname", c.fake_hostname);
    field("Fake user", "fake_user", c.fake_user);
    field("Login attempts before accept", "login_attempts_before_accept",
          String((unsigned)c.login_attempts_before_accept), "number");
    sec_close();

    sec_open("\xF0\x9F\x94\x90 Dashboard auth", false);
    checkbox("Require login", "dashboard_auth_enabled", c.dashboard_auth_enabled);
    field("User", "dashboard_user", c.dashboard_user);
    field("Password", "dashboard_pass", c.dashboard_pass, "password");
    addF(F("<p class='meta' style='grid-column:1/3;margin:-4px 0 0'>"
           "When enabled, browsers from outside the LAN must enter the user/password above. "
           "Local-network clients are always allowed in.</p>"));
    addF(F("<hr style='grid-column:1/3;border:0;border-top:1px solid #2a2f4a;margin:8px 0'>"));
    checkbox("Web dashboard enabled (uncheck to free RAM)", "web_enabled", c.web_enabled);
    addF(F("<p class='meta' style='grid-column:1/3;margin:-4px 0 0'>"
           "Disabling stops the HTTP dashboard at the next reboot, freeing "
           "~30-50 KiB of internal heap. Requires at least one threat-intel "
           "reporter (AbuseIPDB / OTX / Hub) to be enabled and credentialled, "
           "otherwise the device would have no remote visibility. The serial "
           "menu (key <code>w</code>) and the AP setup portal always remain "
           "available for recovery.</p>"));
    sec_close();

    sec_open("\xF0\x9F\x8C\x8D Geolocation", false);
    checkbox("GeoIP enabled", "geoip_enabled", c.geoip_enabled);
    field("GeoIP URL ({ip} placeholder)", "geoip_url", c.geoip_url);
    sec_close();

    sec_open("\xF0\x9F\x9B\xA1\xEF\xB8\x8F Threat intelligence reporting", false);
    checkbox("AbuseIPDB", "abuseipdb_enabled", c.abuseipdb_enabled);
    field("AbuseIPDB API key", "abuseipdb_key", c.abuseipdb_key, "password");
    field("AbuseIPDB comment", "abuseipdb_comment", c.abuseipdb_comment);
    checkbox("AlienVault OTX", "otx_enabled", c.otx_enabled);
    field("OTX API key", "otx_key", c.otx_key, "password");
    field("OTX pulse name", "otx_pulse_name", c.otx_pulse_name);
    field("OTX pulse id (fixed; empty = create-by-name)", "otx_pulse_id", c.otx_pulse_id);
    checkbox("DShield", "dshield_enabled", c.dshield_enabled);
    field("DShield email", "dshield_email", c.dshield_email, "email");
    field("DShield API key", "dshield_apikey", c.dshield_apikey, "password");
    checkbox("HoneyOpus Hub", "hub_enabled", c.hub_enabled);
    field("Hub URL (origin only, no path)", "hub_url", c.hub_url);
    field("Hub token (hop_…)", "hub_token", c.hub_token, "password");
    addF(F("<p class='meta' style='grid-column:1/3;margin:-4px 0 0'>"
           "Attacks coming from LAN/private IPs are never reported to AbuseIPDB, OTX, or DShield. "
           "The Hub <b>does</b> receive LAN attacks (idempotent on attack id). "
           "See <code>docs/INGEST_PROTOCOL.md</code> in the HoneyOpusHUB repo.</p>"));
    sec_close();

    sec_open("\xE2\x8F\xB0 Time &amp; NTP", false);
    field("POSIX TZ string", "tz", c.tz);
    field("NTP server #1", "ntp_server1", c.ntp_server1);
    field("NTP server #2", "ntp_server2", c.ntp_server2);
    field("NTP server #3", "ntp_server3", c.ntp_server3);
    addF(F("<p class='meta' style='grid-column:1/3;margin:-4px 0 0'>"
           "Examples: <code>CET-1CEST,M3.5.0,M10.5.0/3</code> (Europe), "
           "<code>EST5EDT,M3.2.0,M11.1.0</code> (US East), "
           "<code>UTC0</code>. Re-applied immediately on save.</p>"));
    sec_close();

    sec_open("\xF0\x9F\x96\xA5\xEF\xB8\x8F Display", false);
    field("Display on (s)", "display_on_seconds",
          String((unsigned)c.display_on_seconds), "number");
    field("Attack icon (s)", "attack_icon_seconds",
          String((unsigned)c.attack_icon_seconds), "number");
    sec_close();

    sec_open("\xF0\x9F\x92\xBE Storage", false);
    field("Max sessions kept", "max_sessions",
          String((unsigned)c.max_sessions), "number");
    field("Max attack log entries", "max_attack_entries",
          String((unsigned)c.max_attack_entries), "number");
    field("Max /sessions size (KB, 0=unlimited)", "max_session_dir_kb",
          String((unsigned)c.max_session_dir_kb), "number");
    sec_close();

    addF(F("<div class='row form-actions'><div></div>"
           "<div style='display:flex;gap:8px;justify-content:flex-end'>"
           "<button type='button' class='alt' onclick=\"location.href='/'\">Cancel</button>"
           "<button type='submit'>Save</button>"
           "</div></div></form>"
           "<h4 style='color:#e94560;margin-top:24px'>Danger zone</h4>"
           "<p class='meta' style='margin:-6px 0 10px'>"
           "Permanently deletes all recorded sessions and attack-log entries. "
           "Configuration (WiFi, API keys, …) is preserved.</p>"
           "<button type='button' class='danger' onclick=\"showClear()\">"
           "&#x1F5D1;&#xFE0F; Clear all attack history</button>"
           "</div>"));

    addF(F(R"HTML(
<div class="modal-bg" id="clearModal">
  <div class="modal" role="dialog" aria-labelledby="clrTitle" aria-modal="true">
    <h3 id="clrTitle">&#x26A0;&#xFE0F; Clear all attack history?</h3>
    <p>This will permanently remove every recorded asciinema session and every
       row in the attack log. Your WiFi, API keys and other settings are kept.</p>
    <p class="meta">This action cannot be undone.</p>
    <div class="actions">
      <button type="button" class="alt" onclick="hideClear()">Cancel</button>
      <button type="button" class="danger" id="clrConfirm" onclick="doClear()">
        Yes, delete everything
      </button>
    </div>
  </div>
</div>
<script>
function showClear(){document.getElementById('clearModal').classList.add('show');}
function hideClear(){document.getElementById('clearModal').classList.remove('show');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')hideClear();});
function doClear(){
  var b=document.getElementById('clrConfirm');b.disabled=true;b.textContent='Clearing…';
  fetch('/admin/clear_history',{method:'POST',credentials:'same-origin'})
    .then(r=>r.ok?r.text():Promise.reject(r.status))
    .then(t=>{
      hideClear();
      var t2=document.createElement('div');t2.className='toast';t2.textContent='History cleared ('+t+' files removed)';
      document.body.appendChild(t2);
      setTimeout(()=>{t2.remove();location.href='/';},1400);
    })
    .catch(err=>{b.disabled=false;b.textContent='Yes, delete everything';
      alert('Clear failed: '+err);});
}
</script>
)HTML"));
    addF(FPSTR(PAGE_FOOT));

    AsyncWebServerResponse* resp = req->beginChunkedResponse("text/html; charset=utf-8",
                                                             make_seg_filler(pg));
    resp->addHeader("Cache-Control", "no-store");
    req->send(resp);
}

static void handle_config_post(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    auto& c = g_config.get();
    auto get = [&](const char* n, const String& def = String("")) -> String {
        if (req->hasParam(n, true)) return req->getParam(n, true)->value();
        return def;
    };
    auto getBool = [&](const char* n, bool def) -> bool {
        bool found = false, on = false;
        for (size_t i = 0; i < req->params(); ++i) {
            const AsyncWebParameter* p = req->getParam(i);
            if (!p) continue;
            if (p->isPost() && p->name() == n) {
                found = true;
                if (p->value() == "1") on = true;
            }
        }
        return found ? on : def;
    };
    auto getU16 = [&](const char* n, uint16_t def) -> uint16_t {
        if (req->hasParam(n, true)) return (uint16_t)req->getParam(n, true)->value().toInt();
        return def;
    };
    auto getU8 = [&](const char* n, uint8_t def) -> uint8_t {
        if (req->hasParam(n, true)) return (uint8_t)req->getParam(n, true)->value().toInt();
        return def;
    };
    c.wifi_ssid = get("wifi_ssid", c.wifi_ssid);
    c.wifi_pass = get("wifi_pass", c.wifi_pass);
    c.hostname  = get("hostname",  c.hostname);
    c.telnet_enabled = getBool("telnet_enabled", c.telnet_enabled);
    c.ssh_enabled    = getBool("ssh_enabled", c.ssh_enabled);
    c.telnet_banner  = get("telnet_banner", c.telnet_banner);
    c.ssh_banner     = get("ssh_banner", c.ssh_banner);
    c.fake_hostname  = get("fake_hostname", c.fake_hostname);
    c.fake_user      = get("fake_user", c.fake_user);
    c.login_attempts_before_accept = getU8("login_attempts_before_accept", c.login_attempts_before_accept);
    c.dashboard_auth_enabled = getBool("dashboard_auth_enabled", c.dashboard_auth_enabled);
    c.dashboard_user = get("dashboard_user", c.dashboard_user);
    c.dashboard_pass = get("dashboard_pass", c.dashboard_pass);
    bool old_web = c.web_enabled;
    c.web_enabled    = getBool("web_enabled", c.web_enabled);
    c.geoip_enabled  = getBool("geoip_enabled", c.geoip_enabled);
    c.geoip_url      = get("geoip_url", c.geoip_url);
    c.abuseipdb_enabled = getBool("abuseipdb_enabled", c.abuseipdb_enabled);
    c.abuseipdb_key  = get("abuseipdb_key", c.abuseipdb_key);
    c.abuseipdb_comment = get("abuseipdb_comment", c.abuseipdb_comment);
    c.otx_enabled    = getBool("otx_enabled", c.otx_enabled);
    c.otx_key        = get("otx_key", c.otx_key);
    c.otx_pulse_name = get("otx_pulse_name", c.otx_pulse_name);
    c.otx_pulse_id   = get("otx_pulse_id", c.otx_pulse_id);
    c.dshield_enabled = getBool("dshield_enabled", c.dshield_enabled);
    c.dshield_email = get("dshield_email", c.dshield_email);
    c.dshield_apikey = get("dshield_apikey", c.dshield_apikey);
    c.hub_enabled    = getBool("hub_enabled", c.hub_enabled);
    c.hub_url        = get("hub_url", c.hub_url);
    c.hub_token      = get("hub_token", c.hub_token);
    while (c.hub_url.length() && c.hub_url[c.hub_url.length() - 1] == '/')
        c.hub_url.remove(c.hub_url.length() - 1);
    String old_tz   = c.tz;
    String old_ntp1 = c.ntp_server1;
    String old_ntp2 = c.ntp_server2;
    String old_ntp3 = c.ntp_server3;
    c.tz                  = get("tz", c.tz);
    c.ntp_server1         = get("ntp_server1", c.ntp_server1);
    c.ntp_server2         = get("ntp_server2", c.ntp_server2);
    c.ntp_server3         = get("ntp_server3", c.ntp_server3);
    c.display_on_seconds  = getU16("display_on_seconds",  c.display_on_seconds);
    c.attack_icon_seconds = getU16("attack_icon_seconds", c.attack_icon_seconds);
    c.max_sessions       = getU16("max_sessions", c.max_sessions);
    c.max_attack_entries = getU16("max_attack_entries", c.max_attack_entries);
    c.max_session_dir_kb = getU16("max_session_dir_kb", c.max_session_dir_kb);

    // Safety gate: refuse to disable the web dashboard when there's no
    // active intel reporter, otherwise the device would have zero remote
    // visibility (and the user might not realise until they need it).
    bool web_blocked = false;
    if (!c.web_enabled && old_web && !intel_any_active(c)) {
        c.web_enabled = true;
        web_blocked = true;
        Serial.println("[web] refused to disable: no active intel reporter "
                       "(AbuseIPDB / OTX / Hub) — keeping web ON");
    }
    g_config.save();

    // If TZ or NTP servers changed, re-arm SNTP and re-set the kernel TZ env.
    if (c.tz != old_tz || c.ntp_server1 != old_ntp1 ||
        c.ntp_server2 != old_ntp2 || c.ntp_server3 != old_ntp3) {
        configTzTime(c.tz.c_str(),
                     c.ntp_server1.c_str(),
                     c.ntp_server2.c_str(),
                     c.ntp_server3.c_str());
        Serial.printf("[time] reconfigured tz=%s ntp=%s,%s,%s\n",
                      c.tz.c_str(), c.ntp_server1.c_str(),
                      c.ntp_server2.c_str(), c.ntp_server3.c_str());
    }

    // If wifi creds changed and we're in AP mode, attempt to reconnect.
    if (wifi_mode() == NetMode::FallbackAP && c.wifi_ssid.length()) {
        // Don't tear down AP yet — schedule a reconnect after responding.
        req->onDisconnect([](){ wifi_try_sta(); });
    }

    auto* r = req->beginResponse(303);
    if (web_blocked) {
        r->addHeader("Location", "/config?saved=1&web_blocked=1");
    } else if (old_web && !c.web_enabled) {
        r->addHeader("Location", "/config?saved=1&web_off=1");
    } else {
        r->addHeader("Location", "/config?saved=1");
    }
    req->send(r);
}

static void handle_clear_history(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    g_attack_log.clearAll();
    size_t removed = storage_clear_history();
    Serial.printf("[admin] history cleared via web (%u files removed)\n", (unsigned)removed);
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", (unsigned)removed);
    req->send(200, "text/plain", buf);
}

static void send_play_page(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!req->hasParam("id")) { req->send(400, "text/plain", "missing id"); return; }
    if (!web_heap_ok_(req, "/play")) return;
    uint32_t id = req->getParam("id")->value().toInt();
    AttackEntry e;
    if (!g_attack_log.getById(id, e) || !e.cast_path.length()) {
        req->send(404, "text/plain", "no cast for id"); return;
    }

    AsyncResponseStream* s = req->beginResponseStream("text/html; charset=utf-8");
    s->print(FPSTR(PAGE_HEAD));
    s->print("<link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/asciinema-player@3.7.1/dist/bundle/asciinema-player.css'/>");
    s->print(FPSTR(PAGE_NAV));
    s->printf("<div class='card'><h3>Session #%u — %s from <code>%s</code></h3>",
              (unsigned)id, e.protocol.c_str(), html_escape(e.ip).c_str());
    s->print("<p class='meta'>");
    s->print(fmt_ts(e.ts)); s->print(" · ");
    s->print(html_escape(e.country));
    if (e.city.length())  { s->print(" · "); s->print(html_escape(e.city)); }
    s->print(" · creds <code>"); s->print(html_escape(e.user));
    s->print("</code>/<code>");  s->print(html_escape(e.pass));
    s->print("</code> · ");
    if (e.auth_attempts == 0) {
        s->print("no login attempt");
    } else if (e.authenticated) {
        s->printf("shell granted (%u attempt%s)", (unsigned)e.auth_attempts,
                  e.auth_attempts == 1 ? "" : "s");
    } else {
        s->printf("creds captured (%u attempt%s, no shell)",
                  (unsigned)e.auth_attempts, e.auth_attempts == 1 ? "" : "s");
    }
    s->printf(" · %.1fs</p>", e.duration_ms / 1000.0f);
    if (e.pubkeys.length()) {
        s->print("<details class='card' style='margin:8px 0;background:#1a1a2e'>"
                 "<summary>SSH public keys offered (");
        // count lines
        int nk = 1;
        for (size_t i=0;i<e.pubkeys.length();++i) if (e.pubkeys[i]=='\n') nk++;
        s->printf("%d)</summary><pre style='white-space:pre-wrap;word-break:break-all;font-size:11px'>", nk);
        s->print(html_escape(e.pubkeys));
        s->print("</pre></details>");
    }
    s->print("<div id='player' style='margin:8px 0;max-width:880px;font-size:12px'>"
             "<p class='meta'>Loading session…</p></div>");
    s->printf("<p><a class='iconlink' href='/cast?id=%u&dl=1' "
              "title='Download asciinema .cast file' aria-label='Download .cast'>"
              "&#x2B07;&#xFE0F;</a> <span class='meta'>asciinema .cast recording</span></p></div>",
              (unsigned)id);
    s->print("<script src='https://cdn.jsdelivr.net/npm/asciinema-player@3.7.1/dist/bundle/asciinema-player.min.js'></script>");
    // Pre-fetch the cast ourselves with credentials:same-origin — the player's
    // own fetch() doesn't always reattach the HTTP basic-auth header that the
    // browser used for the dashboard page, so its promise gets rejected with
    // 401 and you see "Rejection" in the console.
    s->print("<script>");
    // Visibly surface any promise rejection so the player isn't a silent dead
    // square in the page anymore.
    s->print("window.addEventListener('unhandledrejection',function(ev){"
             "var c=document.getElementById('player');"
             "if(c)c.innerHTML='<p style=\"color:#e94560\">Player error: '"
             "+(ev.reason&&ev.reason.message?ev.reason.message:String(ev.reason))+'</p>';"
             "});");
    // Transform each event line of the cast: rewrite kind 'i' → 'o' so
    // asciinema-player actually renders attacker-typed lines. The player
    // only paints 'o' (output) events on playback; in a real recording
    // the typed text shows up in 'o' because the terminal echoes it.
    // Our firmware deliberately does NOT record per-char echo (would
    // produce a useless i,o,i,o,… alternation), so without this rewrite
    // the local player would skip every typed line and the session
    // appears with the credentials/commands missing — exactly the same
    // failure mode the hub had before its own i→o flip. The forensic
    // i/o distinction is preserved on the hub side via the events[]
    // payload extracted from the same cast file.
    s->printf("var cont=document.getElementById('player');"
              "fetch('/cast?id=%u',{credentials:'same-origin',cache:'no-store'})"
              ".then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.text();})"
              ".then(function(data){"
              "data=data.split('\\n').map(function(L){"
              "return L&&L[0]==='['?L.replace(/^(\\[[0-9.]+,)\"i\"(,)/,'$1\"o\"$2'):L;"
              "}).join('\\n');"
              "cont.innerHTML='';"
              "try{AsciinemaPlayer.create({data:data},cont,"
              "{autoPlay:true,fit:'width',terminalFontSize:'11px',terminalLineHeight:1.2,idleTimeLimit:2});}"
              "catch(e){cont.innerHTML='<p style=\"color:#e94560\">Player init failed: '+e.message+'</p>';"
              "console.error('player init',e);}})"
              ".catch(function(err){cont.innerHTML="
              "'<p style=\"color:#e94560\">Failed to load session: '+err.message+'</p>';"
              "console.error('cast fetch failed',err);});",
              (unsigned)id);
    s->print("</script>");
    s->print(FPSTR(PAGE_FOOT));
    req->send(s);
}

static void send_cast(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!req->hasParam("id")) { req->send(400, "text/plain", "missing id"); return; }
    uint32_t id = req->getParam("id")->value().toInt();
    AttackEntry e;
    if (!g_attack_log.getById(id, e) || !e.cast_path.length() || !LittleFS.exists(e.cast_path)) {
        req->send(404, "text/plain", "not found"); return;
    }
    // Stream straight from LittleFS — the framework's
    // beginResponse(FS, path, ...) opens the file, pushes it through
    // AsyncTCP in lwIP-friendly chunks, and closes on completion. No
    // body String, no body.reserve(sz+1) → no OOM hazard regardless
    // of file size. Replaces the prior slurp that could call the
    // global new_handler on any cast over ~70 KiB on a heap-tight
    // C3. See ESP32 stability review E2.
    bool dl = req->hasParam("dl");
    AsyncWebServerResponse* r =
        req->beginResponse(LittleFS, e.cast_path, "application/x-asciicast", dl);
    r->addHeader("Cache-Control", "no-store");
    if (dl) {
        String fn = e.cast_path.substring(e.cast_path.lastIndexOf('/') + 1);
        r->addHeader("Content-Disposition", String("attachment; filename=\"") + fn + "\"");
    }
    req->send(r);
}

static void send_sessions_page(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!web_heap_ok_(req, "/sessions")) return;
    // Chunked rather than building one big body String — with 50+
    // sessions the old slurp could OOM the same way /cast did before
    // D-1. Each row is its own segment, freed as soon as it's flushed
    // to TCP. See ESP32 stability review E2.
    auto names = storage_list_dir("/sessions");
    auto pg = std::make_shared<SegPage>();
    pg->segs.emplace_back(FPSTR(PAGE_HEAD));
    pg->segs.emplace_back(FPSTR(PAGE_NAV));
    {
        String hdr;
        hdr.reserve(80);
        hdr += "<div class='card'><h3>Stored sessions (";
        hdr += names.size();
        hdr += ")</h3><ul>";
        pg->segs.emplace_back(std::move(hdr));
    }
    for (auto& n : names) {
        String row;
        row.reserve(160);
        String full = String("/sessions/") + n;
        File f = LittleFS.open(full, "r");
        size_t sz = f ? f.size() : 0;
        if (f) f.close();
        row += "<li><a href='/raw?path="; row += full; row += "'>"; row += n;
        row += "</a> <span class='meta'>"; row += sz; row += " B</span></li>";
        pg->segs.emplace_back(std::move(row));
    }
    pg->segs.emplace_back(F("</ul></div>"));
    pg->segs.emplace_back(FPSTR(PAGE_FOOT));
    AsyncWebServerResponse* r =
        req->beginChunkedResponse("text/html; charset=utf-8", make_seg_filler(pg));
    req->send(r);
}

static void send_raw(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!req->hasParam("path")) { req->send(400, "text/plain", "missing path"); return; }
    String p = req->getParam("path")->value();
    if (!p.startsWith("/sessions/") && !p.startsWith("/attacks/")) {
        req->send(403, "text/plain", "forbidden"); return;
    }
    if (!LittleFS.exists(p)) { req->send(404, "text/plain", "not found"); return; }
    // Stream from LittleFS in lwIP-friendly chunks. Same reasoning as
    // send_cast — the prior body.reserve(sz+1) for files up to 512 KiB
    // was the largest single OOM hazard on the dashboard. See ESP32
    // stability review E2.
    String fn = p.substring(p.lastIndexOf('/') + 1);
    AsyncWebServerResponse* r =
        req->beginResponse(LittleFS, p, "application/x-asciicast", /*download=*/true);
    r->addHeader("Content-Disposition", String("attachment; filename=\"") + fn + "\"");
    req->send(r);
}

static void api_attacks(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    if (!web_heap_ok_(req, "/api/attacks")) return;
    // Stream the JSON array entry-by-entry rather than building the
    // full document + serialised body in one go. The old path made
    // two heavyweight heap copies of the whole log (one inside the
    // JsonDocument pool, one in the serialised String) — at 100
    // entries × ~600 bytes that's ~120 KB peak, easily enough to
    // OOM a heap-tight C3. ESP32 stability review E2.
    auto pg = std::make_shared<SegPage>();
    pg->segs.emplace_back(F("["));
    bool first = true;
    g_attack_log.forEachRecent(100, [&](const AttackEntry& e) {
        JsonDocument d;
        JsonObject o = d.to<JsonObject>();
        e.toJson(o);
        String chunk;
        chunk.reserve(700);
        if (!first) chunk += ',';
        first = false;
        serializeJson(d, chunk);
        pg->segs.emplace_back(std::move(chunk));
        return true;
    });
    pg->segs.emplace_back(F("]"));
    AsyncWebServerResponse* r =
        req->beginChunkedResponse("application/json", make_seg_filler(pg));
    req->send(r);
}

static void api_scan(AsyncWebServerRequest* req) {
    int n = WiFi.scanComplete();
    if (n == WIFI_SCAN_FAILED || n == -2) {
        // Setup portal runs in AP-only mode by default. Active STA scans
        // from a pure-AP role have been observed to interrupt beacon
        // transmission and disconnect captive-portal clients on certain
        // arduino-esp32 versions. Switch to AP+STA for the scan; we
        // stay in AP+STA for the lifetime of the portal session, which
        // is fine — the STA half stays unconnected while no
        // credentials are saved. See ESP32 stability review W6.
        if (wifi_mode() == NetMode::FallbackAP &&
            WiFi.getMode() != WIFI_AP_STA) {
            WiFi.mode(WIFI_AP_STA);
        }
        WiFi.scanNetworks(true, false, false, 250);
        req->send(202, "application/json", "{\"scanning\":true}");
        return;
    }
    if (n == WIFI_SCAN_RUNNING) {
        req->send(202, "application/json", "{\"scanning\":true}");
        return;
    }
    JsonDocument d;
    JsonArray a = d["networks"].to<JsonArray>();
    for (int i = 0; i < n && i < 20; ++i) {
        JsonObject o = a.add<JsonObject>();
        o["ssid"] = WiFi.SSID(i);
        o["rssi"] = WiFi.RSSI(i);
        o["enc"]  = (int)WiFi.encryptionType(i);
    }
    String body; serializeJson(d, body);
    WiFi.scanDelete();
    req->send(200, "application/json", body);
}

// /health.json — operator-facing diagnostic snapshot. Designed to be
// curlable from monitoring scripts and human-friendly in a browser.
// Surfaces:
//   - heap (free / largest contiguous / min-since-boot)
//   - wifi (mode, ip, online_uptime_s, last disconnect reason)
//   - listeners (telnet/ssh/web)
//   - attacker_gate counters (telnet_total/gated, ssh_total/gated, web_total)
//   - attack-log size
//   - restart history (last reason, total, per-reason counts)
//
// Built as a small JSON String — bounded by the field set, never
// scales with attack count, so no chunked-response needed.
static void api_health(AsyncWebServerRequest* req) {
    if (!authed(req)) return req->requestAuthentication();
    g_gate.incWeb();
    String b;
    b.reserve(640);
    b += '{';
    b += "\"uptime_s\":"; b += (uint32_t)(millis() / 1000);
    b += ",\"heap\":{\"free\":"; b += (uint32_t)ESP.getFreeHeap();
    b += ",\"largest\":";       b += (uint32_t)ESP.getMaxAllocHeap();
    b += ",\"min_since_boot\":"; b += (uint32_t)ESP.getMinFreeHeap();
    b += "}";

    const char* mode = "?";
    switch (wifi_mode()) {
        case NetMode::Boot:          mode = "boot"; break;
        case NetMode::ConnectingSTA: mode = "sta-conn"; break;
        case NetMode::OnlineSTA:     mode = "sta"; break;
        case NetMode::FallbackAP:    mode = "ap"; break;
    }
    b += ",\"wifi\":{\"mode\":\""; b += mode; b += "\"";
    b += ",\"ip\":\""; b += wifi_ip_string(); b += "\"";
    b += ",\"online_uptime_s\":"; b += (uint32_t)(wifi_online_uptime_ms() / 1000);
    b += "}";

    b += ",\"listeners\":{\"telnet\":";
    b += g_config.get().telnet_enabled ? "true" : "false";
    b += ",\"ssh\":";
    b += (g_config.get().ssh_enabled && ssh_listener_running()) ? "true" : "false";
    b += ",\"web\":";
    b += g_config.get().web_enabled ? "true" : "false";
    b += "}";

    b += ",\"gate\":{";
    b += "\"telnet_total\":";  b += g_gate.telnetTotal();
    b += ",\"telnet_gated\":"; b += g_gate.telnetGated();
    b += ",\"telnet_active\":"; b += g_gate.telnetActive();
    b += ",\"ssh_total\":";    b += g_gate.sshTotal();
    b += ",\"ssh_gated\":";    b += g_gate.sshGated();
    b += ",\"web_total\":";    b += g_gate.webTotal();
    b += "}";

    b += ",\"attacks\":{\"persisted\":"; b += (uint32_t)g_attack_log.count();
    b += "}";

    b += ",\"restart\":{";
    restart::summary_json(b);
    b += "}";

    b += '}';
    AsyncWebServerResponse* r = req->beginResponse(200, "application/json", b);
    r->addHeader("Cache-Control", "no-store");
    req->send(r);
}

// -------- Captive portal: setup page --------
static const char PORTAL_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>HoneyOpus setup</title>
<style>
body{margin:0;background:#0e0f13;color:#e7e9ee;font:14px/1.4 -apple-system,Segoe UI,Roboto,Helvetica,sans-serif}
main{max-width:480px;margin:24px auto;padding:18px}
h1{color:#f0b429;font-size:20px;margin:0 0 14px}
.card{background:#171a21;border:1px solid #262a35;border-radius:10px;padding:14px;margin-bottom:14px}
label{display:block;margin:8px 0 4px;color:#9098a8;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
input,select{width:100%;background:#0c0d12;color:#e7e9ee;border:1px solid #262a35;border-radius:6px;padding:9px 10px;font:14px ui-monospace,Menlo,monospace}
button{margin-top:14px;width:100%;background:#f0b429;border:none;color:#0e0f13;font-weight:600;padding:11px;border-radius:6px;font-size:14px}
.row{display:flex;gap:10px;align-items:center}
.row > *{flex:1}
.meta{color:#9098a8;font-size:12px;margin-top:6px}
.aplist li{cursor:pointer;padding:6px 8px;border-bottom:1px solid #262a35}
.aplist li:hover{background:#1b1f29}
ul{list-style:none;margin:0;padding:0;border:1px solid #262a35;border-radius:6px}
.bar{height:6px;background:#262a35;border-radius:3px;overflow:hidden;margin-top:4px}
.bar>span{display:block;height:100%;background:#41d693}
</style></head><body><main>
<h1>&#127855; HoneyOpus setup</h1>
<div class="card">
  <p class="meta">Pick a network or type an SSID, then enter the password.</p>
  <ul id="aplist" class="aplist"><li class="meta">scanning…</li></ul>
</div>
<div class="card">
  <form method="POST" action="/portal/save">
    <label>SSID</label><input name="wifi_ssid" id="ssid" required>
    <label>Password</label><input name="wifi_pass" id="pass" type="password">
    <label>Hostname</label><input name="hostname" value="honeyopus">
    <button type="submit">Connect</button>
  </form>
</div>
<div class="card meta">After saving, HoneyOpus will reboot and join your network. Find it via the IP shown on the OLED, or http://honeyopus.local/.</div>
</main>
<script>
function refresh(){fetch('/api/scan').then(r=>r.json()).then(j=>{
  if(j.scanning){setTimeout(refresh,1500);return;}
  var u=document.getElementById('aplist');u.innerHTML='';
  (j.networks||[]).sort((a,b)=>b.rssi-a.rssi).forEach(n=>{
    var li=document.createElement('li');
    var bar=Math.max(0,Math.min(100,2*(n.rssi+100)));
    li.innerHTML='<b>'+n.ssid+'</b>'+(n.enc?' &#128274;':'')+'<div class=bar><span style=width:'+bar+'%></span></div>';
    li.onclick=()=>{document.getElementById('ssid').value=n.ssid;document.getElementById('pass').focus();};
    u.appendChild(li);
  });
});}refresh();
</script></body></html>
)HTML";

static void send_portal(AsyncWebServerRequest* req) {
    auto* r = req->beginResponse_P(200, "text/html; charset=utf-8", PORTAL_HTML);
    r->addHeader("Cache-Control", "no-store");
    req->send(r);
}

static void portal_save(AsyncWebServerRequest* req) {
    auto& c = g_config.get();
    if (req->hasParam("wifi_ssid", true)) c.wifi_ssid = req->getParam("wifi_ssid", true)->value();
    if (req->hasParam("wifi_pass", true)) c.wifi_pass = req->getParam("wifi_pass", true)->value();
    if (req->hasParam("hostname", true) && req->getParam("hostname", true)->value().length())
        c.hostname = req->getParam("hostname", true)->value();
    g_config.save();
    String body = "<!doctype html><meta charset='utf-8'><title>Saved</title>"
                  "<body style='font-family:sans-serif;background:#0e0f13;color:#e7e9ee;padding:24px'>"
                  "<h2 style='color:#f0b429'>Saved</h2>"
                  "<p>HoneyOpus is rebooting and joining <b>" + html_escape(c.wifi_ssid) +
                  "</b>. Reconnect to your normal network and look for it on the LAN.</p></body>";
    req->send(200, "text/html; charset=utf-8", body);
    req->onDisconnect([](){
        delay(500);
        restart::restart_with(restart::kReasonPortalSaved);
    });
}

// Captive portal redirect handler: any URL while in AP mode -> /portal.
class CaptiveHandler : public AsyncWebHandler {
public:
    bool canHandle(AsyncWebServerRequest* req) override {
        if (wifi_mode() != NetMode::FallbackAP) return false;
        String h = req->host();
        if (h == WiFi.softAPIP().toString()) return false;
        return true;
    }
    void handleRequest(AsyncWebServerRequest* req) override {
        auto* r = req->beginResponse(302, "text/plain", "captive");
        r->addHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/portal");
        req->send(r);
    }
};

void web_begin() {
    s_server.on("/",          HTTP_GET,  send_dashboard);
    s_server.on("/config",    HTTP_GET,  send_config_page);
    s_server.on("/config",    HTTP_POST, handle_config_post);
    s_server.on("/admin/clear_history", HTTP_POST, handle_clear_history);
    s_server.on("/sessions",  HTTP_GET,  send_sessions_page);
    s_server.on("/raw",       HTTP_GET,  send_raw);
    s_server.on("/cast",      HTTP_GET,  send_cast);
    s_server.on("/play",      HTTP_GET,  send_play_page);
    s_server.on("/api/attacks", HTTP_GET, api_attacks);
    s_server.on("/api/scan",  HTTP_GET,  api_scan);
    s_server.on("/health.json", HTTP_GET, api_health);

    s_server.on("/portal",    HTTP_GET,  send_portal);
    s_server.on("/portal/save", HTTP_POST, portal_save);

    // Captive-portal probe URLs: respond 204 in STA mode (real internet)
    // and 302 in AP mode (handled by CaptiveHandler below).
    auto probe = [](AsyncWebServerRequest* r) { r->send(204); };
    s_server.on("/generate_204", HTTP_GET, probe);
    s_server.on("/gen_204",      HTTP_GET, probe);
    s_server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest* r){
        r->send(200, "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
    });

    s_server.addHandler(new CaptiveHandler());

    s_server.onNotFound([](AsyncWebServerRequest* req) {
        if (wifi_mode() == NetMode::FallbackAP) {
            auto* r = req->beginResponse(302, "text/plain", "captive");
            r->addHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/portal");
            req->send(r);
            return;
        }
        req->send(404, "text/plain", "not found");
    });

    s_server.begin();
    Serial.printf("[web] http://%s/ (AP fallback http://%s/portal)\n",
                  WiFi.localIP().toString().c_str(),
                  WiFi.softAPIP().toString().c_str());
}

} // namespace honeyopus
