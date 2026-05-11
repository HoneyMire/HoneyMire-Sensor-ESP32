# HoneyMire ESP32 Stability Code Review

Review date: 2026-05-06

Scope: stability review of the current working tree, with emphasis on WiFi behavior, watchdog resets, exception/OOM handling, AsyncTCP/libssh lifecycle, LittleFS/NVS usage, and restart triggers. No source code was changed as part of this review.

The tree was already dirty before this file was added. Findings below reference the current local files and line numbers.

## Executive Summary

HoneyMire has accumulated several good defensive changes: heap health logging, a global `new_handler`, per-board concurrency caps, AsyncTCP WDT disable flags, an AsyncTCP patch script, a telnet finalizer task, a persister task for the attack log, and several heap gates before TLS/reporting work. Those are directionally correct.

The remaining reliability problem is that the firmware still performs blocking, heap-heavy, or lifecycle-sensitive work from places that must stay quick:

- Telnet callbacks still execute fake shell commands, write asciicast events, write event sidecars, and loop on TCP send space.
- The main loop still calls `AsyncClient::close(true)` from `telnet_reap()`. Your pasted `[telnet] reaper: session ... idle >15s, closing` log points directly at this path.
- Telnet session objects can be deleted while AsyncTCP still holds their callback argument.
- WiFi reconnect policy mixes `AutoReconnect`, manual `disconnect()`/`begin()`, and a TCP/53 "outbound probe" that can be false-negative on many normal networks.
- Web endpoints still allocate whole response bodies and whole cast files despite the newer chunked response helper.
- Several shared objects are mutated from multiple FreeRTOS tasks without a lock.

The repeated restarts are therefore probably not one single library bug. The repo code is currently using libraries in ways that are fragile on ESP32-C3 class RAM and under hostile network traffic. On ESP32-S3 with PSRAM the device will tolerate more abuse, but the same lifecycle bugs remain.

## Failure Mapping

### WiFi log: `Reason: 202 - AUTH_FAIL`

This message usually means the AP rejected authentication: wrong password, WPA mode/security mismatch, PMF/802.11w policy mismatch, router steering/deauth behavior, or a transient handshake failure. The current code does not record or branch on the disconnect reason at all. `wifi_manager.cpp:41-56` only sets a boolean for any STA disconnect.

Code-level risk: after a real auth failure, repeated `WiFi.begin()` calls are unlikely to help. The firmware should log the reason, fail fast to AP/setup mode for auth-specific reasons, and back off for transient reasons.

### WDT log: `task_wdt: - loopTask`

`loopTask` is explicitly added to the task watchdog at `src/main.cpp:96-106` and reset at the very top of `loop()` at `src/main.cpp:153-154`. A loopTask WDT means execution entered something in `loop()` and did not return to the top within the watchdog timeout.

The most suspicious path is `telnet_reap()`:

- `src/main.cpp:168-172` calls `telnet_reap()` every second from `loopTask`.
- `src/telnet_honeypot.cpp:512-514` calls `close_victims[i]->close(true)`.
- `src/telnet_honeypot.cpp:515-520` reboots if a stuck session survives.

Your pasted telnet reaper log immediately before instability matches this path. The comments already acknowledge historical hangs around telnet close, but the risky call still runs on the watchdog-subscribed main loop.

### Telnet log: `[telnet] reaper: session id=... idle >15s, closing`

This is not harmless housekeeping in the current design. It is the point where the main loop calls into AsyncTCP client teardown, against a session object that may also be touched by AsyncTCP callbacks and by the telnet finalizer worker.

## High Severity Findings

### H1. Telnet session can be double-deleted or used after free

Files:

- `src/telnet_honeypot.cpp:245-263`
- `src/telnet_honeypot.cpp:344-352`
- `src/telnet_honeypot.cpp:232-242`

`tn_finalize()` sets `s->finalized = true`, removes the session from the registry, queues the raw pointer to `tn_worker_task()`, and the worker later calls `delete s`.

`tn_on_disconnect()` then does this:

```cpp
if (s->finalized) {
    delete s;
    return;
}
```

That is unsafe. If the reaper already queued the session and AsyncTCP later fires `onDisconnect`, the same `TnSession*` can be deleted once by `tn_on_disconnect()` and again by `tn_worker_task()`. If the worker wins the race first, the callback dereferences freed memory just to read `s->finalized`.

Impact:

- Heap corruption.
- Random crashes that appear unrelated to telnet.
- WDTs or panics shortly after the reaper runs.

Recommendation:

- Make session ownership explicit. AsyncTCP callback args must remain valid until all callbacks are detached or the client is guaranteed gone.
- Do not delete the session from `tn_on_disconnect()` when `finalized` is already true.
- Consider reference counting, a single owner task, or a small state machine where callbacks only enqueue events and never free session memory directly.

### H2. Main loop calls `AsyncClient::close(true)` and can wedge `loopTask`

Files:

- `src/main.cpp:168-172`
- `src/telnet_honeypot.cpp:460-520`

`telnet_reap()` runs from `loopTask` and performs a force close on stuck clients. This is exactly the kind of library call that can block or wait on internal AsyncTCP/lwIP state. Because `loopTask` is subscribed to the WDT, any hang here becomes the watchdog panic you pasted.

The comment at `src/main.cpp:101-104` says a hang after `close(true)` was previously observed. The reaper still invokes `close(true)` from the main loop at `src/telnet_honeypot.cpp:512-514`.

Impact:

- WDT reset with `loopTask`.
- Reboots tied to idle telnet sessions.
- Device may look like WiFi died when the loop is actually stuck in teardown.

Recommendation:

- Move client close requests off the main loop and into the AsyncTCP context or a dedicated network-control task with bounded behavior.
- Prefer scheduling a close flag/event and letting the actual close happen in the client's own callback path.
- If a hard recovery is required, make the reaper choose a controlled reboot directly after marking a session unrecoverable, instead of first calling a potentially blocking close from `loopTask`.

### H3. Telnet callbacks still perform synchronous LittleFS work

Files:

- `src/telnet_honeypot.cpp:265-342`
- `src/telnet_honeypot.cpp:110-127`
- `src/asciinema.cpp:70-88`
- `src/fake_shell.cpp:710-735`
- `src/fake_shell.cpp:787-813`

The code correctly moved finalization work to a worker task, but the active telnet path still does flash I/O inside AsyncTCP callbacks:

- `tn_on_data()` calls `s->cast.in(...)`.
- `tn_send()` calls `s->cast.out(...)`.
- `Asciinema::writeEvent_()` writes to LittleFS and flushes periodically.
- `FakeShell::logEvent_()` opens, appends, and closes an events JSONL sidecar per notable command.
- `FakeShell::execute()` and command logging run inline from `tn_on_data()`.

LittleFS can stall during garbage collection, wear-leveling, or metadata updates. Running that from AsyncTCP can starve the networking task and cause secondary WiFi/TCP failures.

Impact:

- AsyncTCP stalls during active telnet sessions.
- Dropped TCP sessions, stuck callbacks, and reaper activation.
- More heap fragmentation due to frequent `String`, JSON, and file object churn.

Recommendation:

- Treat telnet callbacks as interrupt-like: parse bytes, append small immutable events to a queue, and return.
- Move shell execution, cast writing, and event sidecar writing to a per-session worker or a single session engine task.
- If real-time echo is required, keep only small writes in the callback and defer recording/logging.

### H4. `tn_send()` can block an AsyncTCP callback for up to 4 seconds per send

File: `src/telnet_honeypot.cpp:110-127`

`tn_send()` loops until all data is accepted or a 4000 ms deadline expires. It calls `vTaskDelay(2)` while waiting for client buffer space. This is polite to the scheduler, but it still keeps the AsyncTCP callback occupied for a long time.

This is especially risky when a shell command returns a large MOTD/output or the peer stops reading. A single slow client can hold the shared AsyncTCP task while other clients, web dashboard traffic, and TCP maintenance wait.

Impact:

- Head-of-line blocking across AsyncTCP users.
- More idle/stuck sessions.
- Cascading connection failures under slowloris-style clients.

Recommendation:

- Use AsyncTCP `onAck`/buffer callbacks or a queued outbound ring per session.
- Bound per-callback send work to a small byte/time budget.
- Drop clients whose output queue stays full.

### H5. Fake shell `sleep` and payload execution delay run in the telnet callback path

Files:

- `src/fake_shell.cpp:2282-2296`
- `src/fake_shell.cpp:2499-2500`
- `src/telnet_honeypot.cpp:200-208`

The fake shell caps sleep to 3000 ms and payload execution delay to 1500 ms. That cap is good, but in telnet these delays happen inside `tn_on_data()` through `s->shell.execute(line)`.

Impact:

- Any attacker typing `sleep 999` blocks the AsyncTCP callback for up to 3 seconds.
- Multiple slow commands can accumulate and make networking look unstable.

Recommendation:

- Execute shell commands outside the AsyncTCP callback.
- If that is too large a refactor, make telnet fake delays virtual: log that sleep was requested, but do not call `delay()` in telnet mode.

### H6. `AttackerGate` is not thread-safe

Files:

- `src/attacker_gate.h:28-61`
- `src/attacker_gate.cpp:7-33`
- Callers include telnet AsyncTCP callbacks, the SSH task, web callbacks, and `loopTask`.

`AttackerGate` stores mutable `String` slots and counters without a mutex or critical section. It is updated from multiple tasks:

- Telnet callbacks call `incTelnet()`, `admit()`, `touch()`, and `setTelnetActive()`.
- SSH task calls `incSsh()`, `admit()`, and `touch()`.
- Web callbacks call `incWeb()`.
- Main loop reads counters in the health log.

Concurrent mutation of `String` and unsynchronized counters can corrupt heap or produce invalid reads.

Impact:

- Rare, hard-to-reproduce heap corruption.
- Incorrect gating/counter state.
- Crashes that appear unrelated to the gate.

Recommendation:

- Protect all `AttackerGate` state with a mutex or critical section.
- Avoid `String` mutation under interrupt-disabled critical sections; a FreeRTOS mutex is more appropriate here.

### H7. Attack IDs are persisted to NVS from hot network paths

Files:

- `src/attack_log.cpp:187-199`
- `src/telnet_honeypot.cpp:414`
- `src/ssh_honeypot.cpp:211`

`AttackLog::nextId()` writes to Preferences/NVS on every new session. For telnet, this is called directly from `tn_on_client()`, an AsyncTCP callback. NVS writes are flash operations and can block, especially under wear-leveling or flash GC.

The intent is good: never reuse IDs after a leaked session. The execution location is risky.

Impact:

- AsyncTCP stalls during connection floods.
- Flash wear and latency spikes.
- More chances for WDT-adjacent network stalls.

Recommendation:

- Allocate IDs from RAM in the callback and queue NVS high-water persistence to the existing persister task.
- Persist the high-water mark periodically or after a small batch, not synchronously per connection.

## WiFi Findings

### W1. Disconnect reason is thrown away

File: `src/wifi_manager.cpp:41-56`

The callback receives `WiFiEventInfo_t info`, but it never records `info.wifi_sta_disconnected.reason`. As a result, AUTH_FAIL, AP not found, beacon timeout, handshake timeout, and router deauth all take the same path.

Impact:

- Operator cannot distinguish bad credentials from RF/router instability.
- Firmware cannot fail fast for permanent auth errors.
- Reconnect strategy is blind.

Recommendation:

- Store the last disconnect reason and print it once from `wifi_loop()`.
- Treat auth failures as configuration failures: stop retry storms and start AP/setup mode.
- Treat transient loss with exponential backoff.

### W2. Manual reconnect fights `WiFi.setAutoReconnect(true)`

Files:

- `src/wifi_manager.cpp:111-114`
- `src/wifi_manager.cpp:127-136`
- `src/wifi_manager.cpp:153-164`
- `src/wifi_manager.cpp:181-187`

The code enables Arduino auto reconnect and also performs manual `WiFi.disconnect(false, true)` plus `WiFi.begin()` from `wifi_loop()`. Those state machines can overlap.

Impact:

- Repeated connect/disconnect churn.
- More `AUTH_FAIL`/deauth noise if the AP is slow or rejects repeated handshakes.
- Harder diagnosis because logs do not distinguish auto reconnect from forced reconnect.

Recommendation:

- Pick one owner for reconnect policy.
- For a honeypot, a manual finite state machine is preferable: reason-aware backoff, bounded attempts, AP fallback, and no concurrent auto reconnect.

### W3. `WiFi.disconnect(false, true)` is probably too aggressive

Files:

- `src/wifi_manager.cpp:134`
- `src/wifi_manager.cpp:161`
- `src/wifi_manager.cpp:184`

The second argument to Arduino-ESP32 `disconnect()` is the "erase AP config" flag. With `WiFi.persistent(false)` this may not write NVS, but it still asks the driver to erase/forget the current AP config. Doing this repeatedly on every recovery path is heavier than necessary.

Impact:

- More WiFi driver churn during recovery.
- Possible interaction with auto reconnect.
- Harder AP roaming/reassociation behavior.

Recommendation:

- Use the least destructive disconnect that reliably resets STA state.
- Reserve erase-style disconnects for config changes or explicit credential resets.

### W4. The outbound probe can false-negative healthy networks

Files:

- `src/wifi_manager.cpp:58-69`
- `src/wifi_manager.cpp:171-188`

The probe connects to the default gateway on TCP port 53 and assumes "every consumer router answers." Many routers do not accept TCP/53 on the gateway IP. Some networks use a separate DNS server, block TCP DNS, or firewall LAN-to-gateway service ports.

After three false negatives, the firmware kicks STA even though WiFi may be fine.

Impact:

- Periodic self-inflicted reconnects every few minutes.
- Misleading "WiFi is flaky" behavior.
- Potential AUTH_FAIL bursts after forced reconnects.

Recommendation:

- Make the probe configurable.
- Prefer a DNS resolution check against the configured DNS server, a UDP DNS query, or simply remove the outbound probe unless a hub/reporter needs internet.
- If kept, do not force a disconnect solely on TCP/53 failure. Mark upstream degraded and retry with backoff.

### W5. Fallback AP IP is configured after `softAP()`

File: `src/wifi_manager.cpp:75-82`

`WiFi.softAPConfig(ap_ip, ap_ip, ap_nm)` is called after `WiFi.softAP(...)`. The normal Arduino pattern is to configure AP IP before starting the AP.

Impact:

- Captive portal IP may not be deterministic on all framework versions.
- DNS captive behavior can become inconsistent.

Recommendation:

- Configure the AP IP before `softAP()`.

### W6. AP setup WiFi scanning can disrupt AP service

Files:

- `src/web_dashboard.cpp:975-996`
- `src/wifi_manager.cpp:71-89`

The captive portal starts SoftAP only, then `/api/scan` calls `WiFi.scanNetworks(true, ...)`. Active scans while serving a SoftAP can interrupt AP beacons or require AP+STA mode depending on framework behavior.

Impact:

- Portal clients can disconnect while scanning.
- Setup mode can look flaky.

Recommendation:

- Use AP+STA mode for setup scanning, or scan only before starting AP, or make scan optional/manual with clear timeout handling.

## Watchdog and Restart Policy Findings

### WD1. The WDT timeout was enlarged, but blocking work remains

Files:

- `src/main.cpp:96-106`
- `src/main.cpp:153-219`

The 60 second WDT masks shorter stalls but does not fix them. `loop()` calls serial menu, WiFi loop, display, telnet reaper, health logging, heap reboot logic, and `delay(5)`. Most are quick, but `telnet_reap()` and some WiFi calls can enter driver/library code.

Impact:

- A library wedge becomes a reset instead of a recoverable event.
- The stack trace points at WDT but the root cause is usually a blocked call inside loop.

Recommendation:

- Keep `loopTask` boring: no force-closing clients, no long network probes, no blocking teardown.
- Emit a breadcrumb before and after each risky section during diagnosis so the last printed marker identifies the stuck call.

### WD2. Restart is used as normal flow control

Files:

- `src/main.cpp:198-214`
- `src/wifi_manager.cpp:198-208`
- `src/telnet_honeypot.cpp:515-520`
- `src/web_dashboard.cpp:1069-1071`

Some restarts are acceptable on small ESP32 boards, but here reboot is a common recovery path for low heap, WiFi outage, telnet stuck sessions, and portal credential save.

Impact:

- Real bugs become normalized as "self-heal."
- Attack traffic can deliberately induce reboots.
- Logs are lost unless persisted before restart.

Recommendation:

- Keep restart as last resort.
- Track restart reason in RTC memory or NVS before reboot.
- Add counters for WiFi-recovery reboot, heap-recovery reboot, telnet-reaper reboot, and OOM new-handler reboot.

## Exception and OOM Handling

### E1. Global `new_handler` restarts instead of recovering

File: `src/main.cpp:41-57`

The handler is safer than an uncaught `std::bad_alloc` abort, and using `ets_printf()` is correct. But it still means any unexpected allocation failure is a reboot.

Impact:

- Heap pressure from web/API/reporting appears as random restart.
- No high-level component attribution unless the caller logs before allocation.

Recommendation:

- Keep the handler, but treat it as crash reporting.
- Reduce allocations in hot paths so the handler is rare.
- Add component-level heap gates to every endpoint/task that can allocate large buffers.

### E2. Web heap gates are incomplete

Files:

- Good gate: `src/web_dashboard.cpp:224-253`
- Ungated or insufficiently gated endpoints: `src/web_dashboard.cpp:872-972`, `src/web_dashboard.cpp:909-928`, `src/web_dashboard.cpp:930-960`, `src/web_dashboard.cpp:962-972`, `src/web_dashboard.cpp:975-996`

The dashboard and config page use a heap gate and chunked response model. Other endpoints still build whole responses:

- `/cast` reads up to 512 KiB into a `String`.
- `/raw` reads up to 512 KiB into a `String`.
- `/sessions` builds a full HTML page in one `String`.
- `/api/attacks` copies up to 100 `AttackEntry` objects and serializes a full JSON body.
- `/api/scan` allocates a dynamic JSON response.

On ESP32-C3, a 512 KiB body is beyond realistic heap. `body.reserve(sz + 1)` can trigger the global restart handler.

Impact:

- Dashboard usage can crash/restart the device.
- Pulling a cast or raw file under attack load is especially dangerous.

Recommendation:

- Stream `/cast` and `/raw` from LittleFS in chunks.
- Apply `web_heap_ok_()` or route-specific gates to all handlers.
- Avoid copying the attack log for `/api/attacks`; iterate under lock or cap lower on C3.

### E3. Hub reporting still builds multiple large in-memory copies

Files:

- `src/intel.cpp:486-562`
- `src/intel.cpp:680-725`
- `src/intel.cpp:737-771`

The dynamic event cap is thoughtful, but the hub reporter can still hold:

- `events_json`
- the ArduinoJson document
- the serialized HTTP `body`
- TLS buffers
- HTTP response string

The code tries to budget this, but the model is still fragile under fragmented heap.

Impact:

- OOM/restarts when reporting after rich sessions.
- Reporter activity can destabilize the honeypot during attacks.

Recommendation:

- Stream or chunk hub event upload where possible.
- On C3, default to metadata-only or very small event payloads unless web and SSH are disabled.
- Make hub reporting optional per board profile.

### E4. `geoip_lookup()` has no heap gate

File: `src/geoip.cpp:100-163`

GeoIP runs from the intel task and uses HTTPClient plus dynamic JSON. Unlike the other intel reporters, it has no `heap_ok_for_tls_()` style gate.

Impact:

- Heap pressure during repeated lookups.
- TLS GeoIP URLs are especially risky.

Recommendation:

- Apply the same heap gate used for other HTTP/TLS reporters.
- Skip GeoIP during low heap and retry later.

## SSH/libssh Findings

### S1. SSH is too heavy to leave enabled by default on ESP32-C3

Files:

- `platformio.ini:75-78`
- `platformio.ini:32-45`
- `src/main.cpp:198-205`
- `src/ssh_honeypot.cpp:550-570`

The code itself documents libssh residual heap losses and gates KEX on C3. That is a strong signal that SSH on C3 is operationally marginal.

Impact:

- Each SSH session can permanently reduce available heap until reboot.
- Web, hub reporting, and TLS reporters compete with libssh.
- Low-heap restarts become expected under SSH scans.

Recommendation:

- Default SSH off for ESP32-C3, or make the C3 profile telnet-only unless the user explicitly enables SSH.
- Keep SSH for S3+PSRAM targets.

### S2. `ssh_bind_accept()` can block listener control flow

File: `src/ssh_honeypot.cpp:538-549`

The loop checks `ssh_enabled` and `WiFi.status()` before creating a session, then calls `ssh_bind_accept()`. If accept blocks, the task cannot notice WiFi loss or config toggles until accept returns.

Impact:

- SSH listener may not recover cleanly across WiFi disconnect/reconnect.
- Config changes can appear ignored.

Recommendation:

- Put the listening socket in nonblocking mode or use a bounded accept timeout.
- On WiFi disconnect, close/recreate the bind socket.

### S3. SSH task handles sessions serially

Files:

- `src/ssh_honeypot.cpp:538-614`
- `src/ssh_honeypot.cpp:611-613`

The single-session policy is reasonable for RAM, but one slow client monopolizes SSH until idle timeout. That is acceptable on C3 if documented, but it means SSH availability under scan traffic will be poor.

Recommendation:

- Keep the one-session cap, but reject or timeout pre-auth clients aggressively.
- Surface "SSH busy" in health logs if possible.

## Web/Dashboard Findings

### WEB1. `/play` uses `AsyncResponseStream` after the code documents why full streams are risky

Files:

- `src/web_dashboard.cpp:184-193`
- `src/web_dashboard.cpp:778-870`

The comment explains that full buffered responses caused OOM. `send_play_page()` still uses `beginResponseStream()` and prints the whole page into it. It is smaller than the main dashboard, but it follows the old risky pattern.

Recommendation:

- Convert `/play` to the same segmented chunked response helper.

### WEB2. Admin auth bypass for private IPs is a security tradeoff

File: `src/web_dashboard.cpp:109-118`

This is not a stability bug, but it matters operationally. Any LAN client bypasses dashboard auth. If the device is put on an untrusted LAN, or a router exposes port 80 unexpectedly, config and history operations are available.

Recommendation:

- Make LAN bypass configurable.
- Keep auth required by default if the device is deployed outside a controlled home/lab network.

## Storage and Logging Findings

### ST1. LittleFS writes are scattered across several tasks

Files:

- `src/asciinema.cpp`
- `src/fake_shell.cpp:710-735`
- `src/attack_log.cpp`
- `src/storage.cpp`
- `src/web_dashboard.cpp:768-776`
- `src/ssh_honeypot.cpp`

The attack log has a persister task, but cast writes, event writes, quota enforcement, raw/cast reads, and admin clears can still happen concurrently.

Impact:

- Flash GC latency appears in unrelated tasks.
- More lock contention and heap fragmentation.
- Harder to reason about LittleFS safety.

Recommendation:

- Centralize all LittleFS writes through one storage worker.
- Reads can remain direct if streamed and bounded, but writes should be serialized.

### ST2. Session quota enforcement can be expensive at finalization

Files:

- `src/telnet_honeypot.cpp:221-224`
- `src/ssh_honeypot.cpp:483-486`
- `src/storage.cpp:89-130`

Every finalized session can enumerate `/sessions`, stat/open files, sort names, and delete old files. It is off the telnet AsyncTCP path now, which is good. For SSH it runs in the SSH task. Under many sessions this still creates latency and heap churn.

Recommendation:

- Run quota enforcement periodically in the storage worker, or after N finalized sessions, not after every session.

## Build and Dependency Findings

### B1. Project relies on patching installed AsyncTCP source

Files:

- `platformio.ini:49`
- `scripts/patch_asynctcp.py`

The patch script addresses real AsyncTCP issues, but patching `.pio/libdeps` at build time is fragile:

- It depends on exact source text.
- A library update can silently leave parts unpatched.
- The comments in `platformio.ini` and the patch script indicate several severe upstream/library problems.

Recommendation:

- Pin the exact AsyncTCP dependency version.
- Make the patch script fail the build if expected patch targets are not found.
- Prefer a maintained fork with the patches committed if this project depends on them for stability.

### B2. Framework and libraries are old enough to treat as part of the risk

File: `platformio.ini:11-56`

The project uses `espressif32@^6.7.0`, AsyncTCP-esphome, ESPAsyncWebServer-esphome, and LibSSH-ESP32. The code comments already document issues in these dependencies.

Recommendation:

- For stability testing, pin all versions exactly, not with `^`.
- Maintain a known-good matrix by board.
- Do soak tests before moving any dependency.

## What Is Already Good

- `src/main.cpp:52-57`: `new_handler` uses `ets_printf()` instead of `Serial`, avoiding recursive UART/stdio locks.
- `src/main.cpp:96-106`: WDT setup makes loop hangs visible instead of silent.
- `platformio.ini:44-45`: AsyncTCP event WDT disabled to avoid false WDT trips during known slow paths.
- `scripts/patch_asynctcp.py`: AsyncTCP malloc null guards and receive-window clamp address real crash classes.
- `src/attack_log.cpp:172-183`: attack log persistence moved to a worker task.
- `src/telnet_honeypot.cpp:232-263`: finalization work is intended to be moved off AsyncTCP callbacks.
- `src/intel.cpp:28-38`: TLS heap gate recognizes fragmentation, not just total heap.
- `src/web_dashboard.cpp:184-253`: segmented page responses and heap gates are the right pattern for ESP32-C3.
- `src/ssh_honeypot.cpp:550-570`: early SSH heap gate avoids some KEX failures.
- `src/wifi_manager.cpp:198-208`: prolonged total WiFi outage has a last-resort reboot path.

## Recommended Stabilization Order

1. Fix telnet ownership/lifecycle first. Remove the double-delete/use-after-free risk and stop calling `close(true)` from `loopTask`.
2. Move telnet shell execution and all telnet cast/event file writes out of AsyncTCP callbacks.
3. Make `AttackerGate` thread-safe.
4. Remove synchronous NVS writes from `AttackLog::nextId()` in network callbacks.
5. Rework WiFi reconnect into one explicit state machine: reason-aware, no `AutoReconnect`, bounded backoff, AP fallback for auth/config failures.
6. Replace the TCP/53 gateway probe with a configurable, non-disruptive health check or remove it.
7. Stream `/cast` and `/raw`; convert `/sessions`, `/play`, and `/api/attacks` to bounded/chunked patterns.
8. Default ESP32-C3 to telnet-only or clearly mark SSH as experimental on C3.
9. Add persisted restart reason counters.
10. Pin all dependency versions and make the AsyncTCP patch script fail loudly if it cannot apply every expected patch.

## Targeted Diagnostics To Add Before More Refactors

These are low-cost diagnostics that would make the next failure much easier to classify:

- Last WiFi disconnect reason, channel, RSSI, BSSID, and uptime.
- Last loop section marker: before/after serial menu, WiFi loop, display loop, telnet reaper, health log.
- Restart reason stored before each deliberate `ESP.restart()`.
- Telnet session state counters: active, queued-finalize, finalized-waiting-delete, reaper-close-requested.
- Largest free internal heap alongside total free heap for every health line.
- AsyncTCP callback duration histogram or max duration counter.

## Operational Guidance

For the current codebase, the most stable deployment profile is likely:

- ESP32-S3 with PSRAM for SSH plus web plus reporting.
- ESP32-C3 as telnet-only, with web enabled only when needed and hub/reporting payloads kept small.
- Avoid exposing the device to high-rate public scans until telnet lifecycle and callback blocking are fixed.
- If `AUTH_FAIL` repeats, first validate AP password/security/PMF settings. The code should not be expected to recover from truly invalid credentials.

## Bottom Line

The repository is not just suffering from flaky ESP32 WiFi. There are concrete code-level instability risks that match the symptoms: unsafe telnet object lifetime, forced AsyncTCP close from the watchdog-monitored main loop, synchronous flash writes from network callbacks, incomplete OOM protection in web endpoints, and a WiFi recovery probe that can kick healthy networks.

Fixing telnet lifecycle and removing blocking work from AsyncTCP callbacks should be treated as the first milestone. WiFi tuning is still needed, especially reason-aware reconnect handling, but the telnet and heap paths are more likely to explain the frequent crashes and hangs.
