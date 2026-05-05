# HoneyOpus 🍯

A pocket-sized **Telnet + SSH honeypot** for ESP32 boards (C3 SuperMini with
the built-in 0.42" OLED, LilyGO T-QT Pro with a 128×128 colour IPS, or a
headless S3-N16R8 module). Records every captured session as an
[asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/), classifies the
attacker (Mirai bot, IoT loader, manual operator, …), geolocates them, and
optionally submits the IP to **AbuseIPDB**, **AlienVault OTX** and a
self-hosted **HoneyOpus Hub** in the
background. A web dashboard, captive-portal Wi-Fi setup, and serial CLI are
bundled in.

> Vibe-coded end-to-end with the help of AI — every line in this repo was
> generated, reviewed and shaped through an iterative pair-programming dance.
> File issues if anything looks off and I'll feed them back into the loop.

## ✨ Install from your browser

Plug an ESP32-C3 SuperMini, LilyGO T-QT Pro or ESP32-S3 N16R8 into a USB
port and head to
**[kast.github.io/HoneyOpus](https://kast.github.io/HoneyOpus/)**.
Click *Connect*, pick the serial port, and the latest firmware is flashed in
seconds — no toolchain, no `pio`, no drivers beyond the stock USB-CDC. ESP
Web Tools auto-detects the chip family and picks the matching image.

The flasher uses [ESP Web Tools](https://esphome.github.io/esp-web-tools/) and
works in Chrome, Edge and Opera on a desktop computer.

## Hardware

HoneyOpus targets three boards out of the box. Pick one and PlatformIO will
wire up the right display driver, partition table and concurrency caps.

| Build env (`-e`) | Chip | Flash / RAM / PSRAM | Display | Telnet cap | Notes |
|---|---|---|---|---|---|
| `esp32-c3-oled` *(default)* | ESP32-C3 | 4 MB / 400 KB / — | SSD1306 72×40 mono OLED (I²C GPIO 5/6) | 3 | 01Space SuperMini-class. Heap-tight; SSH gated by free-largest. |
| `lilygo-t-qt-pro` | ESP32-S3 | 4 MB / 512 KB / 2 MB QSPI | 128×128 colour IPS, ST7735-class controller (LovyanGFX) | 6 | LilyGO T-QT Pro. Boot button on GPIO 0. The panel is widely advertised as GC9107 but in practice responds to ST7735-family commands — `src/display.cpp` ships a custom init ported from a known-good native ESP-IDF driver. |
| `esp32-s3-n16r8` | ESP32-S3 | 16 MB / 512 KB / 8 MB OPI | headless | 8 | Generic N16R8 module. Best honeypot capacity, no UI. Uses `partitions_16mb.csv`. |

Common to all: boot button (`GPIO 9` on C3, `GPIO 0` on S3) acts as the
function button when the board has one.

## Building from source

```sh
pio run                          # default env (esp32-c3-oled)
pio run -e lilygo-t-qt-pro       # LilyGO T-QT Pro
pio run -e esp32-s3-n16r8        # generic ESP32-S3 N16R8

pio run -e <env> -t upload       # build + flash
pio device monitor               # serial console (115200 baud)
```

The first SSH connection after a fresh flash takes ~30 seconds while the
RSA-2048 host key is generated and persisted to LittleFS. Every subsequent
boot reuses the stored key.

## First boot

1. The OLED briefly shows the **HoneyOpus boot logo** then turns off.
2. With no Wi-Fi credentials saved, the board comes up as a SoftAP named
   **`HoneyOpus-XXXXXX`** (password `honeyopus`). The OLED shows the SSID and
   `192.168.4.1`.
3. Connect to the AP — your phone's captive-portal probe will pop the setup
   page automatically; if not, browse to `http://192.168.4.1/portal`.
4. Pick your network from the live scan, enter the password, hit **Connect**.
   HoneyOpus reboots and joins your LAN.

## Wi-Fi via the serial menu

Open the serial monitor at 115200 baud, press <kbd>m</kbd> (or <kbd>?</kbd>),
and you'll see:

```
HoneyOpus :: menu
  1) Set WiFi SSID
  2) Set WiFi password
  3) Set hostname
  4) Show config
  5) Save & reconnect WiFi
  6) Force AP setup mode
  7) Reset config to defaults
  8) List attacks
  9) List asciinema sessions
  s) Toggle SSH enabled
  t) Toggle Telnet enabled
  k) Set AbuseIPDB API key
  o) Set AlienVault OTX API key
  u) Set HoneyOpus Hub URL
  b) Set HoneyOpus Hub token
```

## OLED behaviour

The display follows a strict, low-power state machine driven by
`src/display.cpp`:

* **Boot logo** for ≈ 2 s on power-up.
* **Off** the rest of the time.
* When a Telnet or SSH session lands, the matching icon flashes for
  `attack_icon_seconds` (default 15) — never longer than `display_on_seconds`
  (default 30).
* Pressing the **function button** (GPIO 9) wakes the display and shows the
  current status; it goes back to sleep after `display_on_seconds`.

Both timers and the icons are configurable from the dashboard.

## Web dashboard

Once associated, browse to `http://<board-ip>/`.

* **Dashboard** — KPIs and a table of recent attacks: time, protocol, source
  IP, geolocation (flag/city/ISP, 🏠 for LAN), captured credentials,
  classified attack profile (Mirai, IoT loader, manual, scripted, recon, …),
  command count, and links to ▶️ play the asciinema recording in the embedded
  player or ⬇️ download the `.cast` file.
* **Config** — every setting lives behind clean accordions with proper toggle
  switches: Wi-Fi, fake banners/usernames, dashboard auth, geolocation
  endpoint, **AbuseIPDB** + **OTX** toggles and API keys, display timers,
  storage caps. Includes a *Danger zone* button to wipe history while
  preserving configuration.
* **Sessions** — flat list of every `.cast` on flash.
* **`/api/attacks`** — JSON feed of the attack log, suitable for plumbing.

Default dashboard auth is **`admin` / `honeyopus`** — change it in *Config*
after first boot. Authentication is **automatically bypassed for clients on
the local network** so you don't get prompted at home; remote clients always
need to authenticate.

### Disabling the web dashboard to free RAM

The HTTP server (AsyncWebServer + handlers + listening socket) costs roughly
30–50 KiB of internal heap. On the C3 / TQT-Pro that's significant — enough,
for example, to let the Hub reporter ship a longer events transcript inside
a single TLS request. You can turn the web dashboard off:

* **Config page** → *Dashboard auth* section → uncheck *Web dashboard enabled*.
* **Serial menu** → key `w`.

The change applies on the **next reboot**. As a safety net, the firmware
**refuses to disable the web dashboard unless at least one threat-intel
reporter (AbuseIPDB / OTX / Hub) is enabled and credentialled** — otherwise
the device would have zero remote visibility. The serial menu and the AP
setup portal always remain available regardless of this flag, so you can
recover from a serial console even after disabling the web UI.

## Threat-intel reporting

Both reporters run from a dedicated FreeRTOS task so the honeypot's I/O is
never blocked. Each captured attack triggers:

1. Geo-IP lookup (`ip-api.com` by default — no key required for low volumes;
   any URL returning `country/city/lat/lon/isp` works).
2. **AbuseIPDB** — submitted with categories `18` (brute-force), `22` (SSH)
   and `23` (IoT-targeted) and your custom comment.
3. **AlienVault OTX** — every captured IP is added as an indicator to a
   single, long-lived pulse tagged `honeypot/brute-force/<proto>`. The
   pulse id is pinned in *Config* (field *OTX pulse id*) so the same feed
   keeps growing across reboots. Leave it empty to fall back to
   create-by-name behaviour.
4. **HoneyOpus Hub** — the project's own ingest endpoint for users running
   their own dashboard. Each attack is POSTed once (idempotent on
   `(token, attack.id)`) to `<hub_url>/api/v1/ingest` as a single JSON
   document containing the full session metadata, geo, classification,
   pubkeys and a structured i/o transcript (`session.events[]`) — the
   hub reconstructs the asciicast on its side, so the firmware ships
   only the bytes that flowed in each direction (capped per board:
   32 KiB on C3, 64 KiB on T-QT Pro, 96 KiB on N16R8). Configure
   *Hub URL* and *Hub token* in *Config*. Unlike AbuseIPDB/OTX, the
   Hub **does** receive LAN attacks (so you can validate your setup).
   Token format is `hop_` + 32 base64url chars; see
   [`docs/INGEST_PROTOCOL.md`](https://github.com/KaSt/HoneyOpusHUB/blob/main/docs/INGEST_PROTOCOL.md)
   in the HoneyOpusHUB repo for the wire contract.

The first three are off by default. Enable them in *Config* and paste your
API keys. **Attacks coming from LAN/private IPs are never reported** to
AbuseIPDB or OTX (the Hub is exempt from this rule).

## Asciinema sessions

Every captured session is appended to `/sessions/<timestamp>-<proto>-<rand>.cast`
on LittleFS. The dashboard player streams the file directly; the CLI
equivalent on a workstation is:

```sh
curl -u admin:honeyopus -O http://<board-ip>/cast?id=42
asciinema play 42.cast
```

The ring-buffer is sized by `max_sessions` (default 50) — older files are
deleted on boot.

## Shell emulation

The fake shell impersonates an Ubuntu 18.04 box with a small in-memory VFS
and ~50 commands. It never executes anything on the host — every output is
synthesised — but enough is implemented to keep Mirai/Gafgyt-style loaders
running through their full infection chain so the recording is interesting:

* `wget`, `curl`, `tftp`, `ftpget` stage virtual binaries (with realistic
  `Saving to:` / progress output) into the VFS; `chmod +x` then `./file`
  triggers an *executed* event tagged with the source URL and a guessed
  arch (`arm`, `mips`, `x86`…).
* `/bin/busybox <APPLET>` answers `applet not found` for unknown applets
  (that's how real BusyBox replies — bots use it as a fingerprint).
* Mirai's post-auth probe sequence (`enable`, `shell`, `system`,
  `linuxshell`) returns silently, like a real sub-shell.
* `dd if=… of=… bs=… count=…` creates the output file and prints the
  proper `N+0 records in/out / NN bytes copied` trio.
* Plausible reads for `/etc/passwd`, `/etc/shadow` (root only),
  `/etc/os-release`, `/etc/machine-id`, `/proc/net/route`,
  `/proc/net/tcp`, `/proc/cpuinfo`, …
* Pipes, redirections (`>`, `>>`, `2>&1`), command separators
  (`;`, `&&`, `||`), single/double quoting and backslash escapes are all
  parsed. Per-command structured events are written next to the asciicast
  in a `.events.jsonl` file.

## Stability & abuse-resistance

* **Per-IP cooldown gate** — repeat connections from the same IP within
  the cooldown window are dropped at accept time, before libssh KEX or
  the Telnet shell are spawned. Gated counts are visible on the
  `[health]` serial line.
* **SSH heap gate** — when the largest free heap block drops below
  ~55 KB the SSH listener silently rejects new connections (libssh+mbedTLS
  KEX needs that much contiguous memory). Acceptance resumes automatically
  once the heap recovers.
* **Heap watchdog** — if free heap stays under 45 KB for 90 s the device
  reboots itself.
* **Health line** — every 30 s the serial log prints
  `up=… heap=… largest=… min=… mode=… ip=… ssh=… tn_act=… tn=N/M ssh=N/M web=…`
  showing uptime, heap stats, telnet/ssh accept and gated counters and
  dashboard request count.

## Layout

```
src/
  main.cpp                boot + main loop
  config.{h,cpp}          NVS-backed configuration
  display.{h,cpp}         display state machine: U8g2 mono OLED on the
                          C3, LovyanGFX colour IPS on the T-QT Pro, no-op
                          stub on the headless N16R8
  icons.h                 boot logo + Telnet/SSH icons (XBM)
  storage.{h,cpp}         LittleFS bring-up + ring trimming
  attack_log.{h,cpp}      JSONL attack log
  attack_classifier.{h,cpp}  bot vs. script vs. human heuristics
  asciinema.{h,cpp}       asciicast v2 writer
  fake_shell.{h,cpp}      Medium-interaction Ubuntu 18.04 shell emulator
                          (VFS, ~50 commands, downloader/stager detection,
                          shared by Telnet & SSH)
  telnet_honeypot.{h,cpp}
  ssh_honeypot.{h,cpp}    libssh-esp32 server
  geoip.{h,cpp}
  intel.{h,cpp}           AbuseIPDB + OTX + HoneyOpus Hub reporters (background task)
  wifi_manager.{h,cpp}    STA + SoftAP fallback + DNS hijack
  serial_menu.{h,cpp}
  web_dashboard.{h,cpp}   AsyncWebServer + captive portal + web installer page
web/
  index.html              source for the GitHub Pages web flasher
.github/workflows/
  build-and-deploy.yml    CI: build firmware, merge image, publish Pages
```

## Continuous delivery

Pushing to `main`/`master` (or hitting *Run workflow* in the Actions tab)
triggers `.github/workflows/build-and-deploy.yml`, which:

1. Builds firmware for all three boards with PlatformIO.
2. Merges `bootloader + partitions + boot_app0 + app` into one
   per-chip-family `firmware-*.bin` with `esptool.py merge_bin`.
3. Generates an ESP-Web-Tools `manifest.json` containing the commit SHA,
   build timestamp and one entry per chip family so the in-browser
   flasher picks the right image automatically.
4. Publishes everything (HTML + firmware images) to **GitHub Pages**.

To enable the site on a fresh fork, go to *Settings → Pages* and set
**Source = GitHub Actions**. The workflow takes care of the rest.

## Defending yourself

This is a deliberately exposed-to-the-internet honeypot. Run it on a network
segment you do not care about, behind NAT with **only** ports 22/23
forwarded. Disable SSH or Telnet from the dashboard if you don't want one.
The fake shell never touches the real filesystem or network — every
response is synthesised — but nothing in this project is hardened for
production use against a determined adversary.

## License


MIT. See `LICENSE`.
