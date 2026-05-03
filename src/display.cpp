// HoneyOpus display HAL.
//
// One of three driver backends is selected at compile time via
// HONEYOPUS_DISPLAY_DRIVER:
//
//   0 = headless        (no screen — N16R8 dev board)
//   1 = U8g2 mono OLED  (ESP32-C3 SuperMini 72×40 SSD1306)
//   2 = TFT_eSPI color  (LilyGO T-QT Pro 128×128 GC9107)
//
// The public Display API is the same in every backend; everything below
// the API line is `#if`-gated so the unused drivers do not link in.

#include "display.h"
#include "config.h"
#include "icons.h"

#ifndef HONEYOPUS_DISPLAY_DRIVER
#define HONEYOPUS_DISPLAY_DRIVER 1
#endif

namespace honeyopus {

Display g_display;

// ============================================================================
//  Headless backend (driver 0): no-op everything.
// ============================================================================
#if HONEYOPUS_DISPLAY_DRIVER == 0

void Display::begin() {
#if HONEYOPUS_BUTTON_PIN >= 0
    pinMode(HONEYOPUS_BUTTON_PIN, INPUT_PULLUP);
#endif
}
void Display::powerOn_()     { on_ = false; }
void Display::powerOff_()    { on_ = false; }
void Display::off()          {}
void Display::showBootLogo(uint32_t) {}
void Display::showAttack(AttackKind) {}
void Display::showStatus(const String&, const String&, const String&) {}
void Display::renderStatus_() {}
void Display::wakeFromButton() {}
void Display::loop()         {}

// ============================================================================
//  U8g2 mono OLED backend (driver 1): the original 72×40 SSD1306 path.
// ============================================================================
#elif HONEYOPUS_DISPLAY_DRIVER == 1

} // namespace honeyopus
#include <U8g2lib.h>
#include <Wire.h>
namespace honeyopus {

#if HONEYOPUS_DISPLAY_W == 72 && HONEYOPUS_DISPLAY_H == 40
static U8G2_SSD1306_72X40_ER_F_HW_I2C u8g2(U8G2_R0, /*reset=*/U8X8_PIN_NONE);
#elif HONEYOPUS_DISPLAY_W == 128 && HONEYOPUS_DISPLAY_H == 64
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /*reset=*/U8X8_PIN_NONE);
#elif HONEYOPUS_DISPLAY_W == 128 && HONEYOPUS_DISPLAY_H == 32
static U8G2_SSD1306_128X32_UNIVISION_F_HW_I2C u8g2(U8G2_R0, /*reset=*/U8X8_PIN_NONE);
#else
#error "Unsupported HONEYOPUS_DISPLAY_W/H combination for the U8g2 OLED driver"
#endif

void Display::begin() {
    pinMode(HONEYOPUS_BUTTON_PIN, INPUT_PULLUP);
    Wire.begin(HONEYOPUS_I2C_SDA, HONEYOPUS_I2C_SCL);
    u8g2.begin();
    u8g2.setBusClock(400000);
    u8g2.setContrast(255);
}

void Display::powerOn_() {
    if (!on_) { u8g2.setPowerSave(0); on_ = true; }
}

void Display::powerOff_() {
    if (on_) {
        u8g2.clearBuffer();
        u8g2.sendBuffer();
        u8g2.setPowerSave(1);
        on_ = false;
        attack_kind_ = AttackKind::None;
    }
}

void Display::off() { powerOff_(); }

void Display::showBootLogo(uint32_t hold_ms) {
    powerOn_();
    u8g2.clearBuffer();
    int x = (HONEYOPUS_DISPLAY_W - icons::BOOT_LOGO_W) / 2;
    int y = (HONEYOPUS_DISPLAY_H - icons::BOOT_LOGO_H) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    u8g2.drawXBMP(x, y, icons::BOOT_LOGO_W, icons::BOOT_LOGO_H, icons::BOOT_LOGO);
    u8g2.sendBuffer();
    on_until_ms_ = millis() + hold_ms;
}

void Display::showAttack(AttackKind k) {
    if (k == AttackKind::None) return;
    attack_kind_ = k;
    powerOn_();
    u8g2.clearBuffer();
    const uint8_t* bmp = (k == AttackKind::SSH) ? icons::SSH_ICON : icons::TELNET_ICON;
    int x = (HONEYOPUS_DISPLAY_W - icons::TELNET_ICON_W) / 2;
    int y = (HONEYOPUS_DISPLAY_H - icons::TELNET_ICON_H) / 2;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    u8g2.drawXBMP(x, y, icons::TELNET_ICON_W, icons::TELNET_ICON_H, bmp);
    if (HONEYOPUS_DISPLAY_H >= 48) {
        u8g2.setFont(u8g2_font_5x7_tr);
        const char* label = (k == AttackKind::SSH) ? "SSH" : "TELNET";
        int tw = u8g2.getStrWidth(label);
        u8g2.drawStr((HONEYOPUS_DISPLAY_W - tw) / 2, HONEYOPUS_DISPLAY_H - 1, label);
    }
    u8g2.sendBuffer();
    uint32_t now = millis();
    uint32_t atk = (uint32_t)g_config.get().attack_icon_seconds * 1000UL;
    uint32_t cap = (uint32_t)g_config.get().display_on_seconds * 1000UL;
    attack_until_ms_ = now + atk;
    on_until_ms_ = now + min(atk, cap);
}

void Display::showStatus(const String& l1, const String& l2, const String& l3) {
    status_l1_ = l1; status_l2_ = l2; status_l3_ = l3;
    have_status_ = true;
    if (on_) renderStatus_();
}

void Display::renderStatus_() {
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_5x7_tr);
    int y = 7;
    u8g2.drawStr(0, y, status_l1_.c_str()); y += 9;
    if (status_l2_.length()) { u8g2.drawStr(0, y, status_l2_.c_str()); y += 9; }
    if (status_l3_.length()) { u8g2.drawStr(0, y, status_l3_.c_str()); y += 9; }
    u8g2.sendBuffer();
}

void Display::wakeFromButton() {
    powerOn_();
    if (have_status_) renderStatus_();
    uint32_t cap = (uint32_t)g_config.get().display_on_seconds * 1000UL;
    on_until_ms_ = millis() + cap;
}

void Display::loop() {
    bool pressed = digitalRead(HONEYOPUS_BUTTON_PIN) == LOW;
    uint32_t now = millis();
    if (pressed != !btn_last_state_) {
        if (now - btn_last_change_ > 30) {
            btn_last_change_ = now;
            btn_last_state_ = !pressed;
            if (pressed) wakeFromButton();
        }
    }
    if (!on_) return;
    if (attack_kind_ != AttackKind::None && now >= attack_until_ms_) {
        attack_kind_ = AttackKind::None;
        if (have_status_) renderStatus_();
    }
    if (now >= on_until_ms_) powerOff_();
}

// ============================================================================
//  LovyanGFX color backend (driver 2): LilyGO T-QT Pro 128×128 GC9107.
//  Pin mapping comes from the LilyGO-T-QT-Pro reference repo. We keep the
//  panel config self-contained here so platformio.ini stays clean.
// ============================================================================
#elif HONEYOPUS_DISPLAY_DRIVER == 2

} // namespace honeyopus
#define LGFX_USE_V1
#include <LovyanGFX.hpp>
namespace honeyopus {

// LilyGO T-QT Pro pin map (verified against the LilyGO repo):
//   SCK=3, MOSI=2, CS=5, DC=6, RST=1, BL=10, panel=GC9107, 128×128.
static constexpr int8_t TQT_PIN_SCK = 3;
static constexpr int8_t TQT_PIN_MOSI = 2;
static constexpr int8_t TQT_PIN_CS  = 5;
static constexpr int8_t TQT_PIN_DC  = 6;
static constexpr int8_t TQT_PIN_RST = 1;
static constexpr int8_t TQT_PIN_BL  = 10;

class LGFX_TQTPro : public lgfx::LGFX_Device {
    lgfx::Panel_GC9107  _panel_instance;
    lgfx::Bus_SPI       _bus_instance;
    lgfx::Light_PWM     _light_instance;
public:
    LGFX_TQTPro() {
        {
            auto cfg = _bus_instance.config();
            cfg.spi_host    = SPI2_HOST;
            cfg.spi_mode    = 0;
            cfg.freq_write  = 27000000;
            cfg.freq_read   = 16000000;
            cfg.spi_3wire   = true;
            cfg.use_lock    = true;
            cfg.dma_channel = SPI_DMA_CH_AUTO;
            cfg.pin_sclk    = TQT_PIN_SCK;
            cfg.pin_mosi    = TQT_PIN_MOSI;
            cfg.pin_miso    = -1;
            cfg.pin_dc      = TQT_PIN_DC;
            _bus_instance.config(cfg);
            _panel_instance.setBus(&_bus_instance);
        }
        {
            auto cfg = _panel_instance.config();
            cfg.pin_cs           = TQT_PIN_CS;
            cfg.pin_rst          = TQT_PIN_RST;
            cfg.pin_busy         = -1;
            cfg.memory_width     = 128;
            cfg.memory_height    = 128;
            cfg.panel_width      = 128;
            cfg.panel_height     = 128;
            cfg.offset_x         = 2;   // GC9107 typical offsets
            cfg.offset_y         = 1;
            cfg.offset_rotation  = 0;
            cfg.dummy_read_pixel = 8;
            cfg.dummy_read_bits  = 1;
            cfg.readable         = false;
            cfg.invert           = true;
            cfg.rgb_order        = false;
            cfg.dlen_16bit       = false;
            cfg.bus_shared       = false;
            _panel_instance.config(cfg);
        }
        {
            auto cfg = _light_instance.config();
            cfg.pin_bl      = TQT_PIN_BL;
            cfg.invert      = false;
            cfg.freq        = 12000;
            cfg.pwm_channel = 7;
            _light_instance.config(cfg);
            _panel_instance.setLight(&_light_instance);
        }
        setPanel(&_panel_instance);
    }
};

static LGFX_TQTPro tft;

// XBM (LSB-first, like U8g2) → LovyanGFX with optional integer scaling.
static void drawXBM_(int x, int y, int w, int h,
                     const uint8_t* bmp, uint16_t fg, uint16_t bg, uint8_t scale) {
    int row_bytes = (w + 7) / 8;
    for (int j = 0; j < h; j++) {
        for (int i = 0; i < w; i++) {
            uint8_t b = bmp[j * row_bytes + (i >> 3)];
            bool on  = (b >> (i & 7)) & 1;
            uint16_t c = on ? fg : bg;
            if (scale == 1) tft.drawPixel(x + i, y + j, c);
            else            tft.fillRect(x + i * scale, y + j * scale, scale, scale, c);
        }
    }
}

void Display::begin() {
#if HONEYOPUS_BUTTON_PIN >= 0
    pinMode(HONEYOPUS_BUTTON_PIN, INPUT_PULLUP);
#endif
    tft.init();
    tft.setRotation(0);
    tft.setBrightness(180);
    tft.fillScreen(TFT_BLACK);
}

void Display::powerOn_() {
    tft.setBrightness(180);
    on_ = true;
}

void Display::powerOff_() {
    if (on_) {
        tft.fillScreen(TFT_BLACK);
        tft.setBrightness(0);
        on_ = false;
        attack_kind_ = AttackKind::None;
    }
}

void Display::off() { powerOff_(); }

void Display::showBootLogo(uint32_t hold_ms) {
    powerOn_();
    tft.fillScreen(TFT_BLACK);
    int x = (HONEYOPUS_DISPLAY_W - icons::BOOT_LOGO_W) / 2;
    int y = (HONEYOPUS_DISPLAY_H - icons::BOOT_LOGO_H) / 2;
    drawXBM_(x, y, icons::BOOT_LOGO_W, icons::BOOT_LOGO_H,
             icons::BOOT_LOGO, TFT_GOLD, TFT_BLACK, 1);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.setTextSize(1);
    tft.setTextDatum(textdatum_t::middle_center);
    tft.drawString("HoneyOpus", HONEYOPUS_DISPLAY_W / 2, HONEYOPUS_DISPLAY_H - 10);
    on_until_ms_ = millis() + hold_ms;
}

void Display::showAttack(AttackKind k) {
    if (k == AttackKind::None) return;
    attack_kind_ = k;
    powerOn_();
    bool ssh = (k == AttackKind::SSH);
    uint16_t bg = ssh ? TFT_NAVY : TFT_MAROON;
    uint16_t fg = ssh ? TFT_CYAN : TFT_RED;
    tft.fillScreen(bg);
    const int scale = 3;
    int iw = icons::TELNET_ICON_W * scale;
    int ih = icons::TELNET_ICON_H * scale;
    int x = (HONEYOPUS_DISPLAY_W - iw) / 2;
    int y = (HONEYOPUS_DISPLAY_H - ih) / 2 - 6;
    drawXBM_(x, y, icons::TELNET_ICON_W, icons::TELNET_ICON_H,
             ssh ? icons::SSH_ICON : icons::TELNET_ICON, fg, bg, scale);
    tft.setTextColor(TFT_WHITE, bg);
    tft.setTextSize(2);
    tft.setTextDatum(textdatum_t::middle_center);
    tft.drawString(ssh ? "SSH" : "TELNET",
                   HONEYOPUS_DISPLAY_W / 2, HONEYOPUS_DISPLAY_H - 14);
    uint32_t now = millis();
    uint32_t atk = (uint32_t)g_config.get().attack_icon_seconds * 1000UL;
    uint32_t cap = (uint32_t)g_config.get().display_on_seconds * 1000UL;
    attack_until_ms_ = now + atk;
    on_until_ms_ = now + min(atk, cap);
}

void Display::showStatus(const String& l1, const String& l2, const String& l3) {
    status_l1_ = l1; status_l2_ = l2; status_l3_ = l3;
    have_status_ = true;
    if (on_) renderStatus_();
}

void Display::renderStatus_() {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(1);
    tft.setTextDatum(textdatum_t::top_left);
    int y = 6;
    tft.drawString(status_l1_.c_str(), 4, y);                y += 16;
    if (status_l2_.length()) { tft.drawString(status_l2_.c_str(), 4, y); y += 16; }
    if (status_l3_.length()) { tft.drawString(status_l3_.c_str(), 4, y); y += 16; }
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString("HoneyOpus", 4, HONEYOPUS_DISPLAY_H - 12);
}

void Display::wakeFromButton() {
    powerOn_();
    if (have_status_) renderStatus_();
    uint32_t cap = (uint32_t)g_config.get().display_on_seconds * 1000UL;
    on_until_ms_ = millis() + cap;
}

void Display::loop() {
    bool pressed = digitalRead(HONEYOPUS_BUTTON_PIN) == LOW;
    uint32_t now = millis();
    if (pressed != !btn_last_state_) {
        if (now - btn_last_change_ > 30) {
            btn_last_change_ = now;
            btn_last_state_ = !pressed;
            if (pressed) wakeFromButton();
        }
    }
    if (!on_) return;
    if (attack_kind_ != AttackKind::None && now >= attack_until_ms_) {
        attack_kind_ = AttackKind::None;
        if (have_status_) renderStatus_();
    }
    if (now >= on_until_ms_) powerOff_();
}

#else
#error "Unknown HONEYOPUS_DISPLAY_DRIVER value"
#endif

} // namespace honeyopus
