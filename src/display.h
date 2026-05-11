#pragma once

#include <Arduino.h>

namespace honeymire {

enum class AttackKind { None, Telnet, SSH };

class Display {
public:
    void begin();
    void loop();                       // call from main loop

    void showBootLogo(uint32_t hold_ms = 1500);

    // Safe to call from any task (AsyncTCP, libssh, WiFi events, ...).
    // Actual rendering is deferred to loop(), which runs on the main task
    // that owns the SPI/I2C bus. This prevents cross-task races on the
    // display driver's internal mutex (LovyanGFX/SPI in particular).
    void showAttack(AttackKind k);     // flashes icon for cfg.attack_icon_seconds
    void showStatus(const String& l1,
                    const String& l2 = "",
                    const String& l3 = "");
    void wakeFromButton();             // user pressed function button
    void off();

    bool isOn() const { return on_; }

private:
    void renderStatus_();
    void renderAttack_(AttackKind k);
    void powerOff_();
    void powerOn_();

    bool      on_ = false;
    uint32_t  on_until_ms_ = 0;        // hard ceiling (display_on_seconds)
    uint32_t  attack_until_ms_ = 0;    // attack icon flash deadline
    AttackKind attack_kind_ = AttackKind::None;
    bool      have_status_ = false;
    String    status_l1_, status_l2_, status_l3_;

    bool      btn_last_state_ = true;  // active-low; pulled-up
    uint32_t  btn_last_change_ = 0;

    // Cross-task render request (set from any task; consumed by loop()).
    volatile AttackKind pending_attack_ = AttackKind::None;
};

extern Display g_display;

} // namespace honeymire
