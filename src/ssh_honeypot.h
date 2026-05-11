#pragma once

#include <Arduino.h>

namespace honeymire {

// Starts a FreeRTOS listener task on port HONEYMIRE_SSH_PORT.
// The first time it runs after a fresh flash it generates an RSA host key
// (~30 s on C3) and persists it to LittleFS.
void ssh_begin();

// Status flags used by the dashboard to show "still initializing" state.
bool ssh_hostkey_ready();         // true once the persistent host key is loaded/generated
bool ssh_listener_running();      // true after ssh_bind_listen succeeded

} // namespace honeymire
