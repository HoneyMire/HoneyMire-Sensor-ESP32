#pragma once

#include <Arduino.h>

namespace honeymire {

// Drives an interactive serial CLI. Call from main loop. The very first time
// it's called it prints a banner; while in menu mode it reads characters and
// dispatches commands.
void serial_menu_begin();
void serial_menu_loop();

} // namespace honeymire
