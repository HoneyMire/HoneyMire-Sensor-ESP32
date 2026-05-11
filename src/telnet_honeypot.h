#pragma once

#include <Arduino.h>

namespace honeymire {

// Starts a FreeRTOS listener task on port HONEYMIRE_TELNET_PORT.
// It only does anything once WiFi is connected.
void telnet_begin();

// Reaper. Call periodically (~1 Hz) from the main loop to force-close any
// session that has exceeded the wall-clock cap. AsyncTCP's onPoll/
// onDisconnect callbacks are not always reliable under lwIP pressure;
// without an external sweep, a stuck session can pin ~100 KB of heap
// indefinitely.
void telnet_reap();

} // namespace honeymire
