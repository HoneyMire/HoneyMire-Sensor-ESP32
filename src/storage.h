#pragma once

#include <Arduino.h>
#include <LittleFS.h>

namespace honeymire {

// Initializes LittleFS (formats on first boot if needed) and ensures the
// /sessions/ and /attacks/ directories exist.
bool storage_begin();

// Computes free space in LittleFS (best-effort).
size_t storage_total_bytes();
size_t storage_used_bytes();

// Trims oldest files in /sessions/ until at most max_keep remain. Removes
// matching ".events.jsonl" sidecars together with their parent .cast.
void storage_trim_sessions(uint16_t max_keep);

// Enforces both a file-count cap and a total-bytes cap on /sessions/.
// Deletes oldest-first until used <= max_keep AND total bytes <= max_total_bytes.
// Returns the number of files (cast + sidecar) actually deleted.
size_t storage_enforce_session_quota(uint16_t max_keep, size_t max_total_bytes);

// Wipes EVERY file under /sessions/ (including .events.jsonl sidecars) and
// truncates the attack-log JSONL. Configuration in NVS is left untouched.
// Returns the number of files removed.
size_t storage_clear_history();

// Returns a list of filenames (newest-first) under a directory.
std::vector<String> storage_list_dir(const char* dir, size_t limit = 0);

// Silent existence probe (POSIX stat under /littlefs). LittleFS.exists() calls
// open(...,"r") internally, which logs at ERROR level whenever the file is
// absent — that is fine but spams the console on every first-boot probe.
bool fs_exists_silent(const char* fs_path);

} // namespace honeymire
