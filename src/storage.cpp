#include "storage.h"
#include "config.h"

#include <algorithm>
#include <sys/stat.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

namespace honeymire {

bool fs_exists_silent(const char* fs_path) {
    String vfs = String("/littlefs") + fs_path;
    struct stat st;
    return stat(vfs.c_str(), &st) == 0;
}

bool storage_begin() {
    // First boot on a freshly flashed board: the data partition is empty
    // and LittleFS prints "Corrupted dir pair", "mount failed (-84)",
    // "Failed to initialize LittleFS" before silently formatting. On a
    // 16 MB N16R8 the partition is 12 MB and the format takes several
    // seconds with no output, which looks indistinguishable from a hang.
    // We bracket it with explicit log lines and try a deliberate
    // format-and-retry if the auto-format path didn't take.
    Serial.println("[fs] mounting LittleFS...");
    if (LittleFS.begin(false)) {
        Serial.printf("[fs] mounted (%u/%u KiB used)\n",
                      (unsigned)(LittleFS.usedBytes() / 1024),
                      (unsigned)(LittleFS.totalBytes() / 1024));
    } else {
        Serial.println("[fs] mount failed — formatting (this can take 5-15 s on 16 MB flash)");
        if (!LittleFS.format()) {
            Serial.println("[fs] format failed");
            return false;
        }
        if (!LittleFS.begin(false)) {
            Serial.println("[fs] mount failed even after explicit format");
            return false;
        }
        Serial.printf("[fs] formatted and mounted (%u KiB total)\n",
                      (unsigned)(LittleFS.totalBytes() / 1024));
    }
    if (!fs_exists_silent("/sessions")) LittleFS.mkdir("/sessions");
    if (!fs_exists_silent("/attacks"))  LittleFS.mkdir("/attacks");
    if (!fs_exists_silent("/etc"))      LittleFS.mkdir("/etc");
    // Pre-create an empty attack log so the first read-probe doesn't error.
    if (!fs_exists_silent("/attacks/log.jsonl")) {
        File f = LittleFS.open("/attacks/log.jsonl", "w");
        if (f) f.close();
    }
    return true;
}

size_t storage_total_bytes() { return LittleFS.totalBytes(); }
size_t storage_used_bytes()  { return LittleFS.usedBytes(); }

std::vector<String> storage_list_dir(const char* dir, size_t limit) {
    std::vector<String> out;
    File d = LittleFS.open(dir);
    if (!d || !d.isDirectory()) return out;
    File f = d.openNextFile();
    while (f) {
        if (!f.isDirectory()) out.push_back(String(f.name()));
        f = d.openNextFile();
    }
    // Names are timestamp-prefixed so lexicographic descending == newest first.
    std::sort(out.begin(), out.end(), std::greater<String>());
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

void storage_trim_sessions(uint16_t max_keep) {
    auto names = storage_list_dir("/sessions");
    if (names.size() <= max_keep) return;
    // names are newest-first; delete the tail.
    for (size_t i = max_keep; i < names.size(); ++i) {
        String full = String("/sessions/") + names[i];
        if (fs_exists_silent(full.c_str())) {
            LittleFS.remove(full);
        }
        // Drop the matching events sidecar if any (only for .cast bases).
        if (full.endsWith(".cast")) {
            String side = full + ".events.jsonl";
            if (fs_exists_silent(side.c_str())) LittleFS.remove(side);
        }
    }
}

size_t storage_enforce_session_quota(uint16_t max_keep, size_t max_total_bytes) {
    // Two telnet/SSH sessions can finalize at the same time; without a mutex
    // they race on /sessions enumeration and one task tries to stat or remove
    // files the other has already deleted. ESP-IDF then logs noisy
    // 'vfs_api.cpp:105 open(): ... does not exist' errors for every miss.
    static SemaphoreHandle_t mtx = xSemaphoreCreateMutex();
    if (mtx) xSemaphoreTake(mtx, portMAX_DELAY);
    auto names = storage_list_dir("/sessions");
    // Compute total bytes of every entry. Skip files that disappeared between
    // listing and stat — fs_exists_silent uses stat() and produces no log.
    struct Entry { String name; size_t sz; };
    std::vector<Entry> all;
    all.reserve(names.size());
    size_t total = 0;
    for (auto& n : names) {
        String full = String("/sessions/") + n;
        if (!fs_exists_silent(full.c_str())) continue;
        File f = LittleFS.open(full, "r");
        size_t sz = f ? f.size() : 0;
        if (f) f.close();
        all.push_back({n, sz});
        total += sz;
    }
    // names came back newest-first; we want to delete the oldest first.
    size_t deleted = 0;
    while (!all.empty() &&
           (all.size() > max_keep || (max_total_bytes && total > max_total_bytes))) {
        Entry& victim = all.back();
        String full = String("/sessions/") + victim.name;
        if (LittleFS.remove(full)) ++deleted;
        // Drop matching sidecar.
        if (full.endsWith(".cast")) {
            String side = full + ".events.jsonl";
            if (fs_exists_silent(side.c_str())) {
                if (LittleFS.remove(side)) ++deleted;
            }
        }
        total = (total > victim.sz) ? (total - victim.sz) : 0;
        all.pop_back();
    }
    if (mtx) xSemaphoreGive(mtx);
    return deleted;
}

size_t storage_clear_history() {
    auto names = storage_list_dir("/sessions");
    size_t removed = 0;
    for (auto& n : names) {
        String full = String("/sessions/") + n;
        if (LittleFS.remove(full)) ++removed;
    }
    // Truncate the JSONL log itself.
    File f = LittleFS.open("/attacks/log.jsonl", "w");
    if (f) { f.close(); ++removed; }
    return removed;
}

} // namespace honeymire
