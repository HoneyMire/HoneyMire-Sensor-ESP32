#include "fake_shell.h"
#include "telnet_persona.h"
#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <cstring>
#include <cstdlib>

namespace honeymire {

// ------------ tunables (NEW.md "Safety Rules") ------------
static const uint16_t MAX_COMMANDS_PER_SESSION = 500;
static const uint16_t MAX_CMD_LEN              = 4096;
static const uint16_t MAX_VFS_FILES            = 64;
static const uint16_t MAX_VPROCS               = 64;
static const uint32_t MAX_VFILE_SIZE           = 16 * 1024;
static const uint32_t MAX_SLEEP_MS             = 3000;

// ------------ per-persona static content (FS-CR-1 / FS-4 / FS-5) ------------
//
// Each persona has its own copy of the high-fingerprint fixtures: the
// fields a sophisticated bot probes to figure out what kind of device
// it landed on. Pre-2026-05-08 every persona returned the same Ubuntu
// 18.04 / Xeon E5-2680 content, so a bot running `cat /proc/cpuinfo`
// on what it believed was a HiLinux NVR Box got Xeon — instant tell.
//
// Realism rules of thumb:
//   - Ubuntu       → x86_64, kernel 5.x, bash present, /etc/passwd has
//                    the usual suspects, /proc/* is verbose.
//   - BusyBox      → MIPS or ARM SoC, kernel 4.x, ash shell, minimal
//                    /etc/passwd, sometimes no /etc/os-release at all.
//   - RouterOS     → not a Unix shell. /proc and /etc don't exist in
//                    the way bots expect; we return empty content for
//                    the most-probed paths so cat looks like the file
//                    is empty rather than wrong.
//   - OpenWrt      → MIPS or ARM router, BusyBox + opkg, /etc/openwrt_
//                    release present, /etc/passwd very minimal.
//   - DVRDVS       → ARMv7 Cortex-A9, kernel 3.x, no /etc/os-release,
//                    /etc/passwd is root + admin.
//   - HiLinux NVR  → HiSilicon Hi3516 / Hi3520, kernel 3.x, armv7l,
//                    /etc/passwd is root only, mounts include ubifs.
//
// Field discipline:
//   - All strings end with the same line-terminator semantics they
//     would have on a real device (trailing \n where the kernel emits
//     one, no trailing \n where it doesn't).
//   - Empty string ("") means "this file does not exist on this
//     persona". Callers fall through to the default not-found path.
//   - kernel_release / arch / uname_a stay consistent — `uname -r`
//     and the second field of `uname -a` must agree.
struct PersonaContent {
    const char* os_release;     // /etc/os-release ("" = absent)
    const char* cpuinfo;        // /proc/cpuinfo
    const char* meminfo;        // /proc/meminfo
    const char* mounts;         // /proc/mounts
    const char* hosts;          // /etc/hosts
    const char* resolv;         // /etc/resolv.conf ("" = absent)
    const char* passwd;         // /etc/passwd
    const char* version_proc;   // /proc/version (kernel build banner)
    const char* uname_kernel;   // `uname -r` (kernel release)
    const char* uname_arch;     // `uname -m` (machine)
    const char* uname_a;        // full `uname -a` string (NO trailing \n)
    const char* issue;          // /etc/issue ("" = absent)
};

// ----- Ubuntu: 22.04.1 LTS / x86_64 -----
// Aligned with the persona profile banner ("Ubuntu 22.04.1 LTS"). The
// previous fixtures advertised 18.04 on a 22.04 banner, which was
// itself a tell.
static const char* UBUNTU_OS_RELEASE =
    "PRETTY_NAME=\"Ubuntu 22.04.1 LTS\"\n"
    "NAME=\"Ubuntu\"\n"
    "VERSION_ID=\"22.04\"\n"
    "VERSION=\"22.04.1 LTS (Jammy Jellyfish)\"\n"
    "VERSION_CODENAME=jammy\n"
    "ID=ubuntu\n"
    "ID_LIKE=debian\n"
    "HOME_URL=\"https://www.ubuntu.com/\"\n"
    "SUPPORT_URL=\"https://help.ubuntu.com/\"\n"
    "BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n"
    "PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n"
    "UBUNTU_CODENAME=jammy\n";

static const char* UBUNTU_CPUINFO =
    "processor\t: 0\n"
    "vendor_id\t: GenuineIntel\n"
    "cpu family\t: 6\n"
    "model\t\t: 79\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
    "stepping\t: 1\n"
    "microcode\t: 0xb000038\n"
    "cpu MHz\t\t: 2399.998\n"
    "cache size\t: 35840 KB\n"
    "physical id\t: 0\n"
    "siblings\t: 1\n"
    "core id\t\t: 0\n"
    "cpu cores\t: 1\n"
    "bogomips\t: 4799.99\n"
    "address sizes\t: 46 bits physical, 48 bits virtual\n\n";

static const char* UBUNTU_MEMINFO =
    "MemTotal:        1009856 kB\n"
    "MemFree:          120432 kB\n"
    "MemAvailable:     704128 kB\n"
    "Buffers:           41216 kB\n"
    "Cached:           512384 kB\n"
    "SwapTotal:             0 kB\n"
    "SwapFree:              0 kB\n";

static const char* UBUNTU_MOUNTS =
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "udev /dev devtmpfs rw,nosuid,relatime,size=494056k,nr_inodes=123514,mode=755 0 0\n"
    "/dev/vda1 / ext4 rw,relatime,errors=remount-ro 0 0\n"
    "tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=101000k,mode=755 0 0\n";

static const char* UBUNTU_HOSTS =
    "127.0.0.1 localhost\n"
    "127.0.1.1 ubuntu\n\n"
    "# The following lines are desirable for IPv6 capable hosts\n"
    "::1     ip6-localhost ip6-loopback\n"
    "fe00::0 ip6-localnet\n"
    "ff00::0 ip6-mcastprefix\n"
    "ff02::1 ip6-allnodes\n"
    "ff02::2 ip6-allrouters\n";

static const char* UBUNTU_RESOLV =
    "# Generated by NetworkManager\n"
    "nameserver 8.8.8.8\n"
    "nameserver 1.1.1.1\n";

static const char* UBUNTU_PASSWD =
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin\n"
    "syslog:x:102:106::/home/syslog:/usr/sbin/nologin\n"
    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash\n";

static const char* UBUNTU_VERSION_PROC =
    "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) "
    "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) "
    "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n";

// ----- BusyBox: generic embedded MIPS, BusyBox 1.35.0 -----
// BusyBox-only systems frequently lack /etc/os-release entirely. Bots
// that probe it expect ENOENT; we return "" so callers fall through.
static const char* BUSYBOX_OS_RELEASE = "";

static const char* BUSYBOX_CPUINFO =
    "system type\t\t: Atheros AR9344 rev 2\n"
    "machine\t\t\t: TP-LINK TL-WDR3600 v1\n"
    "processor\t\t: 0\n"
    "cpu model\t\t: MIPS 74Kc V5.0\n"
    "BogoMIPS\t\t: 278.93\n"
    "wait instruction\t: yes\n"
    "microsecond timers\t: yes\n"
    "tlb_entries\t\t: 32\n"
    "extra interrupt vector\t: yes\n"
    "hardware watchpoint\t: yes, count: 4, address/irw mask: [0x0000, 0x0840, 0x0840, 0x0840]\n"
    "isa\t\t\t: mips1 mips2 mips32r1 mips32r2\n"
    "ASEs implemented\t: mips16 dsp\n"
    "shadow register sets\t: 1\n"
    "kscratch registers\t: 0\n"
    "package\t\t\t: 0\n"
    "core\t\t\t: 0\n"
    "VCED exceptions\t\t: not available\n"
    "VCEI exceptions\t\t: not available\n";

static const char* BUSYBOX_MEMINFO =
    "MemTotal:          61420 kB\n"
    "MemFree:           18044 kB\n"
    "MemAvailable:      27108 kB\n"
    "Buffers:            1932 kB\n"
    "Cached:            12648 kB\n"
    "SwapTotal:             0 kB\n"
    "SwapFree:              0 kB\n";

static const char* BUSYBOX_MOUNTS =
    "/dev/root / squashfs ro,relatime 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
    "tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0\n"
    "/dev/mtdblock3 /overlay jffs2 rw,noatime 0 0\n"
    "overlayfs:/overlay / overlay rw,noatime,lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work 0 0\n"
    "debugfs /sys/kernel/debug debugfs rw,noatime 0 0\n";

static const char* BUSYBOX_HOSTS =
    "127.0.0.1 localhost\n";

static const char* BUSYBOX_RESOLV =
    "nameserver 192.168.1.1\n";

static const char* BUSYBOX_PASSWD =
    "root:x:0:0:root:/root:/bin/ash\n"
    "nobody:x:99:99:nobody:/:/bin/false\n"
    "admin:x:1000:1000:admin:/home/admin:/bin/ash\n";

static const char* BUSYBOX_VERSION_PROC =
    "Linux version 4.14.221 (builder@buildhost) "
    "(gcc version 7.5.0 (OpenWrt GCC 7.5.0 r11208-ce6496d796)) "
    "#0 SMP Wed Mar 24 17:43:00 2021\n";

// ----- RouterOS: not a Unix shell. Most /proc and /etc are absent. -----
// RouterOS doesn't ship cat or /proc; if a bot somehow gets to a path
// that we honour anyway, returning "" gives an empty-file response —
// closer to truth than fake Linux content.
static const char* ROUTEROS_OS_RELEASE = "";
static const char* ROUTEROS_CPUINFO    = "";
static const char* ROUTEROS_MEMINFO    = "";
static const char* ROUTEROS_MOUNTS     = "";
static const char* ROUTEROS_HOSTS      = "";
static const char* ROUTEROS_RESOLV     = "";
static const char* ROUTEROS_PASSWD     = "";
static const char* ROUTEROS_VERSION_PROC = "";

// ----- OpenWrt: BARRIER BREAKER 14.07 / MIPS -----
// Matches the persona's MOTD ASCII art ("BARRIER BREAKER (14.07,
// r42625)"). Real OpenWrt 14.07 ran on kernel 3.10.x.
static const char* OPENWRT_OS_RELEASE =
    "NAME=\"OpenWrt\"\n"
    "VERSION=\"BARRIER BREAKER (14.07, r42625)\"\n"
    "ID=openwrt\n"
    "ID_LIKE=lede\n"
    "PRETTY_NAME=\"OpenWrt BARRIER BREAKER 14.07\"\n"
    "VERSION_ID=\"14.07\"\n"
    "HOME_URL=\"https://openwrt.org/\"\n"
    "BUG_URL=\"https://bugs.openwrt.org/\"\n"
    "SUPPORT_URL=\"https://forum.openwrt.org/\"\n";

static const char* OPENWRT_CPUINFO =
    "system type\t\t: Atheros AR9344 rev 2\n"
    "machine\t\t\t: TP-LINK TL-WDR3600 v1\n"
    "processor\t\t: 0\n"
    "cpu model\t\t: MIPS 74Kc V5.0\n"
    "BogoMIPS\t\t: 278.93\n"
    "wait instruction\t: yes\n"
    "microsecond timers\t: yes\n"
    "tlb_entries\t\t: 32\n"
    "isa\t\t\t: mips1 mips2 mips32r1 mips32r2\n"
    "ASEs implemented\t: mips16 dsp\n"
    "package\t\t\t: 0\n"
    "core\t\t\t: 0\n";

static const char* OPENWRT_MEMINFO =
    "MemTotal:          61420 kB\n"
    "MemFree:           14228 kB\n"
    "MemAvailable:      26384 kB\n"
    "Buffers:            1812 kB\n"
    "Cached:            13164 kB\n"
    "SwapTotal:             0 kB\n"
    "SwapFree:              0 kB\n";

static const char* OPENWRT_MOUNTS =
    "/dev/root / squashfs ro,relatime 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
    "tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0\n"
    "/dev/mtdblock3 /overlay jffs2 rw,noatime 0 0\n"
    "overlayfs:/overlay / overlay rw,noatime,lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work 0 0\n"
    "debugfs /sys/kernel/debug debugfs rw,noatime 0 0\n";

static const char* OPENWRT_HOSTS =
    "127.0.0.1 localhost\n";

static const char* OPENWRT_RESOLV =
    "# /tmp/resolv.conf.auto generated by dnsmasq\n"
    "nameserver 192.168.1.1\n";

static const char* OPENWRT_PASSWD =
    "root:x:0:0:root:/root:/bin/ash\n"
    "daemon:*:1:1:daemon:/var:/bin/false\n"
    "nobody:*:65534:65534:nobody:/var:/bin/false\n";

static const char* OPENWRT_VERSION_PROC =
    "Linux version 3.10.49 (blogic@buildhost) "
    "(gcc version 4.8.3 (OpenWrt/Linaro GCC 4.8-2014.04 r42625) ) "
    "#1 Tue Sep 23 17:12:08 UTC 2014\n";

// ----- DVRDVS: ARMv7 / kernel 3.4 / 2014-vintage DVR firmware -----
// DVR firmware typically has no /etc/os-release, an /etc/passwd with
// just root + admin, and an ARM Cortex-A9 SoC.
static const char* DVRDVS_OS_RELEASE = "";

static const char* DVRDVS_CPUINFO =
    "Processor\t: ARMv7 Processor rev 1 (v7l)\n"
    "BogoMIPS\t: 532.48\n"
    "Features\t: swp half thumb fastmult vfp edsp neon vfpv3 tls vfpd32\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 7\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xc09\n"
    "CPU revision\t: 1\n"
    "\n"
    "Hardware\t: hi3520d\n"
    "Revision\t: 0000\n"
    "Serial\t\t: 0000000000000000\n";

static const char* DVRDVS_MEMINFO =
    "MemTotal:         253840 kB\n"
    "MemFree:           42168 kB\n"
    "Buffers:            8120 kB\n"
    "Cached:            76544 kB\n"
    "SwapTotal:             0 kB\n"
    "SwapFree:              0 kB\n";

static const char* DVRDVS_MOUNTS =
    "rootfs / rootfs rw 0 0\n"
    "/dev/root / squashfs ro,relatime 0 0\n"
    "proc /proc proc rw,relatime 0 0\n"
    "sysfs /sys sysfs rw,relatime 0 0\n"
    "tmpfs /tmp tmpfs rw,relatime 0 0\n"
    "tmpfs /var tmpfs rw,relatime 0 0\n"
    "/dev/mtdblock3 /home jffs2 rw,relatime 0 0\n";

static const char* DVRDVS_HOSTS =
    "127.0.0.1 localhost\n";

static const char* DVRDVS_RESOLV = "";

static const char* DVRDVS_PASSWD =
    "root:x:0:0::/root:/bin/sh\n"
    "admin:x:500:500::/home/admin:/bin/sh\n";

static const char* DVRDVS_VERSION_PROC =
    "Linux version 3.4.35 (root@dvr-build) "
    "(gcc version 4.8.3 20131202 (prerelease) (Hisilicon_v300) ) "
    "#1 PREEMPT Wed Jan 8 18:51:30 CST 2014\n";

// ----- HiLinux NVR Box: HiSilicon Hi3516 / kernel 3.10 / armv7l -----
// The HiLinux persona is the "NVR Box" appearance bots target most
// often — anything in the Hi3516/Hi3520 family. We model it after
// the Hisilicon DVR/IPC SDK output that ships with these devices.
static const char* HILINUX_OS_RELEASE = "";

static const char* HILINUX_CPUINFO =
    "Processor\t: ARMv7 Processor rev 5 (v7l)\n"
    "BogoMIPS\t: 1196.85\n"
    "Features\t: swp half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 7\n"
    "CPU variant\t: 0x0\n"
    "CPU part\t: 0xc07\n"
    "CPU revision\t: 5\n"
    "\n"
    "Hardware\t: hi3516cv300\n"
    "Revision\t: 0000\n"
    "Serial\t\t: 0000000000000000\n";

static const char* HILINUX_MEMINFO =
    "MemTotal:         126244 kB\n"
    "MemFree:           28912 kB\n"
    "Buffers:            5320 kB\n"
    "Cached:            42048 kB\n"
    "SwapTotal:             0 kB\n"
    "SwapFree:              0 kB\n";

static const char* HILINUX_MOUNTS =
    "rootfs / rootfs rw 0 0\n"
    "/dev/mtdblock2 / squashfs ro,relatime 0 0\n"
    "proc /proc proc rw,relatime 0 0\n"
    "sysfs /sys sysfs rw,relatime 0 0\n"
    "tmpfs /tmp tmpfs rw,relatime 0 0\n"
    "tmpfs /var tmpfs rw,relatime 0 0\n"
    "/dev/mtdblock4 /usr/local jffs2 rw,relatime 0 0\n"
    "ubi0:rootfs /mnt/mtd ubifs rw,relatime 0 0\n";

static const char* HILINUX_HOSTS =
    "127.0.0.1 localhost\n";

static const char* HILINUX_RESOLV = "";

static const char* HILINUX_PASSWD =
    "root:x:0:0:root:/root:/bin/sh\n";

static const char* HILINUX_VERSION_PROC =
    "Linux version 3.10.0 (root@buildhost) "
    "(gcc version 4.8.3 20140320 (prerelease) (Hisilicon_v500) ) "
    "#46 SMP PREEMPT Mon Aug 28 11:23:34 CST 2017\n";

// Order MUST match TelnetPersona enum order (Ubuntu, BusyBox, RouterOS,
// OpenWrt, DVRDVS, HiLinux). Same convention used by telnet_persona.cpp's
// profiles[] array.
static const PersonaContent PERSONA_CONTENT[6] = {
    /* Ubuntu   */ {
        UBUNTU_OS_RELEASE, UBUNTU_CPUINFO, UBUNTU_MEMINFO, UBUNTU_MOUNTS,
        UBUNTU_HOSTS, UBUNTU_RESOLV, UBUNTU_PASSWD, UBUNTU_VERSION_PROC,
        "5.15.0-91-generic", "x86_64",
        "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
        "Ubuntu 22.04.1 LTS \\n \\l\n\n",
    },
    /* BusyBox  */ {
        BUSYBOX_OS_RELEASE, BUSYBOX_CPUINFO, BUSYBOX_MEMINFO, BUSYBOX_MOUNTS,
        BUSYBOX_HOSTS, BUSYBOX_RESOLV, BUSYBOX_PASSWD, BUSYBOX_VERSION_PROC,
        "4.14.221", "mips",
        "Linux router 4.14.221 #0 SMP Wed Mar 24 17:43:00 2021 mips GNU/Linux",
        "",
    },
    /* RouterOS */ {
        ROUTEROS_OS_RELEASE, ROUTEROS_CPUINFO, ROUTEROS_MEMINFO, ROUTEROS_MOUNTS,
        ROUTEROS_HOSTS, ROUTEROS_RESOLV, ROUTEROS_PASSWD, ROUTEROS_VERSION_PROC,
        "", "",
        "",
        "",
    },
    /* OpenWrt  */ {
        OPENWRT_OS_RELEASE, OPENWRT_CPUINFO, OPENWRT_MEMINFO, OPENWRT_MOUNTS,
        OPENWRT_HOSTS, OPENWRT_RESOLV, OPENWRT_PASSWD, OPENWRT_VERSION_PROC,
        "3.10.49", "mips",
        "Linux OpenWrt 3.10.49 #1 Tue Sep 23 17:12:08 UTC 2014 mips GNU/Linux",
        "",
    },
    /* DVRDVS   */ {
        DVRDVS_OS_RELEASE, DVRDVS_CPUINFO, DVRDVS_MEMINFO, DVRDVS_MOUNTS,
        DVRDVS_HOSTS, DVRDVS_RESOLV, DVRDVS_PASSWD, DVRDVS_VERSION_PROC,
        "3.4.35", "armv7l",
        "Linux DVRDVS 3.4.35 #1 PREEMPT Wed Jan 8 18:51:30 CST 2014 armv7l GNU/Linux",
        "",
    },
    /* HiLinux  */ {
        HILINUX_OS_RELEASE, HILINUX_CPUINFO, HILINUX_MEMINFO, HILINUX_MOUNTS,
        HILINUX_HOSTS, HILINUX_RESOLV, HILINUX_PASSWD, HILINUX_VERSION_PROC,
        "3.10.0", "armv7l",
        "Linux hilinux-nvrbox 3.10.0 #46 SMP PREEMPT Mon Aug 28 11:23:34 CST 2017 armv7l GNU/Linux",
        "",
    },
};

// ------------ persona-neutral fake content ------------
//
// The FAKE_X constants below are reused across all personas — typically
// because the field is the same shape on every Linux-derivative
// (e.g. /proc/loadavg formatting), or because no realistic attacker
// probes the file in a persona-distinguishing way.

static const char* FAKE_SHADOW =
    "root:!:18000:0:99999:7:::\n"
    "daemon:*:18000:0:99999:7:::\n"
    "ubuntu:!:18000:0:99999:7:::\n";

static const char* FAKE_UPTIME_PROC = "1234567.89 1234000.00\n";

static const char* FAKE_LOADAVG_PROC = "0.08 0.12 0.09 1/142 12345\n";

static const char* FAKE_FILESYSTEMS_PROC =
    "nodev\tsysfs\n"
    "nodev\trootfs\n"
    "nodev\tramfs\n"
    "nodev\tbdev\n"
    "nodev\tproc\n"
    "nodev\tcgroup\n"
    "nodev\tcgroup2\n"
    "nodev\tcpuset\n"
    "nodev\ttmpfs\n"
    "nodev\tdevtmpfs\n"
    "nodev\tdebugfs\n"
    "nodev\ttracefs\n"
    "nodev\tsecurityfs\n"
    "nodev\tsockfs\n"
    "nodev\tpipefs\n"
    "nodev\tdevpts\n"
    "\text4\n"
    "\text3\n"
    "\text2\n"
    "nodev\thugetlbfs\n"
    "nodev\tautofs\n"
    "nodev\tmqueue\n";

static const char* FAKE_MODULES_PROC =
    "nf_conntrack_ipv4 16384 4 - Live 0xffffffffc04d2000\n"
    "nf_defrag_ipv4 16384 1 nf_conntrack_ipv4, Live 0xffffffffc04c5000\n"
    "xt_conntrack 16384 14 - Live 0xffffffffc04ba000\n"
    "ip_tables 28672 2 iptable_filter,iptable_nat, Live 0xffffffffc049d000\n"
    "x_tables 40960 9 xt_conntrack,iptable_filter,ip_tables, Live 0xffffffffc0488000\n"
    "virtio_net 28672 0 - Live 0xffffffffc045d000\n"
    "virtio_blk 20480 3 - Live 0xffffffffc0451000\n";

static const char* FAKE_NET_ROUTE_PROC =
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";

static const char* FAKE_NET_TCP_PROC =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
    "   1: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n"
    "   2: 0101A8C0:0016 0201A8C0:E132 01 00000000:00000000 02:000005A4 00000000     0        0 23456 2 0000000000000000 20 4 30 10 -1\n";

static const char* FAKE_NET_UDP_PROC =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
    "   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11111 2 0000000000000000 0\n"
    "   1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 11112 2 0000000000000000 0\n";

static const char* FAKE_NET_DEV_PROC =
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo: 1842413    14523    0    0    0     0          0         0  1842413   14523    0    0    0     0       0          0\n"
    "  eth0: 543219874  812349    0    0    0     0          0       412 421987432  612893    0    0    0     0       0          0\n";

static const char* FAKE_NET_ARP_PROC =
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0\n";

static const char* FAKE_STAT_PROC =
    "cpu  4523 0 1842 1234567 412 0 89 0 0 0\n"
    "cpu0 4523 0 1842 1234567 412 0 89 0 0 0\n"
    "intr 8123456 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    "ctxt 12345678\n"
    "btime 1685000000\n"
    "processes 12345\n"
    "procs_running 1\n"
    "procs_blocked 0\n"
    "softirq 1234567 0 412345 89 234567 0 0 12345 234567 0 340654\n";

static const char* FAKE_CGROUP_PROC =
    "12:freezer:/\n"
    "11:net_cls,net_prio:/\n"
    "10:cpu,cpuacct:/\n"
    "9:pids:/\n"
    "8:devices:/\n"
    "7:memory:/\n"
    "6:perf_event:/\n"
    "5:hugetlb:/\n"
    "4:blkio:/\n"
    "3:rdma:/\n"
    "2:misc:/\n"
    "1:name=systemd:/\n"
    "0::/\n";

// PID assigned to the current shell ("self"). Matches the entry pushed in
// begin() (pts/0 -bash). Bots that probe /proc/self/* should see consistent
// content tied to this pid.
static const uint16_t kSelfPid = 999;

// If `abs` is /proc/self/X or /proc/self return ("self", X). If it is
// /proc/<digits>/X or /proc/<digits> return (pid_string, X). Otherwise
// return ("", "") — caller should fall through.
static bool parseProcPid_(const String& abs, String& pid_out, String& tail_out) {
    if (!abs.startsWith("/proc/")) return false;
    int slash = abs.indexOf('/', 6);
    String first = (slash < 0) ? abs.substring(6) : abs.substring(6, slash);
    if (first == "self") {
        pid_out = "self";
    } else {
        if (first.length() == 0) return false;
        for (size_t i = 0; i < first.length(); ++i)
            if (!isdigit((unsigned char)first[i])) return false;
        pid_out = first;
    }
    tail_out = (slash < 0) ? String() : abs.substring(slash + 1);
    return true;
}

// ----- helpers -----
static String trim(const String& s) {
    int a=0,b=s.length();
    while(a<b && isspace((unsigned char)s[a])) ++a;
    while(b>a && isspace((unsigned char)s[b-1])) --b;
    return s.substring(a,b);
}
static bool startsWith(const String& s, const char* p) { return s.startsWith(p); }
static bool endsWith(const String& s, const char* p) {
    size_t pl=strlen(p); return s.length()>=pl && s.endsWith(p);
}
static String join(const std::vector<String>& v, char sep, size_t from=0) {
    String r;
    for (size_t i=from;i<v.size();++i) { if(i>from) r+=sep; r+=v[i]; }
    return r;
}
static long toLongOr(const String& s, long d) {
    char* e=nullptr; long v=strtol(s.c_str(),&e,10);
    if (!e || *e!='\0') return d; return v;
}
static String pad(const String& s, int w) {
    String r=s; while ((int)r.length()<w) r+=' '; return r;
}

// ===================== begin / motd / prompt =====================

void FakeShell::begin(const String& user, const String& host) {
    user_ = user;
    host_ = host.length() ? host : String("ubuntu");
    cwd_  = (user_=="root") ? "/root" : ("/home/"+user_);
    commands_=0; exit_=false; cap_hit_=false;
    last_status_ok_=true;
    files_.clear(); procs_.clear(); history_.clear(); env_.clear();
    crontab_="";

    env_.push_back({"HOME", cwd_});
    env_.push_back({"USER", user_});
    env_.push_back({"LOGNAME", user_});
    env_.push_back({"SHELL", "/bin/bash"});
    env_.push_back({"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"});
    env_.push_back({"PWD", cwd_});
    env_.push_back({"LANG", "C.UTF-8"});
    env_.push_back({"TERM", "xterm-256color"});
    env_.push_back({"HOSTNAME", host_});
    env_.push_back({"MAIL", "/var/mail/"+user_});

    // prepopulate a minimal process table
    procs_.push_back({1, "root", "?", "/sbin/init"});
    procs_.push_back({412, "root", "?", "/lib/systemd/systemd-journald"});
    procs_.push_back({501, "root", "?", "/usr/sbin/sshd -D"});
    procs_.push_back({502, "root", "?", "/usr/sbin/cron -f"});
    procs_.push_back({601, "syslog", "?", "/usr/sbin/rsyslogd -n"});
    procs_.push_back({743, "root", "tty1", "-bash"});
    procs_.push_back({999, "root", "pts/0", "-bash"});
}

void FakeShell::setSessionInfo(uint32_t session_id, const String& source_ip,
                               uint16_t source_port, const String& protocol,
                               const String& events_path) {
    session_id_=session_id; src_ip_=source_ip; src_port_=source_port;
    proto_=protocol; events_path_=events_path;
}

void FakeShell::setPersona(TelnetPersona p) {
    persona_ = p;
}

String FakeShell::motd() const {
    String s;
    switch (persona_) {
        case TelnetPersona::Ubuntu:
            s += "Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n";
            s += " * Documentation:  https://help.ubuntu.com\r\n";
            s += " * Management:     https://landscape.canonical.com\r\n";
            s += " * Support:        https://ubuntu.com/advantage\r\n\r\n";
            s += "  System information as of " + String(millis()/1000) + "\r\n\r\n";
            s += "  System load:  0.08              Processes:           98\r\n";
            s += "  Usage of /:   23.4% of 19.56GB  Users logged in:     0\r\n";
            s += "  Memory usage: 28%               IP address for eth0: 10.0.0.42\r\n";
            s += "  Swap usage:   0%\r\n\r\n";
            s += "0 packages can be updated.\r\n";
            s += "0 updates are security updates.\r\n\r\n";
            s += "Last login: Mon Sep  4 09:14:21 2023 from 192.168.1.5\r\n";
            break;
        case TelnetPersona::BusyBox:
            s += "BusyBox v1.35.0 (2022-12-01) built-in shell (ash)\r\n";
            s += "Enter 'help' for a list of built-in commands.\r\n\r\n";
            break;
        case TelnetPersona::RouterOS:
            // RouterOS does not show MOTD on login, just the prompt
            break;
        case TelnetPersona::OpenWrt:
            s += "OpenWrt BARRIER BREAKER 14.07 r42625\r\n\r\n";
            s += "  _______                     ________        __\r\n";
            s += " |       |.-----.-----.-----.|  |  |  |.----.|  |\r\n";
            s += " |   -   ||  _  |  -__|     ||  |  |  ||   _||  |\r\n";
            s += " |_______||   __|_____|__|__||________||__|  |__|\r\n";
            s += " |  _  | |  |  W I R E L E S S    F R E E D O M\r\n";
            s += " | | | | |  |  BARRIER BREAKER (14.07, r42625)\r\n";
            s += " |_|_|_|_|__|_|_____________________________\r\n\r\n";
            break;
        case TelnetPersona::DVRDVS:
            s += "DVRDVS DVR System\r\n";
            s += "Type ? for help\r\n\r\n";
            break;
        case TelnetPersona::HiLinux:
            // HiLinux typically shows minimal banners
            s += "Welcome to HiLinux (NVR Box)\r\n\r\n";
            break;
        default:
            s += "Welcome to the system.\r\n";
            break;
    }
    return s;
}

String FakeShell::prompt() const {
    String p;
    switch (persona_) {
        case TelnetPersona::RouterOS:
            // RouterOS uses [hostname] > format
            p = "[" + host_ + "] > ";
            break;
        case TelnetPersona::BusyBox:
        case TelnetPersona::OpenWrt:
            // BusyBox/OpenWrt use # for root, $ for others
            if (user_ == "root" || user_ == "admin") {
                p = host_ + ":";
                String c = cwd_;
                String home = "/root";
                if (c == home) p += "~";
                else if (c.startsWith(home+"/")) p += "~"+c.substring(home.length());
                else p += c;
                p += "# ";
            } else {
                p = host_ + ":";
                String c = cwd_;
                String home = "/home/"+user_;
                if (c == home) p += "~";
                else if (c.startsWith(home+"/")) p += "~"+c.substring(home.length());
                else p += c;
                p += "$ ";
            }
            break;
        case TelnetPersona::DVRDVS:
            p = "dvrdvs> ";
            break;
        case TelnetPersona::HiLinux:
            p = host_ + "# ";
            break;
        case TelnetPersona::Ubuntu:
        default:
            p = user_ + "@" + host_ + ":";
            String c = cwd_;
            String home = (user_=="root") ? "/root" : ("/home/"+user_);
            if (c == home) p += "~";
            else if (c.startsWith(home+"/")) p += "~"+c.substring(home.length());
            else p += c;
            p += (user_=="root") ? "# " : "$ ";
            break;
    }
    return p;
}

// ===================== parsing =====================

String FakeShell::basename_(const String& p) {
    int i = p.lastIndexOf('/');
    return (i<0) ? p : p.substring(i+1);
}

String FakeShell::normalizeExe_(const String& exe) {
    String b = basename_(exe);
    // BusyBox-style: strip "busybox " prefix or busybox alias names
    if (b == "busybox") return "busybox";
    return b;
}

// Tokenize one segment with quote awareness; supports VAR=val prefixes & redirs.
static void tokenize(const String& src, std::vector<String>& out) {
    String cur;
    bool inS=false, inD=false;
    bool have=false;
    for (size_t i=0;i<src.length();++i) {
        char c = src[i];
        if (!inS && !inD && c=='\\' && i+1<src.length()) {
            // Outside quotes: backslash escapes the next char literally.
            cur+=src[i+1]; ++i; have=true; continue;
        }
        if (inD && c=='\\' && i+1<src.length()) {
            // Inside double quotes, bash only recognises \" \\ \$ \` \newline.
            // Every other backslash sequence is preserved verbatim — including
            // \x.., \n, \t etc., which are then re-interpreted by `echo -e`.
            char n = src[i+1];
            if (n=='"' || n=='\\' || n=='$' || n=='`' || n=='\n') {
                cur+=n; ++i; have=true; continue;
            }
            // Fall through: keep the backslash literal.
        }
        if (!inS && c=='"') { inD=!inD; have=true; continue; }
        if (!inD && c=='\'') { inS=!inS; have=true; continue; }
        if (!inS && !inD && (c==' '||c=='\t')) {
            if (have) { out.push_back(cur); cur=""; have=false; }
            continue;
        }
        cur+=c; have=true;
    }
    if (have) out.push_back(cur);
}

bool FakeShell::parseCmd_(const String& src, Cmd& out) {
    String s = trim(src);
    if (!s.length()) return false;

    // background marker at end
    if (s.endsWith("&")) {
        // but not "&&" or "&>" — those handled elsewhere
        if (!s.endsWith("&&") && !s.endsWith("&>")) {
            out.background = true;
            s = trim(s.substring(0, s.length()-1));
        }
    }

    std::vector<String> tok;
    tokenize(s, tok);
    if (tok.empty()) return false;

    // Strip env prefix VAR=val ...
    size_t k=0;
    while (k<tok.size()) {
        const String& t = tok[k];
        int eq = t.indexOf('=');
        if (eq>0) {
            bool ok=true;
            for (int i=0;i<eq;++i) {
                char ch=t[i];
                if (!(isalnum((unsigned char)ch)||ch=='_')) { ok=false; break; }
            }
            if (ok) {
                out.env_prefix.push_back({t.substring(0,eq), t.substring(eq+1)});
                ++k; continue;
            }
        }
        break;
    }
    if (k>=tok.size()) return false;

    // Walk tokens for redirections
    std::vector<String> argv;
    for (; k<tok.size(); ++k) {
        const String& t = tok[k];
        if (t == ">" || t == "1>") {
            if (k+1<tok.size()) {
                if (tok[k+1]=="/dev/null") out.redirect_null=true;
                else out.redirect_stdout = tok[k+1];
                ++k;
            }
            continue;
        }
        if (t == ">>") {
            if (k+1<tok.size()) { out.redirect_append = tok[k+1]; ++k; }
            continue;
        }
        if (t == "2>") {
            if (k+1<tok.size()) {
                if (tok[k+1]=="/dev/null") out.redirect_stderr_null=true;
                ++k;
            }
            continue;
        }
        if (t == "&>" || t == "2>&1") {
            if (t == "&>" && k+1<tok.size() && tok[k+1]=="/dev/null") {
                out.redirect_null=true; out.redirect_stderr_null=true; ++k;
            } else if (t=="&>") {
                if (k+1<tok.size()) { out.redirect_stdout=tok[k+1]; ++k; }
            }
            continue;
        }
        // 2>&1 inline
        if (t.endsWith("2>&1")) continue;
        argv.push_back(t);
    }
    if (argv.empty()) return false;

    out.argv = argv;
    out.exe  = normalizeExe_(argv[0]);
    out.raw  = s;
    return true;
}

int FakeShell::splitChain_(const String& line, std::vector<CmdNode>& out) {
    // Split on ; && || | with quote awareness.
    String cur;
    bool inS=false, inD=false;
    auto flush = [&](Sep sep){
        Cmd c;
        if (parseCmd_(cur, c)) {
            CmdNode n; n.cmd = c; n.follow = sep;
            out.push_back(n);
        }
        cur="";
    };
    for (size_t i=0;i<line.length();++i) {
        char ch=line[i];
        if (!inS && ch=='\\' && i+1<line.length()) { cur+=ch; cur+=line[i+1]; ++i; continue; }
        if (!inS && ch=='"') { inD=!inD; cur+=ch; continue; }
        if (!inD && ch=='\'') { inS=!inS; cur+=ch; continue; }
        if (!inS && !inD) {
            if (ch=='&' && i+1<line.length() && line[i+1]=='&') { flush(SEP_AND); ++i; continue; }
            if (ch=='|' && i+1<line.length() && line[i+1]=='|') { flush(SEP_OR);  ++i; continue; }
            if (ch=='|') { flush(SEP_PIPE); continue; }
            if (ch==';') { flush(SEP_SEMI); continue; }
        }
        cur+=ch;
    }
    if (trim(cur).length()) flush(SEP_NONE);
    return (int)out.size();
}

// ===================== path / vfs =====================

String FakeShell::resolvePath_(const String& p) const {
    if (!p.length()) return cwd_;
    String s = p;
    if (s == "~") s = (user_=="root") ? "/root" : ("/home/"+user_);
    else if (s.startsWith("~/")) s = ((user_=="root") ? "/root" : ("/home/"+user_)) + s.substring(1);
    String abs = s.startsWith("/") ? s : (cwd_=="/" ? "/"+s : cwd_+"/"+s);

    // normalize . and ..
    std::vector<String> parts;
    int i=0;
    while (i < (int)abs.length()) {
        int j = abs.indexOf('/', i);
        if (j<0) j = abs.length();
        String seg = abs.substring(i, j);
        if (seg.length() && seg != ".") {
            if (seg == "..") { if (!parts.empty()) parts.pop_back(); }
            else parts.push_back(seg);
        }
        i = j+1;
    }
    String r="";
    for (auto& x : parts) { r += "/"; r += x; }
    if (!r.length()) r = "/";
    return r;
}

bool FakeShell::isWritableDir_(const String& dir) {
    return dir=="/tmp" || dir.startsWith("/tmp/") ||
           dir=="/var/tmp" || dir.startsWith("/var/tmp/") ||
           dir=="/dev/shm" || dir.startsWith("/dev/shm/") ||
           dir=="/root" || dir.startsWith("/root/") ||
           dir.startsWith("/home/") || dir=="/var/run" || dir.startsWith("/var/run/");
}

VirtualFile* FakeShell::findFile_(const String& abs) {
    for (auto& f : files_) if (f.path == abs) return &f;
    return nullptr;
}
const VirtualFile* FakeShell::findFile_(const String& abs) const {
    for (auto& f : files_) if (f.path == abs) return &f;
    return nullptr;
}
bool FakeShell::fileExists_(const String& abs) const {
    if (findFile_(abs)) return true;
    // baked-in real-ish files
    if (abs=="/etc/passwd"||abs=="/etc/shadow"||abs=="/etc/os-release"||
        abs=="/etc/issue"||abs=="/etc/hostname"||abs=="/etc/hosts"||
        abs=="/etc/resolv.conf"||abs=="/proc/cpuinfo"||abs=="/proc/meminfo"||
        abs=="/proc/mounts"||abs=="/proc/version"||abs=="/proc/uptime"||
        abs=="/proc/loadavg"||abs=="/proc/stat"||abs=="/proc/filesystems"||
        abs=="/proc/modules"||abs=="/proc/cmdline"||
        abs=="/proc/net/route"||abs=="/proc/net/tcp"||abs=="/proc/net/tcp6"||
        abs=="/proc/net/udp"||abs=="/proc/net/udp6"||abs=="/proc/net/dev"||
        abs=="/proc/net/arp"||abs=="/proc/net/unix"||
        abs=="/proc/sys/kernel/hostname"||abs=="/proc/sys/kernel/osrelease"||
        abs=="/proc/sys/kernel/ostype"||abs=="/proc/sys/kernel/version"||
        abs=="/proc/sys/kernel/random/boot_id"||abs=="/proc/sys/kernel/random/uuid")
        return true;
    // Per-pid synthetic files: /proc/self/<x> or /proc/<existing-pid>/<x>
    {
        String pid_str, tail;
        if (parseProcPid_(abs, pid_str, tail) && tail.length()) {
            bool pid_known = (pid_str == "self");
            if (!pid_known) {
                uint16_t p = (uint16_t)toLongOr(pid_str, 0);
                for (auto& fp : procs_) if (fp.pid == p) { pid_known = true; break; }
            }
            if (pid_known) {
                static const char* leaves[] = {
                    "cmdline","comm","status","stat","statm","environ","loginuid",
                    "sessionid","oom_score","oom_score_adj","io","limits","cgroup",
                    "maps","mounts","mountinfo","exe","cwd","root", nullptr };
                for (int i = 0; leaves[i]; ++i) if (tail == leaves[i]) return true;
            }
        }
    }
    return false;
}
bool FakeShell::isDir_(const String& abs) const {
    auto* f = findFile_(abs);
    if (f) return f->is_dir;
    if (abs=="/"||abs=="/tmp"||abs=="/var"||abs=="/var/tmp"||abs=="/var/log"||
        abs=="/var/run"||abs=="/etc"||abs=="/root"||abs=="/home"||abs=="/dev"||
        abs=="/dev/shm"||abs=="/proc"||abs=="/proc/net"||abs=="/proc/sys"||
        abs=="/proc/sys/kernel"||abs=="/proc/sys/kernel/random"||
        abs=="/sys"||abs=="/usr"||abs=="/usr/bin"||
        abs=="/usr/sbin"||abs=="/usr/local"||abs=="/bin"||abs=="/sbin"||abs=="/lib"||
        abs=="/opt"||abs=="/mnt"||abs.startsWith("/home/")) return true;
    // /proc/self and /proc/<pid> directories
    {
        String pid_str, tail;
        if (parseProcPid_(abs, pid_str, tail) && tail.length() == 0) {
            if (pid_str == "self") return true;
            uint16_t p = (uint16_t)toLongOr(pid_str, 0);
            for (auto& fp : procs_) if (fp.pid == p) return true;
        }
    }
    // Common home subdirs
    if (abs=="/root/.ssh"||abs=="/root/.cache") return true;
    if (abs.startsWith("/home/") &&
        (abs.endsWith("/.ssh")||abs.endsWith("/.cache"))) return true;
    // /etc subdirs commonly traversed
    if (abs=="/etc/ssh"||abs=="/etc/systemd"||abs=="/etc/apt"||
        abs=="/etc/cron.d"||abs=="/etc/cron.hourly"||abs=="/etc/cron.daily") return true;
    return false;
}

VirtualFile* FakeShell::createFile_(const String& abs, const String& created_by) {
    if (auto* f = findFile_(abs)) return f;
    if (files_.size() >= MAX_VFS_FILES) { cap_hit_ = true; return nullptr; }
    VirtualFile f;
    f.path=abs; f.created_by=created_by; f.created_ms=millis(); f.mtime_ms=millis();
    files_.push_back(f);
    return &files_.back();
}

// ===================== payload helpers =====================

String FakeShell::guessArch_(const String& s) {
    String x = s; x.toLowerCase();
    if (x.indexOf("x86_64")>=0||x.indexOf("amd64")>=0) return "x86_64";
    if (x.indexOf("i686")>=0||x.indexOf("i386")>=0||x.indexOf(".x86")>=0) return "x86";
    if (x.indexOf("aarch64")>=0||x.indexOf("arm64")>=0) return "aarch64";
    if (x.indexOf("armv7")>=0||x.indexOf("arm7")>=0) return "armv7";
    if (x.indexOf("armv6")>=0||x.indexOf("arm6")>=0) return "armv6";
    if (x.indexOf("arm")>=0) return "arm";
    if (x.indexOf("mips")>=0) return "mips";
    if (x.indexOf("mipsel")>=0) return "mipsel";
    if (x.indexOf("ppc")>=0||x.indexOf("powerpc")>=0) return "ppc";
    if (x.indexOf("sh4")>=0) return "sh4";
    if (x.indexOf("spc")>=0||x.indexOf("sparc")>=0) return "sparc";
    return "x86_64";
}

String FakeShell::guessProfile_(const String& url, const String& name) {
    String u = url; u.toLowerCase();
    String n = name; n.toLowerCase();
    if (u.indexOf("xmrig")>=0||n.indexOf("xmrig")>=0||n.indexOf("miner")>=0||
        u.indexOf("monero")>=0||u.indexOf("cpuminer")>=0) return "crypto_miner";
    if (n.indexOf("mirai")>=0||u.indexOf("mirai")>=0||
        n=="x86"||n=="arm"||n=="arm5"||n=="arm6"||n=="arm7"||n=="mips"||
        n=="mipsel"||n=="ppc"||n=="sh4"||n=="spc"||n=="m68k") return "mirai_like_bot";
    if (n.indexOf("kinsing")>=0||u.indexOf("kinsing")>=0) return "kinsing";
    if (n.indexOf("tsunami")>=0||u.indexOf("tsunami")>=0) return "tsunami";
    if (n.indexOf("perl")>=0||n.endsWith(".pl")) return "perlbot";
    if (n.endsWith(".sh")) return "shell_dropper";
    return "generic_bot";
}

void FakeShell::detectReverseShell_(const Cmd& c, String& /*out*/) {
    String r = c.raw; String low = r; low.toLowerCase();
    bool hit=false; String tech;
    if (low.indexOf("bash -i")>=0 && low.indexOf("/dev/tcp/")>=0) { hit=true; tech="bash_dev_tcp"; }
    else if (low.indexOf("/dev/tcp/")>=0) { hit=true; tech="dev_tcp"; }
    else if ((low.indexOf("nc ")>=0||low.indexOf("ncat ")>=0) && (low.indexOf(" -e")>=0||low.indexOf("/bin/sh")>=0||low.indexOf("/bin/bash")>=0)) { hit=true; tech="nc_e"; }
    else if (low.indexOf("python")>=0 && low.indexOf("socket.socket")>=0 && low.indexOf("dup2")>=0) { hit=true; tech="python_socket"; }
    else if (low.indexOf("perl")>=0 && low.indexOf("socket")>=0 && low.indexOf("exec")>=0) { hit=true; tech="perl_socket"; }
    else if (low.indexOf("php")>=0 && low.indexOf("fsockopen")>=0) { hit=true; tech="php_fsockopen"; }
    else if (low.indexOf("socat")>=0 && low.indexOf("exec:")>=0) { hit=true; tech="socat_exec"; }
    else if (low.indexOf("mkfifo")>=0 && low.indexOf("nc ")>=0) { hit=true; tech="mkfifo_nc"; }
    if (hit) {
        StaticJsonDocument<384> d;
        d["technique"]=tech;
        d["raw"]=r.substring(0, min((unsigned)r.length(), 480u));
        String body; serializeJson(d, body);
        logEvent_("reverse_shell_attempt", body);
    }
}

// ===================== logging =====================

void FakeShell::logEvent_(const String& type, const String& json_body) {
    if (!events_path_.length()) return;
    StaticJsonDocument<128> head;
    head["ts"]   = (uint32_t) (millis()/1000);
    head["session"] = session_id_;
    head["ip"]   = src_ip_;
    head["port"] = src_port_;
    head["proto"]= proto_;
    head["type"] = type;
    String h; serializeJson(head, h);
    // splice body fields into head
    String line = h;
    if (json_body.length() && json_body[0]=='{') {
        // remove trailing '}' from head, prepend ',' + body inner
        line.remove(line.length()-1);
        if (json_body.length()>2) {
            line += ",";
            line += json_body.substring(1, json_body.length()-1);
        }
        line += "}";
    }
    line += "\n";
    File f = LittleFS.open(events_path_.c_str(), "a");
    if (!f) return;
    f.print(line);
    f.close();
}

void FakeShell::logCommand_(const String& raw, const std::vector<CmdNode>& chain) {
    StaticJsonDocument<512> d;
    d["raw"] = raw.substring(0, min((unsigned)raw.length(), 480u));
    JsonArray a = d["cmds"].to<JsonArray>();
    for (auto& n : chain) {
        JsonObject o = a.add<JsonObject>();
        o["exe"] = n.cmd.exe;
        JsonArray args = o["argv"].to<JsonArray>();
        for (auto& x : n.cmd.argv) args.add(x);
        switch (n.follow) {
            case SEP_AND:  o["sep"]="&&"; break;
            case SEP_OR:   o["sep"]="||"; break;
            case SEP_PIPE: o["sep"]="|"; break;
            case SEP_SEMI: o["sep"]=";"; break;
            default: break;
        }
    }
    String b; serializeJson(d, b);
    logEvent_("command", b);
}

// ===================== execute =====================

String FakeShell::execute(const String& line) {
    if (cap_hit_) return "";
    if (line.length() > MAX_CMD_LEN) { cap_hit_=true; return ""; }
    String s = trim(line);
    if (!s.length()) return "";
    if (++commands_ > MAX_COMMANDS_PER_SESSION) { cap_hit_=true; return ""; }
    {
        uint32_t now = millis();
        if (first_cmd_ms_ == 0) first_cmd_ms_ = now;
        last_cmd_ms_ = now;
    }
    history_.push_back(s);
    if (history_.size() > 256) history_.erase(history_.begin());
    String out = runChain_(s);
    // Normalize newlines for raw telnet/ssh terminals: bare \n -> \r\n
    String norm; norm.reserve(out.length() + 16);
    char prev = 0;
    for (size_t i = 0; i < out.length(); ++i) {
        char c = out[i];
        if (c == '\n' && prev != '\r') norm += '\r';
        norm += c;
        prev = c;
    }
    return norm;
}

String FakeShell::runChain_(const String& raw) {
    std::vector<CmdNode> chain;
    splitChain_(raw, chain);
    if (chain.empty()) return "";
    logCommand_(raw, chain);

    String out;
    bool prev_ok = true;
    Sep prev_sep = SEP_NONE;
    for (size_t i=0;i<chain.size();++i) {
        CmdNode& n = chain[i];
        bool run = true;
        if (i>0) {
            if (prev_sep == SEP_AND && !prev_ok) run=false;
            else if (prev_sep == SEP_OR && prev_ok) run=false;
        }
        if (run) {
            // detect reverse shell on each segment first
            detectReverseShell_(n.cmd, out);
            String r = runWithRedirects_(n.cmd);
            out += r;
            prev_ok = last_status_ok_;
        }
        prev_sep = n.follow;
        if (exit_ || cap_hit_) break;
    }
    return out;
}

String FakeShell::runWithRedirects_(Cmd& c) {
    String r = runOne_(c);
    // honor redirect_null/stderr_null and to-file by writing into VFS
    if (c.redirect_null) return "";
    if (c.redirect_stdout.length() || c.redirect_append.length()) {
        String tgt = c.redirect_stdout.length() ? c.redirect_stdout : c.redirect_append;
        String abs = resolvePath_(tgt);
        if (isWritableDir_(abs.substring(0, abs.lastIndexOf('/')+1))) {
            VirtualFile* vf = createFile_(abs, "redirect");
            if (vf) {
                if (c.redirect_append.length()) vf->content += r;
                else vf->content = r;
                if (vf->content.length() > MAX_VFILE_SIZE)
                    vf->content.remove(MAX_VFILE_SIZE);
                vf->size = vf->content.length();
                vf->mtime_ms = millis();
                // detect authorized_keys persistence
                if (abs.endsWith("/.ssh/authorized_keys")) {
                    StaticJsonDocument<256> d;
                    d["path"]=abs;
                    d["bytes"]=(uint32_t)r.length();
                    String b; serializeJson(d, b);
                    logEvent_("authorized_key_added", b);
                }
            }
        }
        return "";
    }
    return r;
}

// ===================== command dispatch =====================

String FakeShell::runOne_(Cmd& c) {
    last_status_ok_ = true;
    last_was_unknown_cmd_ = false;
    const String& e = c.exe;

    // BusyBox aliasing: "busybox <cmd> ..." -> shift. If <cmd> isn't a real
    // applet we *must* mimic BusyBox's "<applet>: applet not found" output —
    // Mirai/Gafgyt droppers probe exactly with `/bin/busybox <RANDOMSTRING>`
    // and treat the bash-style "command not found" as a honeypot tell.
    if (e == "busybox") {
        if (c.argv.size() < 2) {
            // Bare `busybox` — print a stub banner like real busybox does.
            return F("BusyBox v1.30.1 (2020-12-23 15:49:40 UTC) multi-call binary.\n"
                     "BusyBox is copyrighted by many authors between 1998-2015.\n"
                     "Licensed under GPLv2. See source distribution for detailed\n"
                     "copyright notices.\n\n"
                     "Usage: busybox [function [arguments]...]\n");
        }
        String applet = c.argv[1];
        c.argv.erase(c.argv.begin());
        c.exe = normalizeExe_(c.argv[0]);
        // Mark the inner dispatch as a busybox-context call so applets
        // (cmdWget_, etc.) can emit busybox-flavored output instead of
        // their default GNU style, regardless of which persona the
        // session is wearing.
        bool prev_busybox = in_busybox_call_;
        in_busybox_call_ = true;
        String r = runOne_(c);
        in_busybox_call_ = prev_busybox;
        // If the inner dispatch fell through to the persona's
        // not-found path (NOT a real applet error), rewrite as the
        // BusyBox applet-not-found line — that's what real
        // `busybox <unknown>` prints regardless of the surrounding
        // shell. We use last_was_unknown_cmd_ rather than just
        // last_status_ok_ so a real applet that ran and emitted its
        // own "<applet>: <error>" passes through verbatim.
        if (last_was_unknown_cmd_) {
            return applet + ": applet not found\n";
        }
        return r;
    }

    // path execution: ./x, /tmp/x, etc.
    if (c.argv[0].startsWith("./") || c.argv[0].startsWith("/")) {
        if (c.argv[0].endsWith(".sh") || c.argv[0].startsWith("/tmp/") ||
            c.argv[0].startsWith("/var/tmp/") || c.argv[0].startsWith("/dev/shm/") ||
            c.argv[0].startsWith("./")) {
            return cmdExecute_(c);
        }
    }

    if (e=="exit"||e=="logout"||e=="quit") { exit_=true; return ""; }
    if (e=="echo") return cmdEcho_(c);
    if (e=="printf") return cmdPrintf_(c);
    if (e=="ls"||e=="dir") return cmdLs_(c);
    if (e=="cd") return cmdCd_(c);
    if (e=="pwd") return cwd_+"\n";
    if (e=="whoami") return user_+"\n";
    if (e=="hostname") return host_+"\n";
    if (e=="uname") return cmdUname_(c);
    if (e=="id") return cmdId_(c);
    if (e=="cat") return cmdCat_(c);
    if (e=="head") return cmdHead_(c, false);
    if (e=="tail") return cmdHead_(c, true);
    if (e=="grep"||e=="egrep"||e=="fgrep") return cmdGrep_(c);
    if (e=="wc") return cmdWc_(c);
    if (e=="base64") return cmdBase64_(c);
    if (e=="ps") return cmdPs_(c);
    if (e=="netstat") return cmdNetstat_(c);
    if (e=="ss") return cmdSs_(c);
    if (e=="ifconfig") return cmdIfconfig_(c);
    if (e=="ip") return cmdIp_(c);
    if (e=="route") return cmdRoute_(c);
    if (e=="df") return cmdDf_(c);
    if (e=="free") return cmdFree_(c);
    if (e=="uptime") return cmdUptime_(c);
    if (e=="w"||e=="who") return cmdW_(c);
    if (e=="last") return cmdLast_(c);
    if (e=="mount") return cmdMount_(c);
    if (e=="lscpu") return cmdLscpu_(c);
    if (e=="env"||e=="printenv") return cmdEnv_(c);
    if (e=="export"||e=="set") return cmdExport_(c);
    if (e=="history") return cmdHistory_(c);
    if (e=="wget") return cmdWget_(c);
    if (e=="curl") return cmdCurl_(c);
    if (e=="tftp") return cmdTftp_(c);
    if (e=="ftpget"||e=="tftpget") return cmdFtpget_(c);
    if (e=="chmod") return cmdChmod_(c);
    if (e=="chown"||e=="chgrp") return cmdChown_(c);
    if (e=="rm") return cmdRm_(c);
    if (e=="mkdir") return cmdMkdir_(c);
    if (e=="rmdir") return ""; // silent
    if (e=="touch") return cmdTouch_(c);
    if (e=="mv") return cmdMv_(c);
    if (e=="cp") return cmdCp_(c);
    if (e=="which") return cmdWhich_(c);
    if (e=="whereis"||e=="type") return cmdWhereis_(c);
    if (e=="sleep") return cmdSleep_(c);
    if (e=="apt"||e=="apt-get"||e=="aptitude") return cmdApt_(c);
    if (e=="dpkg") return cmdDpkg_(c);
    if (e=="pip"||e=="pip2"||e=="pip3") return cmdPip_(c);
    if (e=="crontab") return cmdCrontab_(c);
    if (e=="systemctl") return cmdSystemctl_(c);
    if (e=="service") return cmdService_(c);
    if (e=="kill"||e=="killall"||e=="pkill") return cmdKill_(c, e);
    if (e=="nc"||e=="ncat") return cmdNc_(c);
    if (e=="ping"||e=="ping6") return cmdPing_(c);
    if (e=="iptables") return cmdIptables_(c);
    if (e=="ufw") return cmdUfw_(c);
    if (e=="sh"||e=="bash"||e=="ash"||e=="dash"||e=="zsh") return cmdShEval_(c);
    if (e=="python"||e=="python2"||e=="python3"||e=="perl"||e=="php"||
        e=="ruby"||e=="lua") return cmdInterp_(c);
    if (e=="nohup"||e=="setsid"||e=="timeout"||e=="screen"||e=="tmux") {
        if (c.argv.size()>=2) {
            // shift one or two leading wrappers
            String first=c.argv[1];
            c.argv.erase(c.argv.begin());
            if ((e=="timeout") && c.argv.size()>=2) {
                // timeout DURATION CMD ...
                c.argv.erase(c.argv.begin());
            }
            if (!c.argv.empty()) {
                c.exe = normalizeExe_(c.argv[0]);
                return runOne_(c);
            }
        }
        return "";
    }
    if (e=="reboot"||e=="shutdown"||e=="halt"||e=="poweroff") {
        last_status_ok_=false;
        return e+": Failed to set wall message: Operation not permitted\nFailed to reboot system via logind: Access denied\nFailed to open /dev/initctl: Permission denied\n";
    }
    if (e=="clear") return "\x1b[H\x1b[2J";
    if (e==":"||e=="true") return "";
    if (e=="false") { last_status_ok_=false; return ""; }

    // ----- Mirai/Gafgyt login probes & shell-cleanup commands -----
    // After successful telnet auth, Mirai sends:
    //   enable\nshell\nsh\n/bin/busybox MIRAI
    // The first three need to silently succeed (real BusyBox responds to
    // each by spawning a sub-shell that just exits). If we return
    // "command not found", the bot flags us as a honeypot and disconnects.
    if (e=="enable" || e=="shell" || e=="system" || e=="linuxshell") return "";
    // Bots clean up traces with these — silent success is correct.
    if (e=="unset" || e=="alias" || e=="unalias") return "";
    if (e=="ulimit" || e=="umask") return "";
    // FS-CR-4: shell builtins that bots use to set up reverse-shell file
    // descriptors. The most common pattern is `exec 5<>/dev/tcp/host/port;
    // cat <&5` (bash network builtin) — exec falls through to "command
    // not found" today, fingerprinting us. Silent success here makes the
    // bot's subshell continue; the forensic record is already logged via
    // detectReverseShell_ on c.raw, which catches the "/dev/tcp/" needle
    // regardless of how it was wrapped. Same reasoning for eval/source/
    // command/builtin: real shells silently treat them as evaluable
    // wrappers, and the inner content is what matters forensically.
    if (e=="exec" || e=="eval" || e=="source" || e=="." ||
        e=="command" || e=="builtin") return "";
    // dd is used both for system probing (`dd if=/dev/zero ...`) and as
    // a stager (`dd bs=52 count=1 if=.s of=/tmp/x`). Silent success +
    // optional file creation is enough for the bot's flow to continue.
    if (e=="dd") return cmdDd_(c);
    // Fake top one-shot — bots use `top -bn1` for recon.
    if (e=="top") return cmdTop_(c);

    // not found — use the persona's shell-specific format.
    // bash:    "-bash: <cmd>: command not found"
    // ash:     "<cmd>: not found"   (BusyBox / OpenWrt)
    // RouterOS: "bad command name <cmd> (line 1 column 1)"
    // …etc. See PersonaProfile::not_found_fmt.
    last_status_ok_ = false;
    last_was_unknown_cmd_ = true;
    const auto& profile = telnet_persona_profile(persona_);
    const char* fmt = profile.not_found_fmt
                          ? profile.not_found_fmt
                          : "-bash: %s: command not found\n";
    char buf[160];
    // Cap the cmd-name interpolation so an attacker pasting a 4 KB
    // "command" (real case: garbage from a binary echo) can't blow
    // the stack buffer.
    String name = c.argv[0];
    if (name.length() > 96) name = name.substring(0, 96);
    snprintf(buf, sizeof(buf), fmt, name.c_str());
    return String(buf);
}

// ===================== individual commands =====================

String FakeShell::cmdEcho_(Cmd& c) {
    bool n=false; bool e=false; size_t i=1;
    while (i<c.argv.size() && c.argv[i].length()>1 && c.argv[i][0]=='-') {
        // Real bash echo only recognises a *combination* of n/e/E in one flag;
        // any other char makes the whole token a literal. Good enough.
        const String& f = c.argv[i];
        bool ok = true;
        bool nn=false, ee=false, EE=false;
        for (size_t k=1;k<f.length();++k) {
            if (f[k]=='n') nn=true;
            else if (f[k]=='e') ee=true;
            else if (f[k]=='E') EE=true;
            else { ok=false; break; }
        }
        if (!ok) break;
        if (nn) n=true;
        if (ee) e=true;
        if (EE) e=false;
        ++i;
    }
    String r;
    auto interp = [](const String& in, String& out, bool& stop) {
        for (size_t k=0;k<in.length();++k) {
            char ch = in[k];
            if (ch != '\\' || k+1 >= in.length()) { out += ch; continue; }
            char nx = in[k+1];
            switch (nx) {
                case 'a': out += '\a'; k++; break;
                case 'b': out += '\b'; k++; break;
                case 'e': out += '\x1b'; k++; break;
                case 'f': out += '\f'; k++; break;
                case 'n': out += '\n'; k++; break;
                case 'r': out += '\r'; k++; break;
                case 't': out += '\t'; k++; break;
                case 'v': out += '\v'; k++; break;
                case '\\': out += '\\'; k++; break;
                case '0': {
                    // \0NNN — up to 3 octal digits after the literal '0'.
                    k++;
                    int v = 0, d = 0;
                    while (d < 3 && k+1 < in.length() &&
                           in[k+1] >= '0' && in[k+1] <= '7') {
                        v = v*8 + (in[k+1]-'0'); ++k; ++d;
                    }
                    out += (char)(v & 0xff);
                    break;
                }
                case 'x': {
                    // \xHH — 1 or 2 hex digits.
                    auto hex = [](char x)->int{
                        if (x>='0'&&x<='9') return x-'0';
                        if (x>='a'&&x<='f') return x-'a'+10;
                        if (x>='A'&&x<='F') return x-'A'+10;
                        return -1;
                    };
                    if (k+2 < in.length() && hex(in[k+2]) >= 0) {
                        int v = hex(in[k+2]);
                        k += 2;
                        if (k+1 < in.length() && hex(in[k+1]) >= 0) {
                            v = v*16 + hex(in[k+1]); ++k;
                        }
                        out += (char)(v & 0xff);
                    } else {
                        out += '\\'; out += 'x'; ++k;
                    }
                    break;
                }
                case 'c':
                    // \c — suppress trailing newline and stop processing.
                    stop = true;
                    return;
                default:
                    out += '\\'; out += nx; ++k; break;
            }
        }
    };
    bool stop = false;
    for (size_t j=i;j<c.argv.size();++j) {
        if (j>i) r+=' ';
        if (e) {
            String piece;
            interp(c.argv[j], piece, stop);
            r += piece;
            if (stop) { n = true; break; }
        } else {
            r += c.argv[j];
        }
    }
    if (!n) r+='\n';
    return r;
}

// Minimal `printf` — handles backslash escapes (\xHH, \NNN, \n, \t, \r, \\ ...)
// in the format string, and the most common conversions (%s %d %i %x %X %o %c
// %% %b). Argument list is recycled if more conversions than args, matching
// real bash printf semantics. No newline is appended automatically — that's
// what the format string is for.
String FakeShell::cmdPrintf_(Cmd& c) {
    if (c.argv.size() < 2) return "";
    auto hex = [](char x)->int{
        if (x>='0'&&x<='9') return x-'0';
        if (x>='a'&&x<='f') return x-'a'+10;
        if (x>='A'&&x<='F') return x-'A'+10;
        return -1;
    };
    auto interpEsc = [&](const String& in, String& out) {
        for (size_t k=0;k<in.length();++k) {
            char ch = in[k];
            if (ch != '\\' || k+1 >= in.length()) { out += ch; continue; }
            char nx = in[k+1];
            switch (nx) {
                case 'a': out += '\a'; ++k; break;
                case 'b': out += '\b'; ++k; break;
                case 'e': out += '\x1b'; ++k; break;
                case 'f': out += '\f'; ++k; break;
                case 'n': out += '\n'; ++k; break;
                case 'r': out += '\r'; ++k; break;
                case 't': out += '\t'; ++k; break;
                case 'v': out += '\v'; ++k; break;
                case '\\': out += '\\'; ++k; break;
                case '"': out += '"'; ++k; break;
                case '\'': out += '\''; ++k; break;
                case 'x': {
                    if (k+2 < in.length() && hex(in[k+2]) >= 0) {
                        int v = hex(in[k+2]); k += 2;
                        if (k+1 < in.length() && hex(in[k+1]) >= 0) {
                            v = v*16 + hex(in[k+1]); ++k;
                        }
                        out += (char)(v & 0xff);
                    } else { out += '\\'; out += 'x'; ++k; }
                    break;
                }
                default:
                    if (nx >= '0' && nx <= '7') {
                        int v = 0, d = 0;
                        while (d < 3 && k+1 < in.length() &&
                               in[k+1] >= '0' && in[k+1] <= '7') {
                            v = v*8 + (in[k+1]-'0'); ++k; ++d;
                        }
                        out += (char)(v & 0xff);
                    } else {
                        out += '\\'; out += nx; ++k;
                    }
                    break;
            }
        }
    };

    const String& fmt = c.argv[1];
    size_t arg = 2;
    String out;
    bool consumed_any = false;

    // printf cycles the format string until all args are consumed, with at
    // least one pass.
    do {
        consumed_any = false;
        for (size_t k=0;k<fmt.length();++k) {
            char ch = fmt[k];
            if (ch == '\\' && k+1 < fmt.length()) {
                String tmp; tmp += ch; tmp += fmt[k+1];
                size_t before = out.length();
                interpEsc(tmp, out);
                if (out.length() != before+2) ++k;  // consumed escape
                continue;
            }
            if (ch != '%') { out += ch; continue; }
            // Format spec: %[flags][width][.prec]conv
            size_t s = k+1;
            // Skip flags / width / precision — we ignore them but must advance.
            while (s < fmt.length() && (fmt[s]=='-'||fmt[s]=='+'||fmt[s]==' '||
                                        fmt[s]=='#'||fmt[s]=='0')) ++s;
            while (s < fmt.length() && fmt[s] >= '0' && fmt[s] <= '9') ++s;
            if (s < fmt.length() && fmt[s]=='.') {
                ++s;
                while (s < fmt.length() && fmt[s] >= '0' && fmt[s] <= '9') ++s;
            }
            if (s >= fmt.length()) { out += '%'; continue; }
            char conv = fmt[s];
            const String& a = (arg < c.argv.size()) ? c.argv[arg] : String("");
            switch (conv) {
                case '%': out += '%'; break;
                case 's': out += a; if (arg<c.argv.size()){++arg;consumed_any=true;} break;
                case 'b': {
                    String tmp; interpEsc(a, tmp); out += tmp;
                    if (arg<c.argv.size()){++arg;consumed_any=true;}
                    break;
                }
                case 'c':
                    if (a.length()) out += a[0];
                    if (arg<c.argv.size()){++arg;consumed_any=true;}
                    break;
                case 'd': case 'i': {
                    long v = a.toInt();
                    out += String(v);
                    if (arg<c.argv.size()){++arg;consumed_any=true;}
                    break;
                }
                case 'u': case 'x': case 'X': case 'o': {
                    unsigned long v = (unsigned long)a.toInt();
                    char buf[24];
                    const char* sp = (conv=='x') ? "%lx" :
                                     (conv=='X') ? "%lX" :
                                     (conv=='o') ? "%lo" : "%lu";
                    snprintf(buf, sizeof(buf), sp, v);
                    out += buf;
                    if (arg<c.argv.size()){++arg;consumed_any=true;}
                    break;
                }
                default:
                    // Unknown conversion: emit literally.
                    for (size_t q=k;q<=s;++q) out += fmt[q];
                    break;
            }
            k = s;
        }
    } while (arg < c.argv.size() && consumed_any);

    return out;
}

String FakeShell::cmdLs_(Cmd& c) {
    bool longf=false, all=false;
    String target;
    for (size_t i=1;i<c.argv.size();++i) {
        const String& a=c.argv[i];
        if (a.startsWith("-")) {
            if (a.indexOf('l')>=0) longf=true;
            if (a.indexOf('a')>=0) all=true;
        } else target=a;
    }
    String dir = resolvePath_(target.length()?target:cwd_);
    String out;
    std::vector<String> emitted;

    auto emit = [&](const String& name, bool is_dir, uint32_t sz){
        for (auto& n : emitted) if (n == name) return;
        emitted.push_back(name);
        if (longf) {
            String mode = is_dir ? "drwxr-xr-x" : "-rw-r--r--";
            out += mode; out += " 1 root root ";
            String ssz = String(sz);
            while (ssz.length()<6) ssz=" "+ssz;
            out += ssz; out += " Sep  4 09:14 "; out += name; out += "\n";
        } else { out += name; out += "  "; }
    };

    String home = (user_=="root") ? "/root" : ("/home/"+user_);
    if (dir == home) {
        if (all) { emit(".", true, 4096); emit("..", true, 4096); emit(".bash_history", false, 1024); emit(".bashrc", false, 3771); emit(".profile", false, 807); }
        emit(".cache", true, 4096);
        emit(".ssh", true, 4096);
    } else if (dir == home + "/.ssh") {
        if (all) { emit(".", true, 4096); emit("..", true, 4096); }
        emit("authorized_keys", false, 0);
        emit("known_hosts", false, 1776);
    } else if (dir == home + "/.cache") {
        if (all) { emit(".", true, 4096); emit("..", true, 4096); }
        emit("motd.legal-displayed", false, 0);
    } else if (dir == "/") {
        const char* roots[]={"bin","boot","dev","etc","home","lib","media","mnt","opt","proc","root","run","sbin","srv","sys","tmp","usr","var",nullptr};
        for (int j=0;roots[j];++j) emit(roots[j], true, 4096);
    } else if (dir == "/etc") {
        const char* es[]={"passwd","shadow","hostname","hosts","resolv.conf","os-release","issue","crontab","cron.d","cron.hourly","cron.daily","ssh","systemd","apt",nullptr};
        for (int j=0;es[j];++j) emit(es[j], (j>=8), j<8?(uint32_t)512:4096);
    } else if (dir == "/proc") {
        // Numeric pid dirs first (sorted by insertion order — good enough),
        // then the standard top-level pseudo-files real /proc exposes.
        for (auto& p : procs_) {
            emit(String(p.pid).c_str(), true, 0);
        }
        emit("self", true, 0);
        emit("thread-self", true, 0);
        const char* pf[]={"cpuinfo","meminfo","mounts","uptime","loadavg","stat",
            "version","cmdline","filesystems","modules","cgroups","crypto",
            "devices","diskstats","interrupts","kallsyms","keys","kmsg",
            "misc","partitions","sched_debug","slabinfo","softirqs","swaps",
            "sysrq-trigger","timer_list","vmallocinfo","vmstat","zoneinfo",
            "net","sys","tty","bus","driver","fs","irq","scsi", nullptr};
        for (int j=0;pf[j];++j) {
            bool d = (String(pf[j])=="net" || String(pf[j])=="sys" ||
                      String(pf[j])=="tty" || String(pf[j])=="bus" ||
                      String(pf[j])=="driver"||String(pf[j])=="fs" ||
                      String(pf[j])=="irq" || String(pf[j])=="scsi");
            emit(pf[j], d, d ? 0 : 0);
        }
    } else if (dir.startsWith("/proc/")) {
        // /proc/<pid> or /proc/self
        String pid_str, tail;
        if (parseProcPid_(dir, pid_str, tail) && tail.length() == 0) {
            const char* leaves[] = {
                "cmdline","comm","cwd","environ","exe","fd","io","limits",
                "loginuid","maps","mem","mountinfo","mounts","mountstats",
                "net","ns","oom_score","oom_score_adj","pagemap","personality",
                "root","sched","sessionid","setgroups","smaps","stack","stat",
                "statm","status","syscall","task","timers","wchan", nullptr };
            for (int j=0;leaves[j];++j) {
                bool d = (String(leaves[j])=="fd" || String(leaves[j])=="net" ||
                          String(leaves[j])=="ns" || String(leaves[j])=="task");
                emit(leaves[j], d, 0);
            }
        }
    } else if (dir == "/tmp" || dir == "/var/tmp" || dir == "/dev/shm") {
        if (all) { emit(".", true, 4096); emit("..", true, 4096); }
    } else if (!isDir_(dir)) {
        last_status_ok_=false;
        return "ls: cannot access '" + (target.length()?target:dir) + "': No such file or directory\n";
    } else {
        if (all) { emit(".", true, 4096); emit("..", true, 4096); }
    }
    // Always overlay any VFS files that live directly under `dir` — files the
    // attacker just `touch`ed or redirected into. Without this, attacker writes
    // appeared to vanish because the static directory branches above never
    // consulted the VFS.
    {
        String prefix = (dir == "/") ? String("/") : (dir + "/");
        size_t base = (dir == "/") ? 1 : (dir.length() + 1);
        for (auto& f : files_) {
            if (f.path.startsWith(prefix) && f.path.indexOf('/', base) < 0) {
                emit(basename_(f.path), f.is_dir, f.size);
            }
        }
    }
    if (!longf && out.length() && !out.endsWith("\n")) { out=trim(out); out+="\n"; }
    return out;
}

String FakeShell::cmdCd_(Cmd& c) {
    String t = (c.argv.size()<2) ? "~" : c.argv[1];
    String abs = resolvePath_(t);
    if (!isDir_(abs)) {
        last_status_ok_=false;
        return "-bash: cd: "+t+": No such file or directory\n";
    }
    cwd_ = abs;
    for (auto& kv : env_) if (kv.first=="PWD") kv.second = cwd_;
    return "";
}

const PersonaContent& FakeShell::personaContent_() const {
    return PERSONA_CONTENT[(int)persona_];
}

String FakeShell::passwdFile_() const { return personaContent_().passwd; }

bool FakeShell::procVirtualFile_(const String& abs, const Cmd& caller, String& out) const {
    const auto& pc = personaContent_();
    // Top-level /proc/* files first.
    if (abs == "/proc/cpuinfo")     { out += pc.cpuinfo;      return true; }
    if (abs == "/proc/meminfo")     { out += pc.meminfo;      return true; }
    if (abs == "/proc/mounts")      { out += pc.mounts;       return true; }
    if (abs == "/proc/version")     { out += pc.version_proc; return true; }
    if (abs == "/proc/uptime")      { out += FAKE_UPTIME_PROC; return true; }
    if (abs == "/proc/loadavg")     { out += FAKE_LOADAVG_PROC; return true; }
    if (abs == "/proc/stat")        { out += FAKE_STAT_PROC; return true; }
    if (abs == "/proc/filesystems") { out += FAKE_FILESYSTEMS_PROC; return true; }
    if (abs == "/proc/modules")     { out += FAKE_MODULES_PROC; return true; }
    if (abs == "/proc/cmdline")     { out += "BOOT_IMAGE=/boot/vmlinuz-4.15.0-142-generic root=UUID=01234567-89ab-cdef-0123-456789abcdef ro quiet splash\n"; return true; }
    if (abs == "/proc/version")     { out += "Linux version 4.15.0-142-generic (buildd@lcy01-amd64-006) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #146-Ubuntu SMP Tue Apr 13 01:11:19 UTC 2021\n"; return true; }
    if (abs == "/proc/net/route")   { out += FAKE_NET_ROUTE_PROC; return true; }
    if (abs == "/proc/net/tcp")     { out += FAKE_NET_TCP_PROC; return true; }
    if (abs == "/proc/net/tcp6")    { out += "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"; return true; }
    if (abs == "/proc/net/udp")     { out += FAKE_NET_UDP_PROC; return true; }
    if (abs == "/proc/net/udp6")    { out += "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"; return true; }
    if (abs == "/proc/net/dev")     { out += FAKE_NET_DEV_PROC; return true; }
    if (abs == "/proc/net/arp")     { out += FAKE_NET_ARP_PROC; return true; }
    if (abs == "/proc/net/unix")    { out += "Num       RefCount Protocol Flags    Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 12345 /run/systemd/private\n"; return true; }
    if (abs == "/proc/sys/kernel/hostname")  { out += host_; out += "\n"; return true; }
    if (abs == "/proc/sys/kernel/osrelease") { out += "4.15.0-142-generic\n"; return true; }
    if (abs == "/proc/sys/kernel/ostype")    { out += "Linux\n"; return true; }
    if (abs == "/proc/sys/kernel/version")   { out += "#146-Ubuntu SMP Tue Apr 13 01:11:19 UTC 2021\n"; return true; }
    if (abs == "/proc/sys/kernel/random/boot_id") { out += "0a1b2c3d-4e5f-6789-abcd-ef0123456789\n"; return true; }
    if (abs == "/proc/sys/kernel/random/uuid")    { out += "deadbeef-1234-5678-9abc-def012345678\n"; return true; }

    // Per-pid files: /proc/self/* or /proc/<pid>/*
    String pid_str, tail;
    if (!parseProcPid_(abs, pid_str, tail)) return false;

    // Resolve "self" to the current shell pid; build a synthetic FakeProcess
    // for the caller when emitting cmdline/comm/stat for /proc/self/* so the
    // attacker sees the actual command they just ran.
    bool is_self = (pid_str == "self");
    uint16_t pid = is_self ? kSelfPid : (uint16_t)toLongOr(pid_str, 0);
    if (pid == 0) return false;

    // Lookup process record.
    const FakeProcess* proc = nullptr;
    for (auto& p : procs_) if (p.pid == pid) { proc = &p; break; }

    // For /proc/self/* the "running process" is the cat/head/tail command
    // itself, not the parent shell. Synthesize a matching FakeProcess so
    // cmdline/comm/exe reflect the caller exactly (this is how a real
    // kernel resolves /proc/self at open(2) time).
    FakeProcess synth;
    if (is_self) {
        synth.pid  = kSelfPid;
        synth.user = user_;
        synth.tty  = "pts/0";
        // Reconstruct argv with spaces; cmdline emitter splits back to NULs.
        synth.cmd = caller.exe.length() ? caller.exe : caller.argv[0];
        for (size_t i = 1; i < caller.argv.size(); ++i) {
            synth.cmd += ' ';
            synth.cmd += caller.argv[i];
        }
        proc = &synth;
    }
    if (!proc) {
        // Unknown pid — same ENOENT path as a real kernel.
        return false;
    }

    if (tail == "" || tail == "/") {
        // Cat-ing the directory itself: real kernel returns EISDIR. Caller
        // will fall through to "Is a directory" message. Returning false
        // is fine; isDir_ also recognizes /proc/<pid> as a directory.
        return false;
    }

    if (tail == "cmdline") {
        // NUL-separated argv with trailing NUL, no newline. Terminals don't
        // render NUL so to the human eye they look concatenated; this is
        // exactly what a real Linux box prints.
        String c = proc->cmd;
        for (size_t i = 0; i < c.length(); ++i) {
            if (c[i] == ' ') out += '\0';
            else out += c[i];
        }
        out += '\0';
        return true;
    }
    if (tail == "comm") {
        // basename of argv[0], stripping any leading '-' (login shells).
        String c = proc->cmd;
        int sp = c.indexOf(' ');
        if (sp > 0) c = c.substring(0, sp);
        if (c.startsWith("-")) c = c.substring(1);
        int sl = c.lastIndexOf('/');
        if (sl >= 0) c = c.substring(sl + 1);
        out += c;
        out += '\n';
        return true;
    }
    if (tail == "status") {
        String comm; { Cmd cc; cc.argv.push_back("comm"); String t; procVirtualFile_("/proc/" + pid_str + "/comm", cc, t); comm = trim(t); }
        out += "Name:\t"; out += comm; out += "\n";
        out += "Umask:\t0022\n";
        out += "State:\tS (sleeping)\n";
        out += "Tgid:\t"; out += String(pid); out += "\n";
        out += "Ngid:\t0\n";
        out += "Pid:\t"; out += String(pid); out += "\n";
        out += "PPid:\t1\n";
        out += "TracerPid:\t0\n";
        out += "Uid:\t0\t0\t0\t0\n";
        out += "Gid:\t0\t0\t0\t0\n";
        out += "FDSize:\t64\n";
        out += "Groups:\t\n";
        out += "VmPeak:\t   "; out += String(proc->vsz); out += " kB\n";
        out += "VmSize:\t   "; out += String(proc->vsz); out += " kB\n";
        out += "VmRSS:\t   ";  out += String(proc->rss); out += " kB\n";
        out += "Threads:\t1\n";
        out += "SigQ:\t0/3795\n";
        out += "SigPnd:\t0000000000000000\n";
        out += "ShdPnd:\t0000000000000000\n";
        out += "SigBlk:\t0000000000010000\n";
        out += "SigIgn:\t0000000000384004\n";
        out += "SigCgt:\t000000004b817efb\n";
        out += "CapInh:\t0000000000000000\n";
        out += "CapPrm:\t0000003fffffffff\n";
        out += "CapEff:\t0000003fffffffff\n";
        out += "CapBnd:\t0000003fffffffff\n";
        out += "CapAmb:\t0000000000000000\n";
        out += "Cpus_allowed:\t1\n";
        out += "Cpus_allowed_list:\t0\n";
        out += "Mems_allowed:\t00000000,00000001\n";
        out += "Mems_allowed_list:\t0\n";
        out += "voluntary_ctxt_switches:\t42\n";
        out += "nonvoluntary_ctxt_switches:\t8\n";
        return true;
    }
    if (tail == "stat") {
        String comm; { Cmd cc; cc.argv.push_back("comm"); String t; procVirtualFile_("/proc/" + pid_str + "/comm", cc, t); comm = trim(t); }
        // Minimal /proc/<pid>/stat: 52 fields. Most bots only parse the
        // first few (pid, comm, state, ppid).
        out += String(pid); out += " (";
        out += comm; out += ") S 1 ";
        out += String(pid); out += " "; out += String(pid); out += " 34816 ";
        out += String(pid); out += " 4194304 142 0 0 0 1 0 0 0 20 0 1 0 1234 ";
        out += String(proc->vsz * 1024UL); out += " "; out += String(proc->rss); out += " 18446744073709551615 ";
        out += "94000000000000 94000000010000 140700000000 0 0 0 0 65536 1 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        return true;
    }
    if (tail == "statm") {
        out += String(proc->vsz / 4); out += " ";
        out += String(proc->rss / 4); out += " 256 32 0 128 0\n";
        return true;
    }
    if (tail == "environ") {
        // NUL-separated KEY=VAL pairs.
        for (auto& kv : env_) {
            out += kv.first; out += '='; out += kv.second; out += '\0';
        }
        return true;
    }
    if (tail == "loginuid") { out += "0"; return true; }
    if (tail == "sessionid") { out += "1\n"; return true; }
    if (tail == "oom_score") { out += "0\n"; return true; }
    if (tail == "oom_score_adj") { out += "0\n"; return true; }
    if (tail == "io") {
        out += "rchar: 1024\nwchar: 512\nsyscr: 8\nsyscw: 4\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";
        return true;
    }
    if (tail == "limits") {
        out += "Limit                     Soft Limit           Hard Limit           Units     \n"
               "Max cpu time              unlimited            unlimited            seconds   \n"
               "Max file size             unlimited            unlimited            bytes     \n"
               "Max data size             unlimited            unlimited            bytes     \n"
               "Max stack size            8388608              unlimited            bytes     \n"
               "Max core file size        0                    unlimited            bytes     \n"
               "Max resident set          unlimited            unlimited            bytes     \n"
               "Max processes             3795                 3795                 processes \n"
               "Max open files            1024                 4096                 files     \n"
               "Max locked memory         16777216             16777216             bytes     \n"
               "Max address space         unlimited            unlimited            bytes     \n"
               "Max file locks            unlimited            unlimited            locks     \n"
               "Max pending signals       3795                 3795                 signals   \n"
               "Max msgqueue size         819200               819200               bytes     \n"
               "Max nice priority         0                    0                    \n"
               "Max realtime priority     0                    0                    \n"
               "Max realtime timeout      unlimited            unlimited            us        \n";
        return true;
    }
    if (tail == "cgroup") { out += FAKE_CGROUP_PROC; return true; }
    if (tail == "maps") {
        // Trimmed maps for a typical small static binary.
        out += "00400000-0040b000 r-xp 00000000 08:01 131073                             /bin/cat\n"
               "0060a000-0060b000 r--p 0000a000 08:01 131073                             /bin/cat\n"
               "0060b000-0060c000 rw-p 0000b000 08:01 131073                             /bin/cat\n"
               "7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]\n"
               "7ffd00050000-7ffd00053000 r--p 00000000 00:00 0                          [vvar]\n"
               "7ffd00053000-7ffd00055000 r-xp 00000000 00:00 0                          [vdso]\n"
               "ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]\n";
        return true;
    }
    if (tail == "mounts") { out += personaContent_().mounts; return true; }
    if (tail == "mountinfo") {
        out += "23 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n"
               "24 28 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw\n"
               "25 28 0:6 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=494056k,nr_inodes=123514,mode=755\n"
               "28 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,errors=remount-ro,data=ordered\n";
        return true;
    }
    if (tail == "exe" || tail == "cwd" || tail == "root") {
        // These are symlinks; cat reads them as ENOENT in some kernels and
        // EACCES in others. Mirror the most common Ubuntu behavior — a
        // permission denied for non-owners; for self, cat happily follows
        // the symlink and prints the binary contents (we don't have those).
        // Easiest realistic answer: empty file (cat prints nothing).
        return true;
    }
    if (tail.startsWith("fd/") || tail == "fd") {
        // Skip — let caller report ENOENT for unknown fd entries.
        return false;
    }
    return false;
}

String FakeShell::cmdCat_(Cmd& c) {
    if (c.argv.size()<2) return "";
    String out;
    for (size_t i=1;i<c.argv.size();++i) {
        const String& arg=c.argv[i];
        if (arg.startsWith("-")) continue;
        String abs = resolvePath_(arg);
        const auto& pc = personaContent_();
        if (abs=="/etc/passwd") {
            if (pc.passwd[0]) { out += pc.passwd; }
            else { last_status_ok_ = false;
                   out += "cat: /etc/passwd: No such file or directory\n"; }
            continue;
        }
        if (abs=="/etc/shadow") {
            if (user_!="root") { last_status_ok_=false; out += "cat: /etc/shadow: Permission denied\n"; continue; }
            out += FAKE_SHADOW; continue;
        }
        if (abs=="/etc/os-release") {
            if (pc.os_release[0]) { out += pc.os_release; }
            else { last_status_ok_ = false;
                   out += "cat: /etc/os-release: No such file or directory\n"; }
            continue;
        }
        if (abs=="/etc/issue") {
            if (pc.issue[0]) out += pc.issue;
            // Empty-issue personas: cat returns silent empty (most embedded
            // boxes don't have /etc/issue at all).
            continue;
        }
        if (abs=="/etc/hostname")   { out += host_; out += "\n"; continue; }
        if (abs=="/etc/hosts")      {
            if (pc.hosts[0]) { out += pc.hosts; }
            else { last_status_ok_ = false;
                   out += "cat: /etc/hosts: No such file or directory\n"; }
            continue;
        }
        if (abs=="/etc/resolv.conf"){
            if (pc.resolv[0]) { out += pc.resolv; }
            else { last_status_ok_ = false;
                   out += "cat: /etc/resolv.conf: No such file or directory\n"; }
            continue;
        }
        if (abs=="/etc/machine-id") { out += "f3b1d4c2a5e74e8b9c1f0a2d3e4f5a6b\n"; continue; }
        if (abs=="/proc/net/route") {
            out += "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
            out += "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
            out += "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
            continue;
        }
        if (abs=="/proc/net/tcp") {
            out += "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
            out += "   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11842 1 0000000000000000 100 0 0 10 0\n";
            continue;
        }
        // /proc/* files (top-level + per-pid). procVirtualFile_ knows the
        // current cat invocation so /proc/self/cmdline reflects argv.
        {
            String poutbuf;
            if (procVirtualFile_(abs, c, poutbuf)) { out += poutbuf; continue; }
        }
        auto* vf = findFile_(abs);
        if (vf) { out += vf->content; continue; }
        // Stubbed home-dir files: list-empty rather than 404 so attackers see consistency
        String home = (user_=="root") ? "/root" : ("/home/"+user_);
        if (abs == home + "/.ssh/authorized_keys") continue; // empty file
        if (abs == home + "/.ssh/known_hosts") {
            out += "|1|abc123def456=|xyz789==|ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n";
            continue;
        }
        if (abs == home + "/.bash_history") {
            out += "ls\ncd\nuname -a\nps aux\nexit\n"; continue;
        }
        if (abs == home + "/.bashrc" || abs == home + "/.profile") {
            out += "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
                   "[ -z \"$PS1\" ] && return\nexport PATH=$PATH:/usr/local/bin\n";
            continue;
        }
        if (abs == home + "/.cache/motd.legal-displayed") continue;
        last_status_ok_=false;
        out += "cat: " + arg + ": No such file or directory\n";
    }
    return out;
}

String FakeShell::cmdHead_(Cmd& c, bool tail) {
    int n=10; size_t i=1;
    while (i<c.argv.size() && c.argv[i].startsWith("-")) {
        if (c.argv[i]=="-n" && i+1<c.argv.size()) { n=toLongOr(c.argv[i+1],10); i+=2; continue; }
        if (c.argv[i].startsWith("-") && c.argv[i].length()>1 && isdigit((unsigned char)c.argv[i][1])) {
            n = toLongOr(c.argv[i].substring(1), 10); ++i; continue;
        }
        ++i;
    }
    String all;
    for (; i<c.argv.size(); ++i) {
        Cmd cc=c; cc.argv.clear(); cc.argv.push_back("cat"); cc.argv.push_back(c.argv[i]);
        cc.exe="cat"; all += cmdCat_(cc);
    }
    if (!all.length()) return all;
    // split & cap
    std::vector<String> lines;
    int start=0;
    for (int k=0;k<(int)all.length();++k) if (all[k]=='\n') { lines.push_back(all.substring(start,k)); start=k+1; }
    if (start<(int)all.length()) lines.push_back(all.substring(start));
    String r;
    if (!tail) {
        for (int k=0;k<min((int)lines.size(),n);++k) { r+=lines[k]; r+="\n"; }
    } else {
        int s = max(0, (int)lines.size()-n);
        for (int k=s;k<(int)lines.size();++k) { r+=lines[k]; r+="\n"; }
    }
    return r;
}

String FakeShell::cmdGrep_(Cmd& c) {
    if (c.argv.size()<3) return "";
    String pat;
    size_t i=1;
    while (i<c.argv.size() && c.argv[i].startsWith("-")) ++i;
    if (i>=c.argv.size()) return "";
    pat = c.argv[i++]; pat.toLowerCase();
    String r;
    for (;i<c.argv.size();++i) {
        Cmd cc; cc.argv.push_back("cat"); cc.argv.push_back(c.argv[i]); cc.exe="cat";
        String body = cmdCat_(cc);
        int s=0;
        for (int k=0;k<(int)body.length();++k) {
            if (body[k]=='\n') {
                String ln = body.substring(s,k); String low=ln; low.toLowerCase();
                if (low.indexOf(pat)>=0) { r+=ln; r+='\n'; }
                s=k+1;
            }
        }
    }
    if (!r.length()) last_status_ok_=false;
    return r;
}

String FakeShell::cmdWc_(Cmd& c) {
    if (c.argv.size()<2) return "";
    String r;
    for (size_t i=1;i<c.argv.size();++i) {
        if (c.argv[i].startsWith("-")) continue;
        Cmd cc; cc.argv.push_back("cat"); cc.argv.push_back(c.argv[i]); cc.exe="cat";
        String body = cmdCat_(cc);
        int lines=0, words=0, bytes=body.length();
        for (int k=0;k<(int)body.length();++k) if (body[k]=='\n') ++lines;
        bool inw=false;
        for (int k=0;k<(int)body.length();++k) {
            bool sp=isspace((unsigned char)body[k]);
            if (!sp && !inw) { ++words; inw=true; }
            if (sp) inw=false;
        }
        char buf[64]; snprintf(buf,sizeof(buf),"%d %d %d ", lines, words, bytes);
        r += buf; r += c.argv[i]; r += '\n';
    }
    return r;
}

String FakeShell::cmdBase64_(Cmd& c) {
    bool dec=false;
    for (auto& a : c.argv) if (a=="-d"||a=="--decode") dec=true;
    if (dec) return "";
    return "";
}

String FakeShell::cmdUname_(Cmd& c) {
    bool a=false,s=false,r=false,m=false,n=false,p=false,o=false;
    if (c.argv.size()<2) s=true;
    for (size_t i=1;i<c.argv.size();++i) {
        const String& x=c.argv[i];
        if (x=="-a") a=true;
        else if (x=="-s") s=true;
        else if (x=="-r") r=true;
        else if (x=="-m") m=true;
        else if (x=="-n") n=true;
        else if (x=="-p") p=true;
        else if (x=="-o") o=true;
    }
    const auto& pc = personaContent_();
    // RouterOS persona has empty uname strings — uname isn't a thing on
    // RouterOS. Real RouterOS would give "bad command name uname",
    // which the persona-aware not-found path emits. For all other
    // personas, fall through to the per-flag assembly with persona-
    // faithful kernel/arch/uname_a fields.
    if (a && pc.uname_a[0]) return String(pc.uname_a) + "\n";
    String out;
    if (s) out += "Linux";
    if (n) { if (out.length()) out+=' '; out+=host_; }
    if (r) { if (out.length()) out+=' '; out+=pc.uname_kernel; }
    if (m) { if (out.length()) out+=' '; out+=pc.uname_arch; }
    if (p) { if (out.length()) out+=' '; out+=pc.uname_arch; }
    if (o) { if (out.length()) out+=' '; out+="GNU/Linux"; }
    out+="\n"; return out;
}

String FakeShell::cmdId_(Cmd& c) {
    String t = (c.argv.size()>=2 && !c.argv[1].startsWith("-")) ? c.argv[1] : user_;
    if (t=="root") return "uid=0(root) gid=0(root) groups=0(root)\n";
    return "uid=1000(" + t + ") gid=1000(" + t + ") groups=1000(" + t + "),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)\n";
}

String FakeShell::cmdPs_(Cmd& c) {
    bool aux=false, ef=false;
    for (auto& a : c.argv) {
        if (a.indexOf('a')>=0 && a.indexOf('u')>=0 && a.indexOf('x')>=0) aux=true;
        if (a=="-ef"||a=="ef") ef=true;
    }
    String out;
    if (aux) {
        out += "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n";
        for (auto& p : procs_) {
            char buf[256];
            snprintf(buf,sizeof(buf),"%-10s %5u  0.0  0.1  %6u  %4u %-8s Ss   09:14   0:00 ",
                     p.user.c_str(), p.pid, p.vsz, p.rss, p.tty.c_str());
            out += buf; out += p.cmd; out += "\n";
        }
    } else if (ef) {
        out += "UID        PID  PPID  C STIME TTY          TIME CMD\n";
        for (auto& p : procs_) {
            char buf[256];
            snprintf(buf,sizeof(buf),"%-10s %5u %5u  0 09:14 %-12s 00:00:00 ",
                     p.user.c_str(), p.pid, (unsigned)1, p.tty.c_str());
            out += buf; out += p.cmd; out += "\n";
        }
    } else {
        out += "  PID TTY          TIME CMD\n";
        for (auto& p : procs_) if (p.tty.startsWith("pts")||p.tty=="tty1") {
            char buf[64]; snprintf(buf,sizeof(buf),"%5u %-12s 00:00:00 ",p.pid,p.tty.c_str());
            out += buf; out += p.cmd; out += "\n";
        }
    }
    return out;
}

String FakeShell::cmdNetstat_(Cmd& c) {
    (void)c;
    return
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN\n"
        "tcp        0      0 10.0.0.42:22            "+src_ip_+":"+String(src_port_)+"          ESTABLISHED\n"
        "tcp6       0      0 :::22                   :::*                    LISTEN\n";
}

String FakeShell::cmdSs_(Cmd& c) { return cmdNetstat_(c); }

String FakeShell::cmdIfconfig_(Cmd& c) {
    (void)c;
    return
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        "        inet6 fe80::216:3eff:fe0a:b1c2  prefixlen 64  scopeid 0x20<link>\n"
        "        ether 00:16:3e:0a:b1:c2  txqueuelen 1000  (Ethernet)\n"
        "        RX packets 18234  bytes 21438211 (21.4 MB)\n"
        "        TX packets 11201  bytes 1733122 (1.7 MB)\n\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
        "        loop  txqueuelen 1000  (Local Loopback)\n";
}

String FakeShell::cmdIp_(Cmd& c) {
    if (c.argv.size()>=2 && (c.argv[1]=="a"||c.argv[1]=="addr"||c.argv[1]=="address")) {
        return
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "       valid_lft forever preferred_lft forever\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
        "    link/ether 00:16:3e:0a:b1:c2 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 10.0.0.42/24 brd 10.0.0.255 scope global eth0\n"
        "       valid_lft forever preferred_lft forever\n";
    }
    if (c.argv.size()>=2 && (c.argv[1]=="r"||c.argv[1]=="route")) return cmdRoute_(c);
    return "";
}

String FakeShell::cmdRoute_(Cmd& c) {
    (void)c;
    return
        "Kernel IP routing table\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
        "0.0.0.0         10.0.0.1        0.0.0.0         UG    100    0        0 eth0\n"
        "10.0.0.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0\n";
}

String FakeShell::cmdDf_(Cmd& c) {
    bool h=false; for (auto& a : c.argv) if (a=="-h"||a=="-Th") h=true;
    if (h) return
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "udev            483M     0  483M   0% /dev\n"
        "tmpfs            99M  6.6M   92M   7% /run\n"
        "/dev/vda1        20G  4.7G   15G  24% /\n"
        "tmpfs           493M     0  493M   0% /dev/shm\n"
        "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
        "tmpfs           493M     0  493M   0% /sys/fs/cgroup\n"
        "tmpfs            99M     0   99M   0% /run/user/0\n";
    return
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        "udev              494056       0    494056   0% /dev\n"
        "tmpfs             101000    6792     94208   7% /run\n"
        "/dev/vda1       20511356 4901324  15593648  24% /\n";
}

String FakeShell::cmdFree_(Cmd& c) {
    bool h=false,m=false; for (auto& a : c.argv) { if (a=="-h") h=true; if (a=="-m") m=true; }
    if (h) return
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:           986M        274M        117M        6.4M        595M        687M\n"
        "Swap:            0B          0B          0B\n";
    if (m) return
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:            986         274         117           6         595         687\n"
        "Swap:             0           0           0\n";
    return
        "              total        used        free      shared  buff/cache   available\n"
        "Mem:        1009856      280144      120432        6604      609280      703616\n"
        "Swap:             0           0           0\n";
}

String FakeShell::cmdUptime_(Cmd& c) {
    (void)c;
    return " 09:14:21 up 14 days,  3:42,  1 user,  load average: 0.08, 0.03, 0.01\n";
}
String FakeShell::cmdW_(Cmd& c) {
    (void)c;
    return
        " 09:14:21 up 14 days,  3:42,  1 user,  load average: 0.08, 0.03, 0.01\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        "root     pts/0    "+pad(src_ip_,15)+"  09:14    0.00s  0.04s  0.00s -bash\n";
}
String FakeShell::cmdLast_(Cmd& c) {
    (void)c;
    return
        "root     pts/0        "+src_ip_+"     Mon Sep  4 09:14   still logged in\n"
        "root     pts/0        10.0.0.5         Sun Sep  3 22:01 - 22:43  (00:42)\n"
        "reboot   system boot  4.15.0-142-gener Sun Aug 20 09:32   still running\n\n"
        "wtmp begins Sun Aug 20 09:32:14 2023\n";
}
String FakeShell::cmdMount_(Cmd& c) { (void)c; return personaContent_().mounts; }
String FakeShell::cmdLscpu_(Cmd& c) {
    (void)c;
    return
        "Architecture:        x86_64\n"
        "CPU op-mode(s):      32-bit, 64-bit\n"
        "Byte Order:          Little Endian\n"
        "CPU(s):              1\n"
        "On-line CPU(s) list: 0\n"
        "Thread(s) per core:  1\n"
        "Core(s) per socket:  1\n"
        "Socket(s):           1\n"
        "Vendor ID:           GenuineIntel\n"
        "CPU family:          6\n"
        "Model:               79\n"
        "Model name:          Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        "Stepping:            1\n"
        "CPU MHz:             2399.998\n"
        "BogoMIPS:            4799.99\n"
        "Hypervisor vendor:   KVM\n"
        "Virtualization type: full\n";
}

String FakeShell::cmdEnv_(Cmd& c) {
    (void)c;
    String r;
    for (auto& kv : env_) { r+=kv.first; r+='='; r+=kv.second; r+='\n'; }
    return r;
}
String FakeShell::cmdExport_(Cmd& c) {
    if (c.argv.size()<2) return cmdEnv_(c);
    for (size_t i=1;i<c.argv.size();++i) {
        int eq = c.argv[i].indexOf('=');
        if (eq>0) {
            String k=c.argv[i].substring(0,eq), v=c.argv[i].substring(eq+1);
            bool found=false;
            for (auto& kv : env_) if (kv.first==k) { kv.second=v; found=true; break; }
            if (!found) env_.push_back({k,v});
        }
    }
    return "";
}
String FakeShell::cmdHistory_(Cmd& c) {
    (void)c;
    String r;
    for (size_t i=0;i<history_.size();++i) {
        char buf[16]; snprintf(buf,sizeof(buf),"%5u  ",(unsigned)(i+1));
        r+=buf; r+=history_[i]; r+='\n';
    }
    return r;
}

// ----- wget/curl -----

static String parseDownloadUrl(const std::vector<String>& argv, String& outFile, bool& silent) {
    String url, file; silent=false;
    for (size_t i=1;i<argv.size();++i) {
        const String& a=argv[i];
        if (a=="-O" || a=="-o" || a=="--output-document" || a=="--output") {
            if (i+1<argv.size()) { file = argv[i+1]; ++i; }
            continue;
        }
        if (a.startsWith("-O")) { file=a.substring(2); continue; }
        if (a=="-q"||a=="--quiet"||a=="-s"||a=="--silent") { silent=true; continue; }
        if (a=="-fsSL"||a=="-sSL"||a=="-Lf"||a=="-fSL") { silent=true; continue; }
        if (a.startsWith("-")) continue;
        if (a.startsWith("http://")||a.startsWith("https://")||a.startsWith("ftp://")||a.startsWith("tftp://")) {
            url = a;
        }
    }
    if (!file.length() && url.length()) {
        int s = url.lastIndexOf('/');
        file = (s>=0) ? url.substring(s+1) : url;
        if (!file.length()) file = "index.html";
    }
    outFile = file;
    return url;
}

// Quick IPv4/IPv6 literal check. We don't validate octet ranges —
// just decide "is this a hostname or already an IP?". Real wget
// short-circuits DNS when given a literal IP, and not mimicking that
// is a strong fingerprint that the shell isn't real.
static bool isIpLiteral_(const String& s) {
    if (s.indexOf(':') >= 0) return true;  // any colon → assume IPv6
    int dots = 0;
    for (size_t i = 0; i < s.length(); ++i) {
        char ch = s[i];
        if (ch == '.') dots++;
        else if (ch < '0' || ch > '9') return false;
    }
    return dots == 3;
}

// Stable-looking fake IP derived from a hostname hash. Used in the
// wget "Resolving" line so each hostname always reports the same
// IP across the session, instead of the previous hardcoded
// 185.199.108.133 (GitHub Pages, an obvious tell). FNV-1a is enough
// distribution for cosmetic purposes. Output is in the 185.x.x.x
// space — looks routable, no collision with any specific
// well-known site.
static String hashedFakeIp_(const String& host) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < host.length(); ++i) {
        h ^= (unsigned char)host[i];
        h *= 16777619u;
    }
    char buf[20];
    snprintf(buf, sizeof(buf), "185.%u.%u.%u",
             (unsigned)((h >> 16) & 0xff),
             (unsigned)((h >>  8) & 0xff),
             (unsigned)((h      ) & 0xff));
    return String(buf);
}

// Format a "--YYYY-MM-DD HH:MM:SS--" wget log prefix. Uses real
// local time when NTP is synced; falls back to a frozen value
// otherwise. The previous hardcoded "2023-09-04 09:14:21" is a
// fingerprint when seen on a 2026 capture.
static String wgetTimestampPrefix_() {
    time_t now = time(nullptr);
    if (now > 1700000000) {
        struct tm tm; localtime_r(&now, &tm);
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
        return String(buf);
    }
    return String("2024-11-01 12:00:00");
}

String FakeShell::cmdWget_(Cmd& c) {
    String file; bool silent=false;
    String url = parseDownloadUrl(c.argv, file, silent);
    if (!url.length()) {
        last_status_ok_=false;
        return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n";
    }
    String dst = file.startsWith("/") ? file : (cwd_+"/"+file);
    String abs = resolvePath_(dst);
    String dir = abs.substring(0, abs.lastIndexOf('/')+1);
    if (!isWritableDir_(dir)) abs = "/tmp/" + basename_(file);
    VirtualFile* vf = createFile_(abs, "wget");
    String arch = guessArch_(url+" "+file);
    String prof = guessProfile_(url, file);
    if (vf) {
        vf->source_url = url;
        vf->arch = arch;
        vf->payload_profile = prof;
        vf->size = 8192 + (millis() & 0xfff);
        vf->mode = 0644;
        vf->mtime_ms = millis();
    }
    StaticJsonDocument<384> d;
    d["url"]=url; d["file"]=abs; d["tool"]="wget";
    d["arch"]=arch; d["profile"]=prof;
    String body; serializeJson(d, body);
    logEvent_("download_url", body);

    if (silent) return "";

    // Extract host from URL for the connect line. Strip <scheme>://
    // and any /path or :port suffix.
    int slashslash = url.indexOf("//");
    String host = (slashslash>=0) ? url.substring(slashslash+2) : url;
    int sl = host.indexOf('/'); if (sl>0) host = host.substring(0,sl);
    // Strip optional :port for the resolve/connect lines (they show
    // host without port; the actual connect line includes it
    // separately).
    String host_only = host;
    int hostcolon = host_only.indexOf(':');
    if (hostcolon > 0) host_only = host_only.substring(0, hostcolon);
    bool is_https = url.startsWith("https://") || url.startsWith("HTTPS://");
    String port_str = is_https ? "443" : "80";
    uint32_t fsize = vf ? vf->size : 8192;

    // BusyBox wget emits a much terser dialogue than GNU wget: no
    // "HTTP request sent / Saving to:" block, no "--YYYY-MM-DD ..." log
    // prefix, no `(MB/s) - 'file' saved [size/size]` final line. Bots
    // that key off these lines treat their absence as a tell, so when
    // we're invoked via `busybox wget` (any persona) OR the persona's
    // wget is itself busybox (BusyBox / OpenWrt / DVRDVS / HiLinux),
    // emit busybox 1.35-flavored output instead.
    bool busybox_style = in_busybox_call_ ||
                         persona_ == TelnetPersona::BusyBox ||
                         persona_ == TelnetPersona::OpenWrt ||
                         persona_ == TelnetPersona::DVRDVS ||
                         persona_ == TelnetPersona::HiLinux;

    if (busybox_style) {
        String r;
        if (isIpLiteral_(host_only)) {
            r += "Connecting to "+host_only+" ("+host_only+":"+port_str+")\n";
        } else {
            String resolved = hashedFakeIp_(host_only);
            r += "Connecting to "+host_only+" ("+resolved+":"+port_str+")\n";
        }
        if (is_https) {
            // Real busybox wget on a stripped-down build either rejects
            // HTTPS outright or emits this note before plain-text fallback.
            // We pick the second form so the "saved" path still fires.
            r += "wget: note: TLS certificate validation not implemented\n";
        }
        r += "saving to '"+basename_(abs)+"'\n";
        // Progress line — busybox formats the bar with simple `*` chars
        // and shows a fixed "0:00:00 ETA" since we don't model timing.
        // The width here matches the columns commonly seen in real
        // busybox output (32-char bar).
        char prog[160];
        snprintf(prog, sizeof(prog),
                 "%-19s100%% |********************************| %5u  0:00:00 ETA\n",
                 basename_(abs).c_str(), (unsigned)fsize);
        r += prog;
        r += "'"+basename_(abs)+"' saved\n";
        return r;
    }

    String ts = wgetTimestampPrefix_();
    String r;
    r += "--"; r += ts; r += "--  "; r += url; r += "\n";
    if (isIpLiteral_(host_only)) {
        // Real wget given an IP URL skips DNS entirely — no
        // "Resolving" line, and the connect line uses the bare IP
        // without the |resolved-ip| pipe form.
        r += "Connecting to "+host_only+":"+port_str+"... connected.\n";
    } else {
        String resolved = hashedFakeIp_(host_only);
        r += "Resolving "+host_only+" ("+host_only+")... "+resolved+"\n";
        r += "Connecting to "+host_only+" ("+host_only+")|"+resolved+"|:"+port_str+"... connected.\n";
    }
    r += "HTTP request sent, awaiting response... 200 OK\n";
    r += "Length: "+String(fsize)+" (8.0K) [application/octet-stream]\n";
    r += "Saving to: '"+basename_(abs)+"'\n\n";
    r += basename_(abs)+"     100%[===================>]   8.00K  --.-KB/s    in 0s\n\n";
    r += ts+" (12.4 MB/s) - '"+basename_(abs)+"' saved ["+String(fsize)+"/"+String(fsize)+"]\n\n";
    return r;
}

String FakeShell::cmdCurl_(Cmd& c) {
    String file; bool silent=false;
    String url = parseDownloadUrl(c.argv, file, silent);
    if (!url.length()) { last_status_ok_=false; return "curl: try 'curl --help' for more information\n"; }
    bool to_stdout = true;
    for (size_t i=1;i<c.argv.size();++i) if (c.argv[i]=="-o"||c.argv[i]=="-O"||c.argv[i].startsWith("-O")) to_stdout=false;
    String abs;
    if (!to_stdout) {
        String dst = file.startsWith("/") ? file : (cwd_+"/"+file);
        abs = resolvePath_(dst);
        String dir = abs.substring(0, abs.lastIndexOf('/')+1);
        if (!isWritableDir_(dir)) abs = "/tmp/" + basename_(file);
        VirtualFile* vf = createFile_(abs, "curl");
        if (vf) {
            vf->source_url = url;
            vf->arch = guessArch_(url+" "+file);
            vf->payload_profile = guessProfile_(url, file);
            vf->size = 8192 + (millis() & 0xfff);
        }
    }
    StaticJsonDocument<384> d;
    d["url"]=url; d["file"]=abs.length()?abs:String("-");
    d["tool"]="curl"; d["arch"]=guessArch_(url+" "+file); d["profile"]=guessProfile_(url, file);
    String body; serializeJson(d, body);
    logEvent_("download_url", body);

    if (silent) return "";
    if (!to_stdout) return "";
    // print fake script content if URL ends in .sh — keeps "curl ... | sh" attackers engaged
    String low = url; low.toLowerCase();
    if (low.endsWith(".sh")) {
        return "#!/bin/sh\n# fake remote script\nexit 0\n";
    }
    return "";
}

// ----- tftp / ftpget / nc (Mirai/Gafgyt downloader fallbacks) -----
//
// Real Mirai stagers loop over wget → curl → tftp → ftpget → echo-bytes.
// On a real busy box-Linux all of these silently succeed; emulating that
// keeps the bot's flow advancing past `chmod 777 X` and `./X` so we can
// log the full payload-execution sequence. Output mimics the real tools'
// behavior on success (silent) and only complains when the caller passed
// no arguments at all.

String FakeShell::cmdTftp_(Cmd& c) {
    // Common attacker syntaxes:
    //   tftp HOST -c get FILE
    //   tftp -g -r FILE HOST              (busybox tftp)
    //   tftp -i HOST GET FILE FILE
    String host, file;
    for (size_t i = 1; i < c.argv.size(); ++i) {
        const String& a = c.argv[i];
        if (a == "-c" || a == "-i" || a == "-g" || a == "-p" || a == "-v") continue;
        if (a == "-r" || a == "-l") {
            if (i + 1 < c.argv.size()) { file = c.argv[i + 1]; ++i; }
            continue;
        }
        if (a.equalsIgnoreCase("get") || a.equalsIgnoreCase("put") ||
            a.equalsIgnoreCase("GET") || a.equalsIgnoreCase("PUT")) continue;
        if (a.startsWith("-")) continue;
        // First non-flag token that looks like a host (has a dot, no slash)
        // is the server; the remaining one is the filename.
        if (!host.length() && a.indexOf('/') < 0 && a.indexOf('.') >= 0) { host = a; continue; }
        if (!file.length()) { file = a; continue; }
    }
    if (!host.length() && !file.length()) {
        last_status_ok_ = false;
        return "tftp: usage: tftp [-i] HOST [GET|PUT] SRC [DST]\n";
    }
    if (!file.length()) file = "tftp.bin";
    String dst = file.startsWith("/") ? file : (cwd_ + "/" + file);
    String abs = resolvePath_(dst);
    String dir = abs.substring(0, abs.lastIndexOf('/') + 1);
    if (!isWritableDir_(dir)) abs = "/tmp/" + basename_(file);
    String url = "tftp://" + host + "/" + basename_(file);
    VirtualFile* vf = createFile_(abs, "tftp");
    String arch = guessArch_(url + " " + file);
    String prof = guessProfile_(url, file);
    if (vf) {
        vf->source_url = url;
        vf->arch = arch;
        vf->payload_profile = prof;
        vf->size = 8192 + (millis() & 0xfff);
        vf->mode = 0644;
        vf->mtime_ms = millis();
    }
    StaticJsonDocument<384> d;
    d["url"] = url; d["file"] = abs; d["tool"] = "tftp";
    d["arch"] = arch; d["profile"] = prof;
    String body; serializeJson(d, body);
    logEvent_("download_url", body);
    return "";  // real tftp client is silent on success
}

String FakeShell::cmdFtpget_(Cmd& c) {
    // busybox ftpget [-cvi] [-u USER] [-p PASS] [-P PORT] HOST LOCAL [REMOTE]
    String host, local, remote;
    for (size_t i = 1; i < c.argv.size(); ++i) {
        const String& a = c.argv[i];
        if (a == "-u" || a == "-p" || a == "-P") {
            if (i + 1 < c.argv.size()) ++i;
            continue;
        }
        if (a.startsWith("-")) continue;
        if (!host.length()) { host = a; continue; }
        if (!local.length()) { local = a; continue; }
        if (!remote.length()) { remote = a; continue; }
    }
    if (!host.length() || !local.length()) {
        last_status_ok_ = false;
        return "ftpget: usage: ftpget [-cvi] [-u USER] [-p PASS] HOST LOCAL [REMOTE]\n";
    }
    if (!remote.length()) remote = local;
    String dst = local.startsWith("/") ? local : (cwd_ + "/" + local);
    String abs = resolvePath_(dst);
    String dir = abs.substring(0, abs.lastIndexOf('/') + 1);
    if (!isWritableDir_(dir)) abs = "/tmp/" + basename_(local);
    String url = "ftp://" + host + "/" + remote;
    VirtualFile* vf = createFile_(abs, "ftpget");
    String arch = guessArch_(url + " " + local);
    String prof = guessProfile_(url, local);
    if (vf) {
        vf->source_url = url;
        vf->arch = arch;
        vf->payload_profile = prof;
        vf->size = 8192 + (millis() & 0xfff);
        vf->mode = 0644;
        vf->mtime_ms = millis();
    }
    StaticJsonDocument<384> d;
    d["url"] = url; d["file"] = abs; d["tool"] = "ftpget";
    d["arch"] = arch; d["profile"] = prof;
    String body; serializeJson(d, body);
    logEvent_("download_url", body);
    return "";
}

// ----- dd / top (bot recon + binary stager) -----

String FakeShell::cmdDd_(Cmd& c) {
    // Mirai uses dd both as a recon tool ('dd if=/dev/zero bs=...') and as
    // a binary stager ('dd if=stage of=/tmp/x bs=52 count=1'). Parse just
    // the if=/of=/bs=/count= keys; create the of= file if any.
    String inp, outp; uint32_t bs = 512, cnt = 0;
    for (size_t i = 1; i < c.argv.size(); ++i) {
        const String& a = c.argv[i];
        if (a.startsWith("if="))    inp = a.substring(3);
        else if (a.startsWith("of=")) outp = a.substring(3);
        else if (a.startsWith("bs="))    bs    = (uint32_t)toLongOr(a.substring(3), 512);
        else if (a.startsWith("count=")) cnt   = (uint32_t)toLongOr(a.substring(6), 0);
    }
    if (outp.length()) {
        String dst = outp.startsWith("/") ? outp : (cwd_ + "/" + outp);
        String abs = resolvePath_(dst);
        String dir = abs.substring(0, abs.lastIndexOf('/') + 1);
        if (!isWritableDir_(dir)) abs = "/tmp/" + basename_(outp);
        VirtualFile* vf = createFile_(abs, "dd");
        if (vf) {
            vf->size = (cnt > 0) ? (bs * cnt) : bs;
            vf->mode = 0644;
            vf->mtime_ms = millis();
        }
        StaticJsonDocument<256> d;
        d["if"] = inp; d["of"] = abs; d["bs"] = bs; d["count"] = cnt;
        String body; serializeJson(d, body);
        logEvent_("dd", body);
    }
    // Real dd prints to stderr lines like:
    //   1+0 records in
    //   1+0 records out
    //   52 bytes copied, 0.000123 s, 421 kB/s
    //
    // Synthesise plausible-but-varying time / throughput rather
    // than the hardcoded "0.000123 s, 421 kB/s" — bots that run
    // dd repeatedly and compare outputs would otherwise fingerprint
    // the constant. We pretend a 1-MB/s write rate (slow flash, NVR
    // class) with a small per-call jitter.
    uint32_t bytes = (cnt > 0) ? (bs * cnt) : bs;
    // ~1 MB/s with ±12 % jitter from a hash of bytes + millis.
    uint32_t jitter = ((bytes * 2654435761u) ^ (uint32_t)millis()) & 0xff;
    uint32_t kbps   = 900 + (jitter % 240);            // 900..1140 kB/s
    uint32_t us     = (uint32_t)((uint64_t)bytes * 1000u / kbps); // micros at that rate
    if (us == 0) us = 1;
    char tail[64];
    snprintf(tail, sizeof(tail), "%u bytes copied, %u.%06u s, %u.%u kB/s\n",
             (unsigned)bytes,
             (unsigned)(us / 1000000u),
             (unsigned)(us % 1000000u),
             (unsigned)(kbps / 10), (unsigned)(kbps % 10));
    String out;
    out.reserve(96);
    out += String(cnt > 0 ? cnt : 1) + "+0 records in\n";
    out += String(cnt > 0 ? cnt : 1) + "+0 records out\n";
    out += tail;
    return out;
}

String FakeShell::cmdTop_(Cmd& c) {
    (void)c;
    // Mirai/Gafgyt recon uses `top -bn1`. Real top's batch mode prints a
    // header + a process list. Keep it short — we just need to be plausible.
    String r;
    r.reserve(640);
    r += "top - 09:14:21 up  3:42,  1 user,  load average: 0.04, 0.07, 0.05\n";
    r += "Tasks:  73 total,   1 running,  72 sleeping,   0 stopped,   0 zombie\n";
    r += "%Cpu(s):  0.4 us,  0.7 sy,  0.0 ni, 98.7 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st\n";
    r += "MiB Mem :    972.5 total,    481.2 free,    192.4 used,    298.9 buff/cache\n";
    r += "MiB Swap:      0.0 total,      0.0 free,      0.0 used.    657.8 avail Mem\n\n";
    r += "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n";
    r += "      1 root      20   0  168432  11856   8404 S   0.0   1.2   0:01.45 systemd\n";
    r += "    412 root      20   0   71024   6112   5516 S   0.0   0.6   0:00.21 sshd\n";
    r += "    433 root      20   0   13508   3892   3296 R   0.3   0.4   0:00.04 top\n";
    return r;
}

// ----- chmod/chown/rm/mkdir/touch/mv/cp -----

String FakeShell::cmdChmod_(Cmd& c) {
    if (c.argv.size()<3) return "";
    String mode = c.argv[1];
    bool exec = (mode.indexOf("+x")>=0||mode.indexOf("a+x")>=0||mode.indexOf("u+x")>=0||
                 mode=="755"||mode=="0755"||mode=="777"||mode=="0777"||mode=="700"||mode=="0700"||mode=="555");
    for (size_t i=2;i<c.argv.size();++i) {
        String abs = resolvePath_(c.argv[i]);
        VirtualFile* vf = findFile_(abs);
        if (!vf) vf = createFile_(abs, "chmod");
        if (vf) { vf->executable = exec ? true : vf->executable; vf->mode = (uint16_t)toLongOr(mode,0644); }
        StaticJsonDocument<256> d;
        d["path"]=abs; d["mode"]=mode; d["executable"]=exec;
        String body; serializeJson(d,body);
        logEvent_("chmod", body);
    }
    return "";
}
String FakeShell::cmdChown_(Cmd& c) { (void)c; return ""; }
String FakeShell::cmdRm_(Cmd& c) {
    for (size_t i=1;i<c.argv.size();++i) {
        if (c.argv[i].startsWith("-")) continue;
        String abs = resolvePath_(c.argv[i]);
        for (auto it = files_.begin(); it != files_.end(); ) {
            if (it->path == abs || it->path.startsWith(abs+"/")) it = files_.erase(it);
            else ++it;
        }
    }
    return "";
}
String FakeShell::cmdMkdir_(Cmd& c) {
    for (size_t i=1;i<c.argv.size();++i) {
        if (c.argv[i].startsWith("-")) continue;
        String abs = resolvePath_(c.argv[i]);
        VirtualFile* vf = createFile_(abs, "mkdir");
        if (vf) { vf->is_dir=true; vf->mode=0755; }
    }
    return "";
}
String FakeShell::cmdTouch_(Cmd& c) {
    for (size_t i=1;i<c.argv.size();++i) {
        if (c.argv[i].startsWith("-")) continue;
        String abs = resolvePath_(c.argv[i]);
        VirtualFile* vf = createFile_(abs, "touch");
        if (vf) vf->mtime_ms = millis();
    }
    return "";
}
String FakeShell::cmdMv_(Cmd& c) {
    if (c.argv.size()<3) return "";
    String src = resolvePath_(c.argv[1]);
    String dst = resolvePath_(c.argv[2]);
    auto* sf = findFile_(src);
    if (sf) sf->path = dst;
    return "";
}
String FakeShell::cmdCp_(Cmd& c) {
    if (c.argv.size()<3) return "";
    String src = resolvePath_(c.argv[c.argv.size()-2]);
    String dst = resolvePath_(c.argv[c.argv.size()-1]);
    auto* sf = findFile_(src);
    if (sf) {
        VirtualFile nf = *sf; nf.path = dst; nf.created_by="cp";
        if (files_.size() < MAX_VFS_FILES) files_.push_back(nf);
    }
    return "";
}

String FakeShell::cmdWhich_(Cmd& c) {
    String r;
    for (size_t i=1;i<c.argv.size();++i) {
        const String& n = c.argv[i];
        if (n=="ls"||n=="cat"||n=="echo"||n=="printf"||n=="rm"||n=="cp"||n=="mv"||n=="chmod"||
            n=="bash"||n=="sh"||n=="ps"||n=="grep"||n=="head"||n=="tail")
            r += "/bin/"+n+"\n";
        else if (n=="wget"||n=="curl"||n=="python"||n=="python3"||n=="perl"||n=="php"||
                 n=="nc"||n=="ncat"||n=="ifconfig"||n=="ip"||n=="ss"||n=="netstat"||
                 n=="apt"||n=="apt-get"||n=="dpkg"||n=="tftp"||n=="ftpget"||n=="tftpget")
            r += "/usr/bin/"+n+"\n";
        else { last_status_ok_=false; }
    }
    return r;
}
String FakeShell::cmdWhereis_(Cmd& c) {
    String r;
    for (size_t i=1;i<c.argv.size();++i) {
        if (c.argv[i].startsWith("-")) continue;
        r += c.argv[i] + ": /usr/bin/" + c.argv[i] + " /usr/share/man/man1/" + c.argv[i] + ".1.gz\n";
    }
    return r;
}

String FakeShell::cmdSleep_(Cmd& c) {
    if (c.argv.size()<2) return "";
    long ms;
    String s = c.argv[1];
    if (s.endsWith("s")) { ms = toLongOr(s.substring(0,s.length()-1), 1) * 1000; }
    else if (s.endsWith("m")) { ms = toLongOr(s.substring(0,s.length()-1), 1) * 60000; }
    else { ms = toLongOr(s, 1) * 1000; }
    StaticJsonDocument<128> d;
    d["requested_ms"] = (uint32_t)ms;
    String body; serializeJson(d, body);
    logEvent_("sleep", body);
    if (ms < 0) ms = 0;
    if ((uint32_t)ms > MAX_SLEEP_MS) ms = MAX_SLEEP_MS;
    // virtual_sleep skips the actual stall — telnet runs the shell from
    // an AsyncTCP callback where a 3 s delay() blocks the entire
    // network task. The forensic intent (the attacker called sleep) is
    // already captured in logEvent_ above. See ESP32 stability review H5.
    if (!virtual_sleep_) delay(ms);
    return "";
}

// ----- apt/dpkg/pip -----

String FakeShell::cmdApt_(Cmd& c) {
    String sub = (c.argv.size()>=2) ? c.argv[1] : "";
    if (sub=="update") {
        return
        "Hit:1 http://archive.ubuntu.com/ubuntu bionic InRelease\n"
        "Hit:2 http://archive.ubuntu.com/ubuntu bionic-updates InRelease\n"
        "Hit:3 http://archive.ubuntu.com/ubuntu bionic-backports InRelease\n"
        "Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease\n"
        "Reading package lists... Done\n";
    }
    if (sub=="install"||sub=="-y"||sub=="reinstall") {
        StaticJsonDocument<256> d;
        JsonArray a = d["pkgs"].to<JsonArray>();
        for (size_t i=2;i<c.argv.size();++i) if (!c.argv[i].startsWith("-")) a.add(c.argv[i]);
        String body; serializeJson(d, body);
        logEvent_("package_install_attempt", body);
        return
        "Reading package lists... Done\n"
        "Building dependency tree\n"
        "Reading state information... Done\n"
        "E: Unable to locate package "+(c.argv.size()>=3?c.argv[2]:String("?"))+"\n";
    }
    if (sub=="remove"||sub=="purge") return "Reading package lists... Done\nBuilding dependency tree\n";
    if (sub=="list") return "Listing... Done\n";
    if (sub=="upgrade") return "Reading package lists... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n";
    return "";
}
String FakeShell::cmdDpkg_(Cmd& c) {
    if (c.argv.size()>=2 && (c.argv[1]=="-l"||c.argv[1]=="--list")) {
        return
        "Desired=Unknown/Install/Remove/Purge/Hold\n"
        "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
        "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
        "||/ Name           Version          Architecture     Description\n"
        "+++-==============-================-================-====================\n"
        "ii  bash           4.4.18-2ubuntu1  amd64            GNU Bourne Again SHell\n"
        "ii  coreutils      8.28-1ubuntu1    amd64            GNU core utilities\n"
        "ii  openssh-server 1:7.6p1-4        amd64            secure shell server\n";
    }
    return "";
}
String FakeShell::cmdPip_(Cmd& c) {
    if (c.argv.size()>=2 && c.argv[1]=="install") {
        StaticJsonDocument<256> d;
        JsonArray a = d["pkgs"].to<JsonArray>();
        for (size_t i=2;i<c.argv.size();++i) if (!c.argv[i].startsWith("-")) a.add(c.argv[i]);
        String body; serializeJson(d, body);
        logEvent_("pip_install_attempt", body);
        return "Collecting "+String(c.argv.size()>=3?c.argv[2]:"")+"\nERROR: Could not find a version that satisfies the requirement\n";
    }
    return "";
}

// ----- crontab/systemctl/service -----

String FakeShell::cmdCrontab_(Cmd& c) {
    if (c.argv.size()>=2 && c.argv[1]=="-l") return crontab_;
    if (c.argv.size()>=2 && c.argv[1]=="-r") { crontab_=""; return ""; }
    if (c.argv.size()>=2 && c.argv[1]=="-e") return ""; // editor not real
    // crontab <file> form — read into our crontab
    if (c.argv.size()>=2 && !c.argv[1].startsWith("-")) {
        String abs = resolvePath_(c.argv[1]);
        auto* vf = findFile_(abs);
        if (vf) {
            crontab_ = vf->content;
            StaticJsonDocument<256> d;
            d["from"]=abs; d["bytes"]=(uint32_t)crontab_.length();
            String body; serializeJson(d,body);
            logEvent_("cron_modified", body);
        }
    }
    return "";
}
String FakeShell::cmdSystemctl_(Cmd& c) {
    if (c.argv.size()>=2 && (c.argv[1]=="enable"||c.argv[1]=="start"||c.argv[1]=="restart")) {
        StaticJsonDocument<256> d;
        d["action"]=c.argv[1];
        d["unit"]=(c.argv.size()>=3?c.argv[2]:String(""));
        String body; serializeJson(d,body);
        logEvent_("systemd_service_modified", body);
        return "";
    }
    if (c.argv.size()>=2 && c.argv[1]=="status") {
        return "● "+(c.argv.size()>=3?c.argv[2]:String("unit"))+" - service\n   Loaded: loaded\n   Active: active (running)\n";
    }
    return "";
}
String FakeShell::cmdService_(Cmd& c) { return cmdSystemctl_(c); }
String FakeShell::cmdKill_(Cmd& c, const String& which) { (void)c; (void)which; return ""; }

String FakeShell::cmdNc_(Cmd& c) {
    // log as recon/reverse-shell candidate; output nothing
    StaticJsonDocument<256> d;
    JsonArray a = d["argv"].to<JsonArray>();
    for (auto& x : c.argv) a.add(x);
    String body; serializeJson(d, body);
    logEvent_("nc_invoked", body);
    return "";
}
String FakeShell::cmdPing_(Cmd& c) {
    String tgt = (c.argv.size()>=2) ? c.argv[c.argv.size()-1] : "8.8.8.8";
    return "PING "+tgt+" ("+tgt+") 56(84) bytes of data.\n64 bytes from "+tgt+": icmp_seq=1 ttl=54 time=11.4 ms\n";
}
String FakeShell::cmdIptables_(Cmd& c) {
    if (c.argv.size()>=2 && c.argv[1]=="-L") {
        return
        "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n\n"
        "Chain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination\n\n"
        "Chain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination\n";
    }
    StaticJsonDocument<256> d;
    JsonArray a = d["argv"].to<JsonArray>();
    for (auto& x : c.argv) a.add(x);
    String body; serializeJson(d,body);
    logEvent_("iptables_change", body);
    return "";
}
String FakeShell::cmdUfw_(Cmd& c) {
    if (c.argv.size()>=2 && c.argv[1]=="status") return "Status: inactive\n";
    return "";
}

// ----- sh -c / interpreters / direct execution -----

String FakeShell::cmdShEval_(Cmd& c) {
    // sh / bash with no -c => acts as a recursive shell prompt; just no-op.
    int dashc = -1;
    for (size_t i=1;i<c.argv.size();++i) if (c.argv[i]=="-c") { dashc=(int)i; break; }
    if (dashc<0 || dashc+1>=(int)c.argv.size()) return "";
    String inner = c.argv[dashc+1];
    StaticJsonDocument<384> d;
    d["wrapper"]=c.exe;
    d["script"]=inner.substring(0, min((unsigned)inner.length(), 480u));
    String body; serializeJson(d,body);
    logEvent_("script_execution", body);
    // recurse — split & run inner chain (don't double-count toward command cap)
    if (commands_ < MAX_COMMANDS_PER_SESSION) {
        return runChain_(inner);
    }
    return "";
}

String FakeShell::cmdInterp_(Cmd& c) {
    String inner;
    for (size_t i=1;i<c.argv.size();++i) {
        if (c.argv[i]=="-c" && i+1<c.argv.size()) { inner = c.argv[i+1]; break; }
    }
    if (inner.length()) {
        StaticJsonDocument<384> d;
        d["interp"]=c.exe;
        d["script"]=inner.substring(0, min((unsigned)inner.length(), 480u));
        String body; serializeJson(d,body);
        logEvent_("script_execution", body);
        return "";
    }
    // python myscript.py — try to "run" the script if we have it
    if (c.argv.size()>=2 && !c.argv[1].startsWith("-")) {
        String abs = resolvePath_(c.argv[1]);
        auto* vf = findFile_(abs);
        if (vf) {
            StaticJsonDocument<256> d;
            d["interp"]=c.exe; d["file"]=abs; d["profile"]=vf->payload_profile;
            String body; serializeJson(d,body);
            logEvent_("script_execution", body);
        }
    }
    return "";
}

String FakeShell::cmdExecute_(Cmd& c) {
    String tgt = c.argv[0];
    String abs = resolvePath_(tgt);
    auto* vf = findFile_(abs);
    if (!vf) {
        last_status_ok_=false;
        return "-bash: " + tgt + ": No such file or directory\n";
    }
    if (!vf->executable) {
        last_status_ok_=false;
        return "-bash: " + tgt + ": Permission denied\n";
    }
    vf->executed = true; vf->exec_count++;
    StaticJsonDocument<384> d;
    d["file"]=abs; d["url"]=vf->source_url; d["arch"]=vf->arch;
    d["profile"]=vf->payload_profile; d["exec_count"]=vf->exec_count;
    String body; serializeJson(d,body);
    logEvent_("payload_execution", body);

    // Insert a fake process for ps. Capped at MAX_VPROCS so a long
    // session that runs many payload-execute steps doesn't unbounded-
    // grow the procs_ vector. Bots running 30-50 payloads per session
    // are routine — without this, each one added a FakeProcess that
    // never got reaped.
    if (procs_.size() < MAX_VPROCS) {
        FakeProcess p;
        p.pid = 1000 + (millis() & 0x1fff);
        p.user = user_;
        p.tty = "?";
        p.cmd = abs;
        procs_.push_back(p);
    }

    // realistic small delay — skipped when running from a network
    // callback (telnet); SSH runs on its own task and keeps it.
    if (!virtual_sleep_) delay(min((uint32_t)1500, MAX_SLEEP_MS));
    return "";
}

String FakeShell::commandSummary(size_t max_bytes) const {
    String out;
    out.reserve(256);
    for (size_t i = 0; i < history_.size(); ++i) {
        if (out.length() + history_[i].length() + 1 > max_bytes) break;
        if (out.length()) out += '\n';
        out += history_[i];
    }
    return out;
}

} // namespace honeymire
