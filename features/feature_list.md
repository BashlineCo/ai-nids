# Real-Time IDS Collector — Feature Reference
### PRODUCTION v2 · 40 Features · 0 Placeholders

---

## Overview

The Real-Time IDS Collector captures a **60-second rolling window** of host and network activity, extracting exactly 40 security-relevant features per snapshot for downstream anomaly detection models.

Features span two detection domains:

- **HIDS** (Host Intrusion Detection System) — 29 features covering authentication, process behaviour, filesystem events, binary integrity, kernel state, CPU/memory, and syscall auditing.
- **NIDS** (Network Intrusion Detection System) — 11 features covering connection state, throughput, suspicious ports, DNS activity, HTTP user-agent analysis, and TLS handshake telemetry.

Each snapshot is saved as a timestamped JSON file under `data/raw/`.

---

## Requirements

| Dependency | Purpose | Install |
|---|---|---|
| `psutil` | Process, CPU, memory, network metrics | `pip install psutil` |
| `inotify_simple` | Filesystem event monitoring | `pip install inotify-simple` |
| `scapy` | Deep packet inspection (DNS, TLS, UA) | `pip install scapy` |
| `auditd` | Syscall event logging | system package |
| Root / `CAP_NET_RAW` | Scapy capture + log access | run as root or grant capability |

> Non-root operation is supported. Missing permissions will zero out the affected features; a warning is printed on startup.

---

## Quick Start

```bash
# Install Python dependencies
pip install psutil inotify-simple scapy

# Run with default 60s windows (continuous)
sudo python collect.py

# Refresh binary checksum baseline after a system update
sudo python collect.py --refresh-checksums

# Stop cleanly — Ctrl+C drains threads and closes inotify watches
```

---

## Output Format

```json
{
  "timestamp": 1710000000.0,
  "datetime": "2025-03-09T14:00:00",
  "failed_login_count": 3,
  "root_login_attempts": 0,
  ...
}
```

Each file contains exactly **42 keys**: `timestamp`, `datetime`, and the 40 named features. All values are `int` or `float`; missing features are back-filled with `0` before saving.

---

## All 40 Features

### 🔐 HIDS — Authentication (Features 1–4)

> Sourced from `/var/log/auth.log`. File position is maintained across cycles; log rotation is detected via inode comparison. Year rollover at Dec 31/Jan 1 is handled by trying both the current and previous year when parsing timestamps.

| # | Feature | Description |
|---|---|---|
| 1 | `failed_login_count` | Number of failed SSH/PAM login attempts in the window. High counts indicate brute-force attacks. |
| 2 | `root_login_attempts` | Direct root login events (`Accepted password/publickey for root`). Any non-zero value is high-severity in hardened environments. |
| 3 | `sudo_command_count` | Number of `COMMAND=` entries in auth.log. Spikes may indicate privilege escalation or unauthorized administrative activity. |
| 4 | `unusual_hour_logins` | Logins or attempts outside 06:00–22:00 local time. Late-night activity from service accounts or unknown users is a common intrusion indicator. |

---

### ⚙️ HIDS — Process Behaviour (Features 5–10)

> `psutil.process_iter()` is called every 2 seconds during the window. The parent-child anomaly score is compared against a persistent rolling baseline (capped deque of 10,000 pairs) stored as a pickle file.

| # | Feature | Description |
|---|---|---|
| 5 | `unique_pid_count` | Total distinct PIDs seen across all process scans. Abnormally high values may indicate process injection, fork-bombs, or malware spawning many workers. |
| 6 | `unique_process_name_count` | Number of distinct process names seen. A sudden appearance of many unusual names (e.g. random strings) is a malware indicator. |
| 7 | `total_process_count` | Snapshot count of all running processes at window end. Useful as a baseline to detect large deviations caused by exploitation. |
| 8 | `shell_spawn_count` | Number of `bash`/`sh`/`zsh`/`fish` processes seen. Attackers often spawn interactive reverse shells; this directly tracks that. |
| 9 | `orphan_process_count` | Processes re-parented to PID 1 (init). High counts can mean a parent was killed after spawning children — typical of injection or double-fork daemonization. |
| 10 | `parent_child_anomaly_score` | Ratio of new parent-child PID pairs vs. the rolling baseline. Values near 1.0 indicate a highly unusual process tree, consistent with exploitation. |

---

### 💻 HIDS — Command Analysis (Features 11–14)

> Commands are captured from the `cmdline` of shell processes and deduplicated per window using a set. Entropy is computed per-character (Shannon) and averaged across all commands seen.

| # | Feature | Description |
|---|---|---|
| 11 | `encoded_command_ratio` | Fraction of commands containing `base64`, `\x` hex escapes, `eval`, or `exec`. Attackers routinely encode payloads to evade signature detection. |
| 12 | `suspicious_command_ratio` | Fraction of commands matching known offensive tools: `nc`, `curl`, `wget`, `socat`, `python -c`, `bash -i`, `/dev/tcp`, etc. |
| 13 | `command_entropy` | Average per-character Shannon entropy of all shell commands seen. High entropy (>4.5 bits) in commands often indicates encrypted or compressed payloads. |
| 14 | `pipe_usage_count` | Count of commands containing the `\|` pipe operator. Heavy piping is a hallmark of chained exploitation and data exfiltration one-liners. |

---

### 📁 HIDS — Filesystem Events (Features 15–18)

> Requires `inotify_simple`. Watches `/tmp` and `/var/tmp` recursively (up to 8,000 watches). The thread polls the inotify buffer every 500ms to avoid overflow during burst writes. All four features default to `0` if inotify is unavailable.

| # | Feature | Description |
|---|---|---|
| 15 | `file_create_count` | Files created under monitored paths via inotify `IN_CREATE`. Malware frequently writes to world-writable directories. |
| 16 | `file_delete_count` | Files deleted under monitored paths (`IN_DELETE`). Attackers delete logs, execute-and-remove payloads, or clean up artifacts. |
| 17 | `hidden_file_count` | Files created with a leading `.` in monitored directories. Hidden files are a common persistence mechanism for rootkits and web shells. |
| 18 | `permission_change_count` | `IN_ATTRIB` events (chmod/chown/setuid) on monitored paths. Attackers escalate permissions of dropped binaries before executing them. |

---

### 🔒 HIDS — Integrity Monitoring (Features 19–22)

> SHA-256 checksums for critical binaries are computed on first run and cached to `data/raw/system_checksums.pkl`. The SUID binary scan covers `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, cached at startup and refreshed hourly.

| # | Feature | Description |
|---|---|---|
| 19 | `system_binary_mod_count` | Count of critical binaries (`/bin/bash`, `/usr/bin/sudo`, `sshd`, etc.) whose SHA-256 checksum differs from the stored baseline. Indicates trojanized binaries. |
| 20 | `checksum_mismatch_count` | Increments alongside `system_binary_mod_count`. Retained as a separate counter for downstream model compatibility. |
| 21 | `suid_binary_execution_count` | Processes started in this window whose executable path was in the SUID/SGID binary cache. SUID execution by non-root users is suspicious. |
| 22 | `shadow_file_accessed` | Binary flag (0/1): was `/etc/shadow` accessed within the last `window_size` seconds (via `st_atime`)? Shadow file reads outside of PAM/su indicate credential theft. |

---

### 🧩 HIDS — Kernel State (Feature 23)

> Reads `/proc/modules` and performs a case-insensitive substring match against a list of known rootkit signatures. Log output is de-duplicated: one module prints by name, two or more prints a summary count.

| # | Feature | Description |
|---|---|---|
| 23 | `suspicious_kernel_modules` | Count of loaded modules matching known rootkit names: `diamorphine`, `reptile`, `suterusu`, `kovid`, `umbreon`, etc. |

---

### 📊 HIDS — Resource Utilization (Features 24–26)

> CPU is sampled every 1 second via `psutil.cpu_percent(interval=1)`. Time is checked immediately after each blocking call to avoid interval drift.

| # | Feature | Description |
|---|---|---|
| 24 | `cpu_usage_mean` | Mean CPU utilization (%) across all 1-second samples in the window. Sustained high CPU can indicate crypto-mining or brute-force tools. |
| 25 | `cpu_spike_count` | Number of 1-second samples exceeding 80% CPU. Spikes are more actionable than the mean for detecting short bursts from shellcode or compilers. |
| 26 | `memory_usage_mean` | Mean RAM utilization (%) during the window. Memory exhaustion via injection or large heap allocation is a lateral movement technique. |

---

### 🔍 HIDS — Syscall Auditing (Features 27–29)

> Reads `/var/log/audit/audit.log`. Syscalls are matched by name first; if a number is found it is mapped using the x86_64 `SYSCALL_NAMES` table. Log rotation is detected via inode comparison, identical to the auth.log approach.
>
> ⚠️ Syscall number mapping is **x86_64 only**. On ARM or other architectures, configure auditd to emit syscall names.

| # | Feature | Description |
|---|---|---|
| 27 | `execve_count` | Audit events for `execve`/`fork`/`clone`/`vfork`. High counts indicate unusual process spawning — common in exploitation chains and lateral movement. |
| 28 | `network_syscalls_count` | Audit events for `socket`/`connect`/`bind`/`listen`/`accept`/`send`/`recv` family. Detects covert channels and unexpected network activity from non-network processes. |
| 29 | `suspicious_syscalls_count` | Audit events for `ptrace`, `init_module`, `delete_module`, `finit_module`. These are rarely used legitimately and are hallmarks of debugger-based injection and rootkit loading. |

---

### 🌐 NIDS — Connection State & Throughput (Features 30–37)

> All eight features are collected instantaneously via `psutil.net_connections()` and `psutil.net_io_counters()`. Throughput is derived from the delta between the previous and current io_counters snapshots. Counter wrap-around and interface resets are handled: negative deltas produce `0` rather than erroneous huge values.

| # | Feature | Description |
|---|---|---|
| 30 | `tcp_connections` | Total TCP socket count (all states). A baseline deviation can indicate C2 beaconing, mass scanning, or lateral movement. |
| 31 | `udp_connections` | Total UDP socket count. Attackers use UDP for DNS tunneling and covert exfiltration to avoid TCP state tracking. |
| 32 | `bytes_sent_per_sec` | Outbound bytes/sec. High values are the primary indicator of data exfiltration. |
| 33 | `bytes_recv_per_sec` | Inbound bytes/sec. Large inbound spikes may indicate payload download, tool staging, or C2 receiving instructions. |
| 34 | `listening_ports_count` | Number of sockets in `LISTEN` state. Attackers bind backdoor listeners; a new port not present at baseline is a high-confidence indicator. |
| 35 | `established_connections` | Number of `ESTABLISHED` TCP connections. Sustained high counts outside known services may indicate C2 keep-alives or outbound scanning. |
| 36 | `failed_connections` | Snapshot count of sockets in `SYN_SENT`, `SYN_RECV`, `CLOSING`, `LAST_ACK`. Elevated values suggest active scanning or half-open connection attacks. ⚠️ This is a state snapshot, not a cumulative event counter. |
| 37 | `suspicious_local_ports` | Local ports matching the suspicious list (4444, 5555, 6666, 31337, etc.) or any port >50000. Attackers commonly bind reverse shells on these well-known offensive ports. |

---

### 📡 NIDS — Deep Packet Inspection (Features 38–40)

> Runs in a dedicated Scapy thread started at the beginning of each window. The thread sniffs for `(window_size - 3)` seconds to guarantee it finishes before the main thread's 60-second join timeout. All three features default to `0` if Scapy is unavailable or the thread raises an exception.

| # | Feature | Description |
|---|---|---|
| 38 | `dns_request_count` | DNS queries captured via Scapy (DNS layer, QR bit = 0). High counts or requests to random-looking domains indicate DNS tunneling or DGA malware. |
| 39 | `suspicious_user_agents` | HTTP `User-Agent` strings in captured traffic matching offensive tool patterns: `curl`, `wget`, `python`, `sqlmap`, `nmap`, `masscan`, `nikto`. Decoded from raw TCP payloads. |
| 40 | `tls_handshakes` | TLS Client Hello packets detected (0x16 record type on port 443). Spikes from processes that normally don't use HTTPS indicate covert C2 channels. |

---

## Production Hardening — v2 Fixes

| # | Area | Fix |
|---|---|---|
| 1 | Filesystem thread | No thread is started when inotify is unavailable — eliminates a blocking fallback path. |
| 2 | CPU interval drift | `time.time()` is checked immediately after `psutil.cpu_percent()` returns to avoid overrunning the window. |
| 3 | SUID scan | Moved to `__init__`, cached in memory, refreshed hourly — not re-scanned every 60s cycle. |
| 4 | Network I/O init | Counters initialized in `__init__` — eliminates the artificial zero on the very first cycle. |
| 5 | Auth log year rollover | Parser tries both current and previous year to handle the Dec 31 / Jan 1 timestamp boundary. |
| 6 | Syscall mapping | x86_64 limitation documented; common syscalls expanded; name-first lookup supported. |
| 7 | Feature validation | Feature count is validated before saving; missing keys are back-filled with `0`. |
| 8 | Checksum refresh | `--refresh-checksums` CLI flag deletes the existing baseline before startup. |
| 9 | Graceful shutdown | `SIGINT`/`SIGTERM` handlers set a flag; inotify watches and file descriptors are closed cleanly. |
| 10 | Thread error tracking | Exceptions in the Scapy and filesystem threads are caught and reported via `self.thread_errors`. |
| 11 | Connection tracking | `failed_connections` documented as a state snapshot, not a cumulative event counter. |
| 12 | Scapy timing | Sniff duration is `(window_size - 3)` to guarantee the thread finishes before the join timeout. |

---

## Known Limitations

- **Inotify does not watch new subdirectories.** Directories created under `/tmp` after startup will not be monitored until the next collector restart.
- **Syscall mapping is x86_64 only.** On ARM or other architectures, configure auditd to log syscall names instead of numbers.
- **`failed_connections` is a point-in-time snapshot**, not a cumulative counter. Short-lived connections that complete between scans will not be counted.
- **`shadow_file_accessed` relies on `atime`.** Systems mounted with `noatime` or `relatime` will produce false negatives.
- **Scapy requires `CAP_NET_RAW`.** Running without root silently disables all three deep-packet features.
- **Parent-child baseline warmup.** The anomaly score converges toward `0` on stable systems after a few hours as the rolling baseline fills up.
