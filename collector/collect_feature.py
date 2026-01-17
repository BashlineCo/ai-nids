import os
import json
import time
import psutil
import getpass
import threading
import pickle
import re
from datetime import datetime, timedelta
from stat import S_IMODE
from inotify_simple import INotify, flags
import math
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, TLS

# -----------------------------
# Paths & Baselines
# -----------------------------
DATA_DIR = "/home/eyerin/projects/ai-nids/data/raw"
os.makedirs(DATA_DIR, exist_ok=True)
AUTH_LOG_PATH = "/var/log/auth.log"
WATCH_PATHS = ["/home", "/tmp"]
BASELINE_PATHS = {
    "parent_child": os.path.join(DATA_DIR, "baseline_parent_child.pkl"),
    "user_baseline": os.path.join(DATA_DIR, "baseline_user.pkl"),
    "rolling_failed_login": os.path.join(DATA_DIR, "rolling_failed_login.pkl"),
    "rolling_process_spawn": os.path.join(DATA_DIR, "rolling_process_spawn.pkl"),
    "rolling_network_bytes": os.path.join(DATA_DIR, "rolling_network_bytes.pkl"),
    "rolling_priv_escalation": os.path.join(DATA_DIR, "rolling_priv_escalation.pkl"),
    "rare_commands": os.path.join(DATA_DIR, "rare_commands.pkl")
    "login_hours": os.path.join(DATA_DIR, "login_hours.pkl")
    "z_failed_logins": os.path.join(DATA_DIR, "z_failed_logins.pkl")
    "z_cpu": os.path.join(DATA_DIR, "z_cpu.pk")
    "syscall_counts": os.path.join(DATA_DIR, "syscalls.pkl")
    "kernel_modules": os.path.join(DATA_DIR, "kernel_modules.pkl")
    "network_history": os.path.join(DATA_DIR, "network_history.pkl")
  
}

#adds unexpected login tiome scores

def compute_unexpected_time_score(current_hour):
    baseline_hours = load_pickle(BASELINE_PATHS["login_hours"], list)
    
    if len(baseline_hours) < 10:
        baseline.hours.append(current_hour)
        save_pickle(BASELINE_PATHS["login_hours"], baseline_hours)
        return 0.0
        
    mean_val = sum(hist)/len(hist)
    var = sum((x - mean_val)**2 for x in hist) / len(hist)
    std = max(var**0.5, 1e-6)
    
    z = (value - mean_val) / std
    
    hist.append(value)
    save_pickle(history_path, hist)
    
    return z

#adds avg time between login failures (7 days)

def compute_7d_login_failure_rate():
    history = load_pickle(BASELINE_PATHS["rolling_failed_login"], list)
    if len(history) < 2:
        return 0.0
    return sum(history[-7:]) / min(len(history), 7)
    
#adds rare command ratio last week

def compute_rare_command_ratio(rare_buffer, current_commands):
    week_cmds = [cmds for snapshot in rare_buffer.get_all() for cmd in snapshot]
    if not week_cmds:
        return 0.0
    
    rare = [c for c in current_commands if c not in week_cmds]
    return len(rare) / max(len(current_commands), 1)
    
#adds syscall monitoring via auditd logs

def parse_syscalls():
    syscall_count = 0
    suspicious_syscalls = 0
    network_syscalls = 0
    execve_calls = 0

    syscall_log = "/var/log/audit/audit.log"
    if not os.path.exists(syscall_log):
        return 0,0,0,0

    with open(syscall_log, "r") as f:
        for line in f:
            if "type=SYSCALL" in line:
                syscall_count += 1
                if "execve" in line:
                    execve_calls += 1
                if "connect" in line or "bind" in line:
                    network_syscalls += 1
                if "chmod" in line or "ptrace" in line:
                    suspicious_syscalls += 1

    return syscall_count, suspicious_syscalls, network_syscalls, execve_calls

#kernel module monitoring

def kernel_module_stats():
    modules = open("/proc/modules").read().splitlines()
    loaded_count = len(modules)

    suspicious = [m for m in modules if "rootkit" in m or "hide" in m]
    return loaded_count, len(suspicious)

#dmesg error frequency

def dmesg_error_rate():
    output = os.popen("dmesg --ctime --level=err,warn").read().strip().splitlines()
    return len(output)
    
#low-level fs  integrity checks

SYSTEM_BINARIES = ["/bin", "/usr/bin", "/sbin"]

def check_system_binary_mods():
    changes = 0
    for root_dir in SYSTEM_BINARIES:
        for root, dirs, files in os.walk(root_dir):
            for f in files:
                path = os.path.join(root, f)
                try:
                    if os.stat(path).st_mtime > time.time() - 60:
                        changes += 1
                except:
                    continue
    return changes

#checksum tracking for persistent storage

def checksum_mismatch():
    stored = load_pickle(os.path.join(DATA_DIR, "checksums.pkl"), dict)
    mismatches = 0
    for root_dir in SYSTEM_BINARIES:
        for root, dirs, files in os.walk(root_dir):
            for f in files:
                path = os.path.join(root, f)
                try:
                    with open(path, "rb") as file:
                        data = file.read()
                    checksum = hash(data)

                    if path in stored and stored[path] != checksum:
                        mismatches += 1
                    stored[path] = checksum
                except:
                    continue

    save_pickle(os.path.join(DATA_DIR, "checksums.pkl"), stored)
    return mismatches

#suid binaries and shadow file access

def detect_suid_executions():
    suspicious = 0
    for root, dirs, files in os.walk("/"):
        for f in files:
            path = os.path.join(root, f)
            try:
                if os.stat(path).st_mode & 0o4000:  # SUID bit
                    if os.stat(path).st_atime > time.time() - 60:
                        suspicious += 1
            except:
                continue
    return suspicious


def shadow_accesses():
    shadow = "/etc/shadow"
    try:
        st = os.stat(shadow)
        if st.st_atime > time.time() - 60:
            return 1
    except:
        pass
    return 0

#Network - destination IPs, ports, failures, DNS, HTTP, TLS

NETWORK_SNAPSHOT = {
    "ips": set(),
    "ports": set(),
    "failed_conns": 0,
    "dns": 0,
    "http": 0,
    "weird_ua": 0,
    "weird_len": 0,
    "tls_fails": 0
}

def packet_handler(pkt):
    try:
        if IP in pkt:
            NETWORK_SNAPSHOT["ips"].add(pkt[IP].dst)

        if TCP in pkt:
            NETWORK_SNAPSHOT["ports"].add(pkt[TCP].dport)

            if pkt[TCP].flags == "R":  # reset = connection failed
                NETWORK_SNAPSHOT["failed_conns"] += 1

        if DNS in pkt:
            NETWORK_SNAPSHOT["dns"] += 1

        if Raw in pkt and b"HTTP" in pkt[Raw].load:
            NETWORK_SNAPSHOT["http"] += 1
            if b"User-Agent:" in pkt[Raw].load and b"curl" in pkt[Raw].load:
                NETWORK_SNAPSHOT["weird_ua"] += 1

            if len(pkt[Raw].load) > 20000:
                NETWORK_SNAPSHOT["weird_len"] += 1

        if TLS in pkt and pkt[TLS].type == 0x02:  # handshake fail alert
            NETWORK_SNAPSHOT["tls_fails"] += 1

    except:
        pass
        
sniffer = threading.Thread(target=lambda: sniff(timeout=60, prn=packet_handler, store=False))
sniffer.start()

# -----------------------------
# Pickle Helpers
# -----------------------------
def load_pickle(path, default=None):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    return default() if callable(default) else default

def save_pickle(path, obj):
    with open(path, "wb") as f:
        pickle.dump(obj, f)

# -----------------------------
# Auth Log Parser
# -----------------------------
def parse_auth_log(window_start):
    failed_login_count = 0
    successful_login_count = 0
    unique_users_attempted = set()
    root_login_attempts = 0
    sudo_command_count = 0
    login_timestamps = []

    if not os.path.exists(AUTH_LOG_PATH):
        return failed_login_count, successful_login_count, len(unique_users_attempted), root_login_attempts, sudo_command_count, 0.0

    with open(AUTH_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                timestamp_str = " ".join(line.split()[:3])
                timestamp_dt = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                if timestamp_dt.timestamp() < window_start:
                    continue
            except:
                continue

            if "Failed password" in line:
                failed_login_count += 1
                match = re.search(r'for (\w+)', line)
                if match:
                    unique_users_attempted.add(match.group(1))
                    login_timestamps.append(timestamp_dt.timestamp())
            elif "Accepted password" in line:
                successful_login_count += 1
                match = re.search(r'for (\w+)', line)
                if match:
                    unique_users_attempted.add(match.group(1))
                    login_timestamps.append(timestamp_dt.timestamp())
                    if match.group(1) == "root":
                        root_login_attempts += 1
            elif "sudo:" in line:
                sudo_command_count += 1

    avg_time_between_logins = 0.0
    if len(login_timestamps) > 1:
        diffs = [t2 - t1 for t1, t2 in zip(login_timestamps[:-1], login_timestamps[1:])]
        avg_time_between_logins = sum(diffs)/len(diffs)

    return failed_login_count, successful_login_count, len(unique_users_attempted), root_login_attempts, sudo_command_count, avg_time_between_logins

# -----------------------------
# Parent-Child Anomaly
# -----------------------------
def compute_parent_child_score(current_pairs):
    baseline_pairs = load_pickle(BASELINE_PATHS["parent_child"], set())
    if not baseline_pairs:
        save_pickle(BASELINE_PATHS["parent_child"], set(current_pairs))
        return 0.0
    new_pairs = sum(1 for pair in current_pairs if pair not in baseline_pairs)
    score = new_pairs / max(len(current_pairs), 1)
    baseline_pairs.update(current_pairs)
    save_pickle(BASELINE_PATHS["parent_child"], baseline_pairs)
    return score

# -----------------------------
# Filesystem Monitoring
# -----------------------------
class FSMonitor:
    def __init__(self, paths):
        self.inotify = INotify()
        self.wd_to_path = {}
        for path in paths:
            for root, dirs, files in os.walk(path):
                wd = self.inotify.add_watch(root, flags.CREATE | flags.DELETE | flags.MODIFY | flags.ATTRIB)
                self.wd_to_path[wd] = root
        self.file_create_count = 0
        self.file_delete_count = 0
        self.hidden_file_count = 0
        self.permission_change_count = 0

    def process_events(self, timeout=0):
        for event in self.inotify.read(timeout):
            fname = event.name
            if flags.CREATE in event.mask:
                self.file_create_count += 1
                if fname.startswith("."):
                    self.hidden_file_count += 1
            if flags.DELETE in event.mask:
                self.file_delete_count += 1
            if flags.ATTRIB in event.mask:
                self.permission_change_count += 1

# -----------------------------
# Command Entropy
# -----------------------------
def compute_entropy(commands):
    if not commands: return 0.0
    freq = {}
    for cmd in commands:
        freq[cmd] = freq.get(cmd, 0) + 1
    total = len(commands)
    entropy = -sum((v/total)*math.log2(v/total) for v in freq.values())
    return entropy

# -----------------------------
# Rolling Buffer Class for Long Window
# -----------------------------
class RollingBuffer:
    def __init__(self, path, max_len=10):  # max_len = number of 1-min snapshots in long window
        self.path = path
        self.max_len = max_len
        self.buffer = load_pickle(path, list)

    def add(self, snapshot):
        self.buffer.append(snapshot)
        if len(self.buffer) > self.max_len:
            self.buffer.pop(0)
        save_pickle(self.path, self.buffer)

    def get_all(self):
        return self.buffer

# -----------------------------
# Feature Collector
# -----------------------------
def collect_features(short_window_sec=60, long_window_len=10):
    current_user = getpass.getuser()
    window_start = time.time()
    window_end = window_start + short_window_sec

    cpu_samples, mem_samples = [], []
    spawned_pids_counter = {}
    seen_commands = set()
    fs_monitor = FSMonitor(WATCH_PATHS)

    last_proc_scan = 0
    last_net_io = psutil.net_io_counters()

    # Rolling buffers for long window
    rolling_failed_logins = RollingBuffer(BASELINE_PATHS["rolling_failed_login"], max_len=long_window_len)
    rolling_process_spawn = RollingBuffer(BASELINE_PATHS["rolling_process_spawn"], max_len=long_window_len)
    rolling_network_bytes = RollingBuffer(BASELINE_PATHS["rolling_network_bytes"], max_len=long_window_len)
    rolling_priv_escalation = RollingBuffer(BASELINE_PATHS["rolling_priv_escalation"], max_len=long_window_len)
    rare_commands_buffer = RollingBuffer(BASELINE_PATHS["rare_commands"], max_len=long_window_len)

    # -----------------------------
    # Main loop for 1-min snapshot
    # -----------------------------
    while time.time() < window_end:
        cpu_samples.append(psutil.cpu_percent(interval=1))
        mem_samples.append(psutil.virtual_memory().percent)

        now = time.time()
        if now - last_proc_scan >= 5:
            last_proc_scan = now
            for p in psutil.process_iter(['pid','ppid','name','username','cmdline','create_time']):
                try:
                    spawned_pids_counter[p.info['name']] = spawned_pids_counter.get(p.info['name'],0)+1
                    if p.info['name'] in ("bash","sh","zsh"):
                        cmdline = " ".join(p.info['cmdline'])
                        if cmdline:
                            seen_commands.add(cmdline)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        fs_monitor.process_events(timeout=100)

    # -----------------------------
    # Compute Short Window Features
    # -----------------------------
    all_procs = list(psutil.process_iter(['pid','ppid','username','create_time','name']))
    background_ratio = sum(1 for p in all_procs if p.info.get('username') != current_user)/max(len(all_procs),1)
    orphan_count = sum(1 for p in all_procs if p.info['ppid']==1)
    long_running = sum(1 for p in all_procs if (time.time()-p.create_time())>3600)
    spawned_pids = sum(1 for v in spawned_pids_counter.values() if v==1)
    unique_processes = len(spawned_pids_counter)
    shell_spawn_count = sum(1 for n in spawned_pids_counter if n in ("bash","sh","zsh"))

    unique_commands = len(seen_commands)
    avg_command_length = sum(len(c) for c in seen_commands)/max(len(seen_commands),1)
    pipe_usage_count = sum(1 for c in seen_commands if "|" in c)
    encoded_command_ratio = sum(1 for c in seen_commands if any(x in c for x in ['base64','eval','decode']))/max(len(seen_commands),1)
    suspicious_command_ratio = sum(1 for c in seen_commands if any(x in c for x in ['wget','curl','nc','netcat','chmod 777']))/max(len(seen_commands),1)
    command_entropy = compute_entropy(seen_commands)

    cpu_mean = sum(cpu_samples)/max(len(cpu_samples),1)
    mem_mean = sum(mem_samples)/max(len(mem_samples),1)
    cpu_spike_count = sum(1 for c in cpu_samples if c>80)

    failed_login_count, successful_login_count, unique_users_attempted_count, root_login_attempts, sudo_command_count, avg_time_between_logins = parse_auth_log(window_start)

    current_pairs = [(p.info['pid'], p.info.get('ppid',0)) for p in all_procs]
    parent_child_score = compute_parent_child_score(current_pairs)

    net_io = psutil.net_io_counters()
    bytes_per_sec = (net_io.bytes_sent + net_io.bytes_recv - last_net_io.bytes_sent - last_net_io.bytes_recv)/max(short_window_sec,1)
    packets_per_sec = (net_io.packets_sent + net_io.packets_recv - last_net_io.packets_sent - last_net_io.packets_recv)/max(short_window_sec,1)
    last_net_io = net_io
    inbound_outbound_ratio = (net_io.bytes_recv+1)/(net_io.bytes_sent+1)

    short_features = {
        "failed_login_count": failed_login_count,
        "successful_login_count": successful_login_count,
        "root_login_attempts": root_login_attempts,
        "sudo_command_count": sudo_command_count,
        "avg_time_between_logins": avg_time_between_logins,
        "process_spawn_rate": spawned_pids,
        "unique_process_count": unique_processes,
        "shell_spawn_count": shell_spawn_count,
        "parent_child_anomaly_score": parent_child_score,
        "long_running_process_count": long_running,
        "unique_command_count": unique_commands,
        "avg_command_length": avg_command_length,
        "pipe_usage_count": pipe_usage_count,
        "encoded_command_ratio": encoded_command_ratio,
        "suspicious_command_ratio": suspicious_command_ratio,
        "command_entropy": command_entropy,
        "disk_write_rate": fs_monitor.file_create_count,
        "file_create_count": fs_monitor.file_create_count,
        "file_delete_count": fs_monitor.file_delete_count,
        "hidden_file_count": fs_monitor.hidden_file_count,
        "permission_change_count": fs_monitor.permission_change_count,
        "cpu_usage_mean": cpu_mean,
        "cpu_spike_count": cpu_spike_count,
        "memory_usage_mean": mem_mean,
        "packets_per_second": packets_per_sec,
        "bytes_per_second": bytes_per_sec,
        "inbound_outbound_ratio": inbound_outbound_ratio
        "unexpected_login_time_score": compute_unexpected_login_time_score(datetime.now().hour),
        "z_failed_login_count": compute_z_score(failed_login_count, BASELINE_PATHS["z_failed_logins"]),
        "z_cpu_usage_mean": compute_z_score(cpu_mean, BASELINE_PATHS["z_cpu"]),
        "user_login_hour_deviation_score": compute_unexpected_login_time_score(datetime.now().hour),
        "avg_time_between_login_failures_last_7days": compute_7d_login_failure_rate(),
        "rare_command_ratio_last_week": compute_rare_command_ratio(rare_commands_buffer, seen_commands),
        "syscall_frequency": syscall_count,
        "suspicious_syscalls_count": suspicious_syscalls,
        "network_syscalls_count": network_syscalls,
        "execve_call_count": execve_calls,
        "system_binary_mod_count": system_binary_mods,
        "checksum_mismatch_count": checksum_changes,
        "unexpected_suid_binaries_executed": suid_executed,
        "shadow_file_access_count": shadow_access,
        "loaded_kernel_modules_count": loaded,
        "suspicious_kernel_modules_loaded": loaded_suspicious,
        "dmesg_error_rate": dmesg_errs,
        "unique_destination_ips": len(NETWORK_SNAPSHOT["ips"]),
        "unique_destination_ports": len(NETWORK_SNAPSHOT["ports"]),
        "failed_connection_attempts": NETWORK_SNAPSHOT["failed_conns"],
        "suspicious_port_usage_count": sum(1 for p in NETWORK_SNAPSHOT["ports"] if p > 50000),
        "dns_request_count": NETWORK_SNAPSHOT["dns"],
        "http_request_rate": NETWORK_SNAPSHOT["http"],
        "suspicious_user_agent_count": NETWORK_SNAPSHOT["weird_ua"],
        "unusual_content_length_events": NETWORK_SNAPSHOT["weird_len"],
        "tls_handshake_failures": NETWORK_SNAPSHOT["tls_fails"],
    }

    # -----------------------------
    # Update Long Window / Rolling Features
    # -----------------------------
    rolling_failed_logins.add(failed_login_count)
    rolling_process_spawn.add(spawned_pids)
    rolling_network_bytes.add(bytes_per_sec)
    rolling_priv_escalation.add(suspicious_command_ratio)
    rare_commands_buffer.add(list(seen_commands))

    long_window_snapshot = {
        "rolling_failed_logins": rolling_failed_logins.get_all(),
        "rolling_process_spawn": rolling_process_spawn.get_all(),
        "rolling_network_bytes": rolling_network_bytes.get_all(),
        "rolling_priv_escalation": rolling_priv_escalation.get_all(),
        "rare_commands_snapshot": rare_commands_buffer.get_all()
    }

    # -----------------------------
    # Save snapshot
    # -----------------------------
    file_path = os.path.join(DATA_DIR, f"snapshot_{datetime.now().strftime('%Y%m%d%H%M%S')}.json")
    with open(file_path,"w") as f:
        json.dump({"short_window": short_features, "long_window": long_window_snapshot},f,indent=4)
    print(f"[+] Saved snapshot: {file_path}")

    return file_path

# -----------------------------
# Main Loop
# -----------------------------
if __name__=="__main__":
    print("[*] Dual-window HIDS+NIDS Collector Started")
    cycle = 0
    while True:
        cycle += 1
        print(f"[*] Cycle {cycle}...")
        try:
            collect_features(short_window_sec=60, long_window_len=10)
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(5)

