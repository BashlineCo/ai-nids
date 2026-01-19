import os
import json
import time
import psutil
import getpass
from datetime import datetime
import re
from stat import S_IMODE
import threading
import pickle
import socket

# -----------------------------
# Paths
# -----------------------------
DATA_DIR = "/home/eyerin/projects/ai-nids/data/raw"
os.makedirs(DATA_DIR, exist_ok=True)

AUTH_LOG_PATH = "/var/log/auth.log"
WATCH_PATHS = ["/home", "/tmp"]
BASELINE_PATH = os.path.join(DATA_DIR, "baseline_parent_child.pkl")

# -----------------------------
# Parent-child anomaly functions
# -----------------------------
def load_baseline_pairs():
    if os.path.exists(BASELINE_PATH):
        with open(BASELINE_PATH, "rb") as f:
            return pickle.load(f)
    return set()

def save_baseline_pairs(pairs):
    with open(BASELINE_PATH, "wb") as f:
        pickle.dump(pairs, f)

def compute_parent_child_score(current_pairs):
    baseline_pairs = set(load_baseline_pairs())
    if not baseline_pairs:
        save_baseline_pairs(set(current_pairs))
        return 0.0

    new_pairs = sum(1 for pair in current_pairs if pair not in baseline_pairs)
    score = new_pairs / max(len(current_pairs), 1)

    baseline_pairs.update(current_pairs)
    save_baseline_pairs(baseline_pairs)
    return score

# -----------------------------
# Auth log parser
# -----------------------------
def parse_auth_log(window_start):
    failed_login_count = 0
    successful_login_count = 0
    unique_users_attempted = set()
    root_login_attempts = 0
    sudo_command_count = 0
    login_timestamps = []

    if not os.path.exists(AUTH_LOG_PATH):
        return 0,0,0,0,0,0.0

    with open(AUTH_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                timestamp_str = " ".join(line.split()[:3])
                timestamp_dt = datetime.strptime(
                    f"{datetime.now().year} {timestamp_str}",
                    "%Y %b %d %H:%M:%S"
                )
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
                    user = match.group(1)
                    unique_users_attempted.add(user)
                    login_timestamps.append(timestamp_dt.timestamp())
                    if user == "root":
                        root_login_attempts += 1

            elif "sudo:" in line:
                sudo_command_count += 1

    avg_time_between_logins = 0.0
    if len(login_timestamps) > 1:
        diffs = [
            t2 - t1 for t1, t2 in zip(login_timestamps[:-1], login_timestamps[1:])
        ]
        avg_time_between_logins = sum(diffs) / len(diffs)

    return (
        failed_login_count,
        successful_login_count,
        len(unique_users_attempted),
        root_login_attempts,
        sudo_command_count,
        avg_time_between_logins
    )

# -----------------------------
# Network connection count
# -----------------------------
def total_network_connections():
    try:
        connections = psutil.net_connections(kind='inet')
        tcp_connections = 0
        udp_connections = 0
        total_connections = len(connections)

        for conn in connections:
            if conn.type == socket.SOCK_STREAM:
                tcp_connections += 1
            elif conn.type == socket.SOCK_DGRAM:
                udp_connections += 1

        return total_connections, tcp_connections, udp_connections
    except:
        return 0, 0, 0

# -----------------------------
# Extra NIDS features (ADDED)
# -----------------------------
def listening_ports_count():
    try:
        conns = psutil.net_connections(kind="inet")
        return sum(1 for c in conns if c.status == psutil.CONN_LISTEN)
    except:
        return 0

def established_connections_count():
    try:
        conns = psutil.net_connections(kind="inet")
        return sum(1 for c in conns if c.status == psutil.CONN_ESTABLISHED)
    except:
        return 0

def unique_remote_ips():
    try:
        conns = psutil.net_connections(kind="inet")
        ips = set()
        for c in conns:
            if c.raddr:
                ips.add(c.raddr.ip)
        return len(ips)
    except:
        return 0

# -----------------------------
# Filesystem monitoring
# -----------------------------
def collect_fs_stats(window_size_sec):
    file_mode_map = {}
    initial_files = set()
    initial_hidden = 0

    for path in WATCH_PATHS:
        for root, dirs, files in os.walk(path):
            for f in files:
                full = os.path.join(root, f)
                try:
                    st = os.stat(full)
                    file_mode_map[full] = S_IMODE(st.st_mode)
                    initial_files.add(full)
                    if f.startswith("."):
                        initial_hidden += 1
                except:
                    continue

    disk_write_start = psutil.disk_io_counters().write_bytes
    time.sleep(window_size_sec)

    final_files = set()
    permission_change_count = 0
    final_hidden = 0

    for path in WATCH_PATHS:
        for root, dirs, files in os.walk(path):
            for f in files:
                full = os.path.join(root, f)
                final_files.add(full)
                try:
                    st = os.stat(full)
                    old_mode = file_mode_map.get(full)
                    if old_mode and S_IMODE(st.st_mode) != old_mode:
                        permission_change_count += 1
                    if f.startswith("."):
                        final_hidden += 1
                except:
                    continue

    file_create_count = len(final_files - initial_files)
    file_delete_count = len(initial_files - final_files)
    hidden_file_count = max(final_hidden - initial_hidden, 0)

    disk_write_end = psutil.disk_io_counters().write_bytes
    disk_write_rate = (disk_write_end - disk_write_start) / max(window_size_sec, 1)

    return (
        file_create_count,
        file_delete_count,
        hidden_file_count,
        permission_change_count,
        disk_write_rate
    )

# -----------------------------
# Main collector
# -----------------------------
def collect_features(window_size_sec=60):
    current_user = getpass.getuser()
    window_start = time.time()
    window_end = window_start + window_size_sec

    net_io_start = psutil.net_io_counters()

    cpu_samples, mem_samples = [], []
    spawned_pids_counter = {}
    seen_commands = set()
    fs_results = {}

    def fs_worker():
        fc, fd, hid, perm, rate = collect_fs_stats(window_size_sec)
        fs_results["file_create_count"] = fc
        fs_results["file_delete_count"] = fd
        fs_results["hidden_file_count"] = hid
        fs_results["permission_change_count"] = perm
        fs_results["disk_write_rate"] = rate

    t = threading.Thread(target=fs_worker)
    t.start()

    last_proc_scan = 0
    while time.time() < window_end:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        cpu_samples.append(cpu)
        mem_samples.append(mem)

        now = time.time()
        if now - last_proc_scan >= 5:
            last_proc_scan = now
            for p in psutil.process_iter(['pid','name','username','ppid','cmdline','create_time']):
                try:
                    spawned_pids_counter[p.info['name']] = spawned_pids_counter.get(p.info['name'], 0) + 1
                    if p.info['name'] in ("bash","sh","zsh"):
                        cmdline = " ".join(p.info['cmdline'])
                        if cmdline:
                            seen_commands.add((p.info['pid'], cmdline))
                except:
                    continue

    t.join()

    net_io_end = psutil.net_io_counters()
    bytes_sent_per_sec = (net_io_end.bytes_sent - net_io_start.bytes_sent) / max(window_size_sec, 1)
    bytes_recv_per_sec = (net_io_end.bytes_recv - net_io_start.bytes_recv) / max(window_size_sec, 1)
    inbound_outbound_ratio = (bytes_recv_per_sec + 1) / (bytes_sent_per_sec + 1)

    all_procs = list(psutil.process_iter(['pid','ppid','username','create_time','name']))
    background_ratio = sum(1 for p in all_procs if p.info.get('username') != current_user) / max(len(all_procs),1)
    orphan_count = sum(1 for p in all_procs if p.info['ppid'] == 1)
    long_running = sum(1 for p in all_procs if (time.time() - p.create_time()) > 3600)

    spawned_pids = sum(1 for v in spawned_pids_counter.values() if v == 1)
    unique_processes = len(spawned_pids_counter)
    shell_spawn_count = sum(1 for n in spawned_pids_counter if n in ("bash","sh","zsh"))

    commands_window = [cmd for pid, cmd in seen_commands]
    unique_commands = len(set(commands_window))
    avg_command_length = sum(len(c) for c in commands_window) / max(len(commands_window),1)
    
    #BEHAVIOUR FEATURES
    
    encoded_command_count = 0
    suspicious_command_count = 0
    pipe_usage_count = 0

    encoded_pattern = re.compile(r'base64|\\x[0-9a-fA-F]{2}')
    suspicious_keywords = ["nc", "netcat", "curl", "wget", "chmod", "chown", "scp", "ssh"]

    for cmd in commands_window:
        if encoded_pattern.search(cmd):
            encoded_command_count += 1
        if "|" in cmd:
            pipe_usage_count += 1
        if any(k in cmd for k in suspicious_keywords):
            suspicious_command_count += 1

    encoded_command_ratio = encoded_command_count / max(len(commands_window), 1)
    suspicious_command_ratio = suspicious_command_count / max(len(commands_window), 1)

    cpu_mean = sum(cpu_samples) / max(len(cpu_samples),1)
    mem_mean = sum(mem_samples) / max(len(mem_samples),1)
    cpu_spike_count = sum(1 for c in cpu_samples if c > 80)

    failed_login_count, successful_login_count, unique_users_attempted, root_login_attempts, sudo_command_count, avg_time_between_logins = parse_auth_log(window_start)

    current_pairs = [(p.info['pid'], p.info.get('ppid',0)) for p in all_procs]
    parent_child_score = compute_parent_child_score(current_pairs)

    total_connections, tcp_connections, udp_connections = total_network_connections()
    listening_ports = listening_ports_count()
    established_connections = established_connections_count()
    unique_remote_ip_count = unique_remote_ips()

    features = {
        "window_size_sec": window_size_sec,
        "failed_login_count": failed_login_count,
        "successful_login_count": successful_login_count,
        "unique_users_attempted": unique_users_attempted,
        "root_login_attempts": root_login_attempts,
        "sudo_command_count": sudo_command_count,
        "avg_time_between_logins": avg_time_between_logins,
        "process_spawn_rate": spawned_pids,
        "unique_process_count": unique_processes,
        "shell_spawn_count": shell_spawn_count,
        "parent_child_anomaly_score": parent_child_score,
        "background_process_ratio": background_ratio,
        "orphan_process_count": orphan_count,
        "long_running_process_count": long_running,
        "encoded_command_ratio": encoded_command_ratio,
        "unique_command_count": unique_commands,
        "suspicious_command_ratio": suspicious_command_ratio,
        "avg_command_length": avg_command_length,
        "pipe_usage_count": pipe_usage_count,
        "cpu_usage_mean": cpu_mean,
        "cpu_spike_count": cpu_spike_count,
        "memory_usage_mean": mem_mean,
        "disk_write_rate": fs_results.get("disk_write_rate",0.0),
        "file_create_count": fs_results.get("file_create_count",0),
        "file_delete_count": fs_results.get("file_delete_count",0),
        "hidden_file_count": fs_results.get("hidden_file_count",0),
        "permission_change_count": fs_results.get("permission_change_count",0),
        "total_network_connections": total_connections,
        "tcp_connections": tcp_connections,
        "udp_connections": udp_connections,
        "bytes_sent_per_sec": bytes_sent_per_sec,
        "bytes_recv_per_sec": bytes_recv_per_sec,
        "inbound_outbound_ratio": inbound_outbound_ratio,
        "listening_ports_count": listening_ports,
        "established_connections": established_connections,
        "unique_remote_ips": unique_remote_ip_count
    }

    file_path = os.path.join(DATA_DIR, f"host_{datetime.now().strftime('%Y%m%d%H%M%S')}.json")
    with open(file_path,"w") as f:
        json.dump(features,f,indent=4)

    print(f"[+] Saved snapshot: {file_path}")
    return file_path

# -----------------------------
# Main loop
# -----------------------------
if __name__ == "__main__":
    print("[*] Collector started (running indefinitely)...")
    cycle = 0
    while True:
        cycle += 1
        print(f"[*] Cycle {cycle}...")
        try:
            collect_features(60)
        except Exception as e:
            print(f"[!] Error in cycle {cycle}: {e}")
        time.sleep(5)
