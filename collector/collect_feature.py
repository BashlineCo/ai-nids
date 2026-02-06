"""
Real-Time IDS Collector - PRODUCTION v2
========================================
All bugs fixed from v1:

CRITICAL FIXES:
1. Filesystem thread: Remove thread for scanning fallback (blocks anyway)
2. CPU interval drift: Check time immediately after sample
3. SUID scan: Cache at startup (not every cycle)

MEDIUM FIXES:
4. Network I/O: Initialize in __init__ (no 0 on first run)
5. Auth log: Robust year rollover (try both years)
6. Syscall mapping: Document limitation, add more common syscalls

MINOR FIXES:
7. Feature validation: Check BEFORE saving
8. Checksum baseline: Add refresh option
9. Graceful shutdown: Close inotify properly
10. Thread errors: Track and report failures
11. Connection tracking: Document snapshot limitation
12. Scapy timing: Optimize thread coordination

Total: 40 features, 0 placeholders, production-hardened
"""

import os
import sys
import json
import time
import psutil
import getpass
import threading
import math
import pickle
import hashlib
import socket
import re
import signal
from datetime import datetime
from collections import Counter, deque
from stat import S_IMODE
from pathlib import Path

# Production improvements
try:
    import inotify_simple
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False
    print("[!] inotify_simple not available - filesystem monitoring disabled")
    print("[!] Install: pip install inotify-simple")

try:
    from scapy.all import sniff, DNS, TCP, Raw, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available - deep packet inspection disabled")
    print("[!] Install: pip install scapy")

# ============================================
# CONFIGURATION
# ============================================
DATA_DIR = Path(__file__).parent.parent / "data" / "raw"
DATA_DIR.mkdir(exist_ok=True, parents=True)

WINDOW_SIZE = 60
AUTH_LOG = "/var/log/auth.log"
AUDIT_LOG = "/var/log/audit/audit.log"
WATCH_PATHS = ["/tmp", "/var/tmp"]  # Narrow for performance

SUSPICIOUS_COMMANDS = [
    "nc", "ncat", "netcat", "socat", "wget", "curl",
    "base64", "xxd", "uuencode", "chmod +x", "chmod 777",
    "/dev/tcp", "/dev/udp", "python -c", "perl -e", "ruby -e",
    "bash -i", "sh -i",
]

SUSPICIOUS_KERNEL_MODULES = [
    "rootkit", "diamorphine", "reptile", "suterusu", "kovid", "umbreon",
]

SUSPICIOUS_PORTS = [
    4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321,
]

CRITICAL_BINARIES = [
    "/bin/bash", "/bin/sh", "/bin/ls", "/bin/ps",
    "/usr/bin/sudo", "/usr/bin/ssh", "/usr/bin/scp",
    "/usr/sbin/sshd", "/usr/bin/passwd",
]

BASELINE_PARENT_CHILD = DATA_DIR / "baseline_parent_child.pkl"
CHECKSUM_DB = DATA_DIR / "system_checksums.pkl"

# FIX #6: Expanded syscall mapping (x86_64)
SYSCALL_NAMES = {
    'execve': 59, 'fork': 57, 'clone': 56, 'vfork': 58,
    'ptrace': 101, 'init_module': 175, 'delete_module': 176, 'finit_module': 313,
    'socket': 41, 'connect': 42, 'bind': 49, 'listen': 50,
    'accept': 43, 'accept4': 288, 'sendto': 44, 'recvfrom': 45,
    'sendmsg': 46, 'recvmsg': 47, 'shutdown': 48,
    'open': 2, 'openat': 257, 'creat': 85, 'close': 3,
    'read': 0, 'write': 1, 'unlink': 87, 'unlinkat': 263,
    'chmod': 90, 'fchmod': 91, 'chown': 92, 'fchown': 93,
}

# Global shutdown flag
shutdown_requested = False


# ============================================
# COLLECTOR CLASS
# ============================================
class RealTimeCollector:
    def __init__(self, refresh_checksums=False):
        self.current_user = getpass.getuser()
        self.window_size = WINDOW_SIZE
        self.auth_log_position = 0
        self.audit_log_position = 0
        
        # FIX: Track inodes for log rotation detection
        self.auth_log_inode = None
        self.audit_log_inode = None
        
        # FIX #8: Option to refresh checksum baseline
        if refresh_checksums and CHECKSUM_DB.exists():
            print("[*] Refreshing checksum baseline...")
            CHECKSUM_DB.unlink()
        
        self.checksums = self._load_checksums()
        
        # FIX #4: Initialize network I/O counters (no 0 on first run)
        try:
            self.last_net_io = psutil.net_io_counters()
            self.last_net_io_time = time.time()
        except:
            self.last_net_io = None
            self.last_net_io_time = None
        
        # FIX #7: Cache SUID binaries at startup (not every cycle)
        print("[*] Scanning for SUID binaries...")
        self.suid_paths = self._find_suid_binaries()
        self.suid_last_refresh = time.time()  # FIX: Track refresh time
        print(f"[+] Found {len(self.suid_paths)} SUID/SGID binaries")
        
        # Filesystem Inotify Setup
        self.inotify = None
        self.watch_descriptors = {}
        if INOTIFY_AVAILABLE:
            try:
                self.inotify = inotify_simple.INotify()
                
                # FIX: Recursively watch directories with limit protection
                watch_count = 0
                max_watches = 8000  # Leave buffer below system limit (default: 8192)
                
                for path in WATCH_PATHS:
                    if not os.path.exists(path):
                        continue
                    
                    if watch_count >= max_watches:
                        print(f"[!] Reached watch limit ({max_watches}), stopping directory watches")
                        break
                    
                    # Watch root directory
                    try:
                        wd = self.inotify.add_watch(
                            path,
                            inotify_simple.flags.CREATE |
                            inotify_simple.flags.DELETE |
                            inotify_simple.flags.ATTRIB
                        )
                        self.watch_descriptors[wd] = path
                        watch_count += 1
                    except OSError as e:
                        if e.errno == 28:  # ENOSPC - out of inotify watches
                            print(f"[!] System inotify watch limit reached")
                            break
                        print(f"[!] Failed to watch {path}: {e}")
                        continue
                    
                    # Recursively watch existing subdirectories
                    # (New subdirectories created later won't be watched - this is a known limitation)
                    stop_watching = False
                    try:
                        for root, dirs, files in os.walk(path):
                            if stop_watching:
                                break
                            
                            for d in dirs:
                                if watch_count >= max_watches:
                                    print(f"[!] Reached watch limit ({max_watches}), skipping remaining subdirectories")
                                    stop_watching = True
                                    break
                                
                                subdir = os.path.join(root, d)
                                try:
                                    wd = self.inotify.add_watch(
                                        subdir,
                                        inotify_simple.flags.CREATE |
                                        inotify_simple.flags.DELETE |
                                        inotify_simple.flags.ATTRIB
                                    )
                                    self.watch_descriptors[wd] = subdir
                                    watch_count += 1
                                except OSError as e:
                                    if e.errno == 28:  # ENOSPC
                                        print(f"[!] System inotify watch limit reached at {watch_count} watches")
                                        stop_watching = True
                                        break
                                    # Skip directories we can't watch (permissions, etc.)
                                    pass
                                except:
                                    pass
                    except:
                        pass
                
                print(f"[+] inotify monitoring: {len(self.watch_descriptors)} directories")
            except Exception as e:
                print(f"[!] inotify initialization failed: {e}")
                self.inotify = None
        
        # Thread error tracking
        self.thread_errors = {}
        
        print("="*70)
        print(" Real-Time IDS Collector (PRODUCTION v2)")
        print("="*70)
        print(f"[*] Window: {self.window_size}s")
        print(f"[*] User: {self.current_user}")
        print(f"[*] Filesystem: {'inotify' if self.inotify else 'DISABLED (install inotify-simple)'}")
        print(f"[*] Deep packets: {'Scapy' if SCAPY_AVAILABLE else 'disabled'}")
        print(f"[*] Monitored binaries: {len(self.checksums)}")
        print("="*70)

    # ========================================
    # MAIN COLLECTION
    # ========================================
    def collect_snapshot(self):
        """Collect one 40-feature snapshot with strict timing"""
        window_start = time.time()
        window_end = window_start + self.window_size
        
        print(f"\n[*] Cycle start: {datetime.fromtimestamp(window_start).strftime('%H:%M:%S')}")
        
        # Reset thread errors
        self.thread_errors = {}
        
        # --- START ALL THREADS FIRST ---
        
        # Thread 1: Filesystem (only if inotify available)
        fs_results = {}
        fs_thread = None
        if self.inotify:
            fs_thread = threading.Thread(
                target=self._collect_filesystem_inotify,
                args=(fs_results, self.window_size),
                name="FilesystemThread"
            )
            fs_thread.start()
        else:
            # FIX #1: No thread for disabled filesystem monitoring
            fs_results = {
                'file_create_count': 0,
                'file_delete_count': 0,
                'permission_change_count': 0,
                'hidden_file_count': 0,
            }
        
        # Thread 2: Deep Network (Scapy)
        net_deep_results = {}
        net_thread = None
        if SCAPY_AVAILABLE:
            # FIX #12: Start Scapy slightly shorter to ensure it finishes before join
            net_thread = threading.Thread(
                target=self._collect_network_deep_threaded,
                args=(net_deep_results, self.window_size - 3),
                name="ScapyThread"
            )
            net_thread.start()
        else:
            net_deep_results = {
                'dns_request_count': 0,
                'suspicious_user_agents': 0,
                'tls_handshakes': 0,
            }
        
        # --- SEQUENTIAL COLLECTION (while threads run) ---
        
        process_metrics = self._collect_processes(window_start, window_end)
        auth_metrics = self._collect_auth(window_start)
        network_basic_metrics = self._collect_network_basic()
        syscall_metrics = self._collect_syscalls(window_start)
        integrity_metrics = self._collect_integrity(process_metrics['all_processes'], window_start)
        kernel_metrics = self._collect_kernel()
        
        # --- JOIN THREADS ---
        # Filesystem thread runs for full window (60s), we join after sequential work (~2s)
        # So it needs up to ~58s more to finish
        if fs_thread:
            fs_thread.join(timeout=60)  # Wait up to 60s (full window duration)
            if fs_thread.is_alive():
                print("[!] WARNING: Filesystem thread still running after 60s")
        
        # Scapy thread runs for ~57s, we join after ~2s, needs up to ~55s
        if net_thread:
            net_thread.join(timeout=60)  # Wait up to 60s
            if net_thread.is_alive():
                print("[!] WARNING: Scapy thread still running after 60s")
        
        # FIX #10: Check for thread errors
        if self.thread_errors:
            for thread_name, error in self.thread_errors.items():
                print(f"[!] {thread_name} error: {error}")
        
        # Merge network
        network_metrics = {**network_basic_metrics, **net_deep_results}
        
        # Combine all features
        snapshot = {
            'timestamp': window_start,
            'datetime': datetime.fromtimestamp(window_start).isoformat(),
            **auth_metrics,
            **process_metrics['summary'],
            **fs_results,
            **integrity_metrics,
            **kernel_metrics,
            **network_metrics,
            **syscall_metrics,
        }
        
        # FIX #7: Validate feature count BEFORE saving
        feature_count = len([k for k in snapshot.keys() if k not in ['timestamp', 'datetime']])
        if feature_count != 40:
            print(f"[!] WARNING: Expected 40 features, got {feature_count}")
            expected = {
                'failed_login_count', 'root_login_attempts', 'sudo_command_count', 'unusual_hour_logins',
                'unique_pid_count', 'unique_process_name_count', 'total_process_count',
                'shell_spawn_count', 'orphan_process_count', 'parent_child_anomaly_score',
                'encoded_command_ratio', 'suspicious_command_ratio', 'command_entropy', 'pipe_usage_count',
                'file_create_count', 'file_delete_count', 'hidden_file_count', 'permission_change_count',
                'system_binary_mod_count', 'checksum_mismatch_count', 'suid_binary_execution_count', 'shadow_file_accessed',
                'suspicious_kernel_modules',
                'cpu_usage_mean', 'cpu_spike_count', 'memory_usage_mean',
                'tcp_connections', 'udp_connections', 'bytes_sent_per_sec', 'bytes_recv_per_sec',
                'listening_ports_count', 'established_connections', 'failed_connections', 'suspicious_local_ports',
                'dns_request_count', 'suspicious_user_agents', 'tls_handshakes',
                'execve_count', 'network_syscalls_count', 'suspicious_syscalls_count'
            }
            missing = expected - set(snapshot.keys())
            if missing:
                print(f"[!] Missing features: {missing}")
                # Add missing with 0 values to maintain consistency
                for feat in missing:
                    snapshot[feat] = 0
                feature_count = 40
        
        print(f"[+] Features collected: {feature_count}/40")
        
        # Save
        filepath = self._save_snapshot(snapshot)
        
        return snapshot, filepath

    # ========================================
    # PROCESS & COMMAND MONITORING
    # ========================================
    def _collect_processes(self, window_start, window_end):
        """Monitor processes during window"""
        cpu_samples = []
        mem_samples = []
        seen_pids = set()
        process_names = Counter()
        shell_spawn_count = 0
        
        commands_seen_set = set()
        commands_seen_list = []
        
        last_scan = 0
        
        while time.time() < window_end:
            remaining = window_end - time.time()
            if remaining <= 0:
                break
            
            # CPU sampling with dynamic interval
            interval = min(1.0, remaining)
            try:
                cpu = psutil.cpu_percent(interval=interval)
                mem = psutil.virtual_memory().percent
                cpu_samples.append(cpu)
                mem_samples.append(mem)
            except:
                pass
            
            # FIX #2: Check time immediately after blocking call
            if time.time() >= window_end:
                break
            
            # Process scan every 2s (improved from 5s for short-lived processes)
            now = time.time()
            if now - last_scan >= 2 and now < window_end:
                last_scan = now
                try:
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                        pid = proc.info['pid']
                        name = proc.info['name']
                        
                        if pid not in seen_pids:
                            seen_pids.add(pid)
                            process_names[name] += 1
                            if name in ('bash', 'sh', 'zsh', 'fish'):
                                shell_spawn_count += 1
                        
                        if name in ('bash', 'sh', 'zsh', 'fish'):
                            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                            if cmdline and cmdline not in commands_seen_set:
                                commands_seen_set.add(cmdline)
                                commands_seen_list.append(cmdline)
                except:
                    continue
        
        # Final snapshot
        all_processes = list(psutil.process_iter(['pid', 'ppid', 'username', 'create_time', 'name', 'exe', 'cmdline']))
        
        orphan_count = sum(1 for p in all_processes if p.info.get('ppid') == 1)
        parent_child_pairs = [(p.info['pid'], p.info.get('ppid', 0)) for p in all_processes if p.info.get('pid')]
        parent_child_score = self._compute_parent_child_anomaly(parent_child_pairs)
        command_metrics = self._analyze_commands(commands_seen_list)
        
        cpu_mean = sum(cpu_samples) / max(len(cpu_samples), 1)
        mem_mean = sum(mem_samples) / max(len(mem_samples), 1)
        cpu_spikes = sum(1 for c in cpu_samples if c > 80)
        
        return {
            'summary': {
                'unique_pid_count': len(seen_pids),
                'unique_process_name_count': len(process_names),
                'total_process_count': len(all_processes),
                'shell_spawn_count': shell_spawn_count,
                'orphan_process_count': orphan_count,
                'parent_child_anomaly_score': parent_child_score,
                **command_metrics,
                'cpu_usage_mean': cpu_mean,
                'cpu_spike_count': cpu_spikes,
                'memory_usage_mean': mem_mean,
            },
            'all_processes': all_processes,
        }
    
    def _analyze_commands(self, commands):
        """Analyze commands with normalized entropy"""
        if not commands:
            return {
                'encoded_command_ratio': 0.0,
                'suspicious_command_ratio': 0.0,
                'command_entropy': 0.0,
                'pipe_usage_count': 0
            }
        
        encoded_count = sum(1 for c in commands if re.search(r'base64|\\x[0-9a-fA-F]{2}|eval|exec', c, re.I))
        suspicious_count = sum(1 for c in commands if any(s in c.lower() for s in SUSPICIOUS_COMMANDS))
        pipe_count = sum(1 for c in commands if '|' in c)
        
        # Normalized per-command entropy
        entropies = []
        for cmd in commands:
            if not cmd:
                continue
            freq = Counter(cmd)
            length = len(cmd)
            entropy = 0.0
            for count in freq.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
            entropies.append(entropy)
        
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        return {
            'encoded_command_ratio': encoded_count / len(commands),
            'suspicious_command_ratio': suspicious_count / len(commands),
            'command_entropy': avg_entropy,
            'pipe_usage_count': pipe_count,
        }
    
    def _compute_parent_child_anomaly(self, current_pairs):
        """Track parent-child relationships with capped baseline"""
        try:
            if BASELINE_PARENT_CHILD.exists():
                with open(BASELINE_PARENT_CHILD, 'rb') as f:
                    baseline = deque(pickle.load(f), maxlen=10000)
            else:
                baseline = deque(maxlen=10000)
        except:
            baseline = deque(maxlen=10000)
        
        if not baseline:
            baseline.extend(current_pairs)
            with open(BASELINE_PARENT_CHILD, 'wb') as f:
                pickle.dump(list(baseline), f)
            return 0.0
        
        baseline_set = set(baseline)
        current_set = set(current_pairs)
        new_pairs = current_set - baseline_set
        score = len(new_pairs) / max(len(current_set), 1)
        
        baseline.extend(new_pairs)
        with open(BASELINE_PARENT_CHILD, 'wb') as f:
            pickle.dump(list(baseline), f)
        
        return score

    # ========================================
    # AUTHENTICATION
    # ========================================
    def _collect_auth(self, window_start):
        """Parse auth.log with robust year rollover"""
        if not os.path.exists(AUTH_LOG) or not os.access(AUTH_LOG, os.R_OK):
            return {
                'failed_login_count': 0,
                'root_login_attempts': 0,
                'sudo_command_count': 0,
                'unusual_hour_logins': 0
            }
        
        failed = 0
        root_logins = 0
        sudo_count = 0
        login_hours = []
        
        try:
            # FIX: Check for log rotation using inode (more reliable than size)
            try:
                current_stat = os.stat(AUTH_LOG)
                current_size = current_stat.st_size
                current_inode = current_stat.st_ino
                
                # Initialize inode on first run
                if self.auth_log_inode is None:
                    self.auth_log_inode = current_inode
                
                # If inode changed OR size shrunk, log was rotated
                if current_inode != self.auth_log_inode or self.auth_log_position > current_size:
                    self.auth_log_position = 0
                    self.auth_log_inode = current_inode
            except:
                # If stat fails, reset position
                self.auth_log_position = 0
            
            with open(AUTH_LOG, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.auth_log_position)
                
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    
                    # FIX #5: Robust year rollover - try both years
                    timestamp_str = ' '.join(parts[:3])
                    current_year = datetime.now().year
                    timestamp_dt = None
                    
                    for year in [current_year, current_year - 1]:
                        try:
                            timestamp_dt = datetime.strptime(
                                f"{year} {timestamp_str}",
                                "%Y %b %d %H:%M:%S"
                            )
                            # Accept if within reasonable range (last 24h to now)
                            if window_start - 86400 <= timestamp_dt.timestamp() <= time.time():
                                break
                        except:
                            continue
                    
                    if not timestamp_dt:
                        continue
                    
                    # Filter by window
                    if timestamp_dt.timestamp() < window_start:
                        continue
                    
                    # Parse events
                    if "Failed password" in line:
                        failed += 1
                        login_hours.append(timestamp_dt.hour)
                    
                    elif ("Accepted password" in line or "Accepted publickey" in line):
                        if re.search(r'for\s+root', line):
                            root_logins += 1
                        login_hours.append(timestamp_dt.hour)
                    
                    elif "sudo:" in line and "COMMAND=" in line:
                        sudo_count += 1
                
                self.auth_log_position = f.tell()
        
        except Exception as e:
            print(f"[!] Auth log error: {e}")
        
        unusual = sum(1 for h in login_hours if h < 6 or h > 22)
        
        return {
            'failed_login_count': failed,
            'root_login_attempts': root_logins,
            'sudo_command_count': sudo_count,
            'unusual_hour_logins': unusual
        }

    # ========================================
    # SYSCALLS
    # ========================================
    def _collect_syscalls(self, window_start):
        """
        Parse auditd logs with syscall name support.
        
        NOTE: Syscall number mapping is x86_64 specific.
        For full portability, configure auditd to log syscall names.
        """
        if not os.path.exists(AUDIT_LOG) or not os.access(AUDIT_LOG, os.R_OK):
            return {
                'execve_count': 0,
                'network_syscalls_count': 0,
                'suspicious_syscalls_count': 0
            }
        
        execve = 0
        network = 0
        suspicious = 0
        
        try:
            # FIX: Check for log rotation using inode
            try:
                current_stat = os.stat(AUDIT_LOG)
                current_size = current_stat.st_size
                current_inode = current_stat.st_ino
                
                # Initialize inode on first run
                if self.audit_log_inode is None:
                    self.audit_log_inode = current_inode
                
                # If inode changed OR size shrunk, log was rotated
                if current_inode != self.audit_log_inode or self.audit_log_position > current_size:
                    self.audit_log_position = 0
                    self.audit_log_inode = current_inode
            except:
                self.audit_log_position = 0
            
            with open(AUDIT_LOG, 'r', errors='ignore') as f:
                f.seek(self.audit_log_position)
                
                for line in f:
                    # Parse timestamp
                    timestamp_match = re.search(r'msg=audit\((\d+\.\d+):', line)
                    if not timestamp_match:
                        continue
                    
                    timestamp = float(timestamp_match.group(1))
                    if timestamp < window_start:
                        continue
                    
                    # Parse syscall (name or number)
                    syscall_match = re.search(r'syscall=(\w+)', line)
                    if not syscall_match:
                        continue
                    
                    syscall_str = syscall_match.group(1)
                    
                    # Try as name first
                    if syscall_str.isalpha():
                        syscall_name = syscall_str
                    else:
                        # It's a number, map to name
                        syscall_num = int(syscall_str)
                        syscall_name = None
                        for name, num in SYSCALL_NAMES.items():
                            if num == syscall_num:
                                syscall_name = name
                                break
                    
                    if not syscall_name:
                        continue
                    
                    # Count by name
                    if syscall_name in ['execve', 'fork', 'clone', 'vfork']:
                        execve += 1
                    elif syscall_name in ['socket', 'connect', 'bind', 'listen', 'accept', 'accept4', 
                                          'sendto', 'recvfrom', 'sendmsg', 'recvmsg']:
                        network += 1
                    elif syscall_name in ['ptrace', 'init_module', 'delete_module', 'finit_module']:
                        suspicious += 1
                
                self.audit_log_position = f.tell()
        
        except Exception as e:
            print(f"[!] Audit log error: {e}")
        
        return {
            'execve_count': execve,
            'network_syscalls_count': network,
            'suspicious_syscalls_count': suspicious
        }

    # ========================================
    # NETWORK
    # ========================================
    def _collect_network_basic(self):
        """Collect instantaneous network metrics"""
        try:
            conns = psutil.net_connections(kind='inet')
            net_io = psutil.net_io_counters()
            now = time.time()
            
            # Calculate speeds
            sent_speed = 0.0
            recv_speed = 0.0
            if self.last_net_io and self.last_net_io_time:
                delta = now - self.last_net_io_time
                if delta > 0:
                    # FIX: Handle counter overflow/reset
                    sent_delta = net_io.bytes_sent - self.last_net_io.bytes_sent
                    recv_delta = net_io.bytes_recv - self.last_net_io.bytes_recv
                    
                    # If negative, counter wrapped around or reset (e.g. network restart)
                    # Just use 0 instead of huge negative number
                    if sent_delta >= 0 and recv_delta >= 0:
                        sent_speed = sent_delta / delta
                        recv_speed = recv_delta / delta
                    else:
                        # Counter reset detected, skip this measurement
                        sent_speed = 0.0
                        recv_speed = 0.0
            
            self.last_net_io = net_io
            self.last_net_io_time = now
            
            # Connection states
            tcp_count = sum(1 for c in conns if c.type == socket.SOCK_STREAM)
            udp_count = sum(1 for c in conns if c.type == socket.SOCK_DGRAM)
            listening = sum(1 for c in conns if c.status == psutil.CONN_LISTEN)
            established = sum(1 for c in conns if c.status == psutil.CONN_ESTABLISHED)
            
            # Failed connections (SYN_SENT, SYN_RECV, CLOSING, LAST_ACK)
            # NOTE: These are snapshots, not events. See documentation.
            failed = sum(1 for c in conns if c.status in [
                psutil.CONN_SYN_SENT,
                psutil.CONN_SYN_RECV,
                psutil.CONN_CLOSING,
                psutil.CONN_LAST_ACK
            ])
            
            # Suspicious ports
            suspicious_ports = 0
            for c in conns:
                if c.laddr:
                    if c.laddr.port in SUSPICIOUS_PORTS or c.laddr.port > 50000:
                        suspicious_ports += 1
            
            return {
                'tcp_connections': tcp_count,
                'udp_connections': udp_count,
                'bytes_sent_per_sec': sent_speed,
                'bytes_recv_per_sec': recv_speed,
                'listening_ports_count': listening,
                'established_connections': established,
                'failed_connections': failed,
                'suspicious_local_ports': suspicious_ports,
            }
        
        except Exception as e:
            print(f"[!] Network basic error: {e}")
            return {
                'tcp_connections': 0, 'udp_connections': 0,
                'bytes_sent_per_sec': 0.0, 'bytes_recv_per_sec': 0.0,
                'listening_ports_count': 0, 'established_connections': 0,
                'failed_connections': 0, 'suspicious_local_ports': 0,
            }

    def _collect_network_deep_threaded(self, result_dict, duration):
        """Threaded Scapy deep packet inspection (burst-proof, lightweight)"""
        try:
            dns_count = 0
            tls_count = 0
            suspicious_ua = 0
            suspicious_ua_patterns = ['curl', 'wget', 'python', 'scanner', 'sqlmap', 'nmap', 'masscan', 'nikto']
            
            def packet_callback(pkt):
                nonlocal dns_count, tls_count, suspicious_ua
                # DNS queries
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                    dns_count += 1
                # TLS handshakes
                if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                    if pkt.haslayer(Raw):
                        payload = bytes(pkt[Raw].load)
                        if len(payload) > 0 and payload[0] == 0x16:  # TLS handshake
                            tls_count += 1
                # User-Agent detection
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    try:
                        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                        if 'User-Agent:' in payload:
                            ua_lines = [line for line in payload.split('\r\n') if 'User-Agent:' in line]
                            if ua_lines:
                                ua = ua_lines[0].split('User-Agent:')[1].strip()
                                if any(pattern in ua.lower() for pattern in suspicious_ua_patterns):
                                    suspicious_ua += 1
                    except:
                        pass
            
            # Continuous sniffing for the duration, don't store packets
            sniff(timeout=duration, prn=packet_callback, store=False)
            
            result_dict.update({
                'dns_request_count': dns_count,
                'suspicious_user_agents': suspicious_ua,
                'tls_handshakes': tls_count,
            })
        
        except Exception as e:
            # FIX #10: Track thread error
            self.thread_errors['ScapyThread'] = str(e)
            result_dict.update({
                'dns_request_count': 0,
                'suspicious_user_agents': 0,
                'tls_handshakes': 0,
            })

    # ========================================
    # FILESYSTEM
    # ========================================
    def _collect_filesystem_inotify(self, results, duration):
        """Fast inotify-based monitoring (thread-safe, burst-proof)"""
        creates = 0
        deletes = 0
        attribs = 0
        hidden = 0
        start = time.time()
        
        try:
            # FIX: Poll inotify buffer every 0.5s to avoid overflow during bursts
            while time.time() - start < duration:
                remaining = duration - (time.time() - start)
                timeout_ms = min(500, int(remaining * 1000))  # 0.5s chunks or remaining time
                
                if timeout_ms <= 0:
                    break
                
                events = self.inotify.read(timeout=timeout_ms)
                
                for event in events:
                    if event.mask & inotify_simple.flags.CREATE:
                        creates += 1
                        if event.name and event.name.startswith('.'):
                            hidden += 1
                    
                    if event.mask & inotify_simple.flags.DELETE:
                        deletes += 1
                    
                    if event.mask & inotify_simple.flags.ATTRIB:
                        attribs += 1
            
            results.update({
                'file_create_count': creates,
                'file_delete_count': deletes,
                'permission_change_count': attribs,
                'hidden_file_count': hidden,
            })
        
        except Exception as e:
            # FIX #10: Track thread error
            self.thread_errors['FilesystemThread'] = str(e)
            results.update({
                'file_create_count': 0,
                'file_delete_count': 0,
                'permission_change_count': 0,
                'hidden_file_count': 0,
            })

    # ========================================
    # INTEGRITY
    # ========================================
    def _load_checksums(self):
        """Load or create checksum baseline"""
        try:
            if CHECKSUM_DB.exists():
                with open(CHECKSUM_DB, 'rb') as f:
                    checksums = pickle.load(f)
                print(f"[+] Loaded checksum baseline for {len(checksums)} binaries")
                return checksums
        except:
            pass
        
        # Create baseline
        print("[*] Creating checksum baseline...")
        checksums = {}
        for binary in CRITICAL_BINARIES:
            if os.path.exists(binary):
                try:
                    sha256 = hashlib.sha256()
                    with open(binary, 'rb') as f:
                        while chunk := f.read(8192):
                            sha256.update(chunk)
                    checksums[binary] = sha256.hexdigest()
                except:
                    continue
        
        if checksums:
            with open(CHECKSUM_DB, 'wb') as f:
                pickle.dump(checksums, f)
            print(f"[+] Created checksum baseline for {len(checksums)} binaries")
        
        return checksums
    
    def _find_suid_binaries(self):
        """
        FIX #3: Scan for SUID binaries at startup (cached).
        This is slow (~1-5s), so we only do it once.
        """
        suid_paths = set()
        search_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
        
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
            try:
                for root, dirs, files in os.walk(search_path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            st = os.stat(filepath)
                            if st.st_mode & 0o4000 or st.st_mode & 0o2000:
                                suid_paths.add(filepath)
                        except:
                            continue
            except:
                continue
        
        return suid_paths
    
    def _collect_integrity(self, all_processes, window_start):
        """Check system integrity (uses cached SUID list with periodic refresh)"""
        mismatches = 0
        modified = 0
        suid_execs = 0
        shadow_accessed = 0
        
        # FIX: Refresh SUID cache hourly to catch new SUID binaries
        if time.time() - self.suid_last_refresh > 3600:  # 1 hour
            print("[*] Refreshing SUID binary cache...")
            self.suid_paths = self._find_suid_binaries()
            self.suid_last_refresh = time.time()
            print(f"[+] SUID cache refreshed: {len(self.suid_paths)} binaries")
        
        # Check checksums
        for binary, expected in self.checksums.items():
            if not os.path.exists(binary):
                continue
            
            try:
                sha256 = hashlib.sha256()
                with open(binary, 'rb') as f:
                    while chunk := f.read(8192):
                        sha256.update(chunk)
                current = sha256.hexdigest()
                
                if current != expected:
                    mismatches += 1
                    modified += 1
                    print(f"[!] Binary modified: {binary}")
            except:
                continue
        
        # FIX #3: Use cached SUID paths (no scan every cycle)
        for proc in all_processes:
            try:
                exe = proc.info.get('exe')
                create_time = proc.info.get('create_time')
                
                if exe and exe in self.suid_paths and create_time and create_time >= window_start:
                    suid_execs += 1
            except:
                continue
        
        # Check /etc/shadow access
        try:
            if os.path.exists('/etc/shadow'):
                st = os.stat('/etc/shadow')
                if st.st_atime > time.time() - self.window_size:
                    shadow_accessed = 1
        except:
            pass
        
        return {
            'system_binary_mod_count': modified,
            'checksum_mismatch_count': mismatches,
            'suid_binary_execution_count': suid_execs,
            'shadow_file_accessed': shadow_accessed,
        }

    # ========================================
    # KERNEL
    # ========================================
    def _collect_kernel(self):
        """Check for suspicious kernel modules"""
        suspicious = 0
        suspicious_modules = []
        
        try:
            with open('/proc/modules', 'r') as f:
                for line in f:
                    parts = line.split()
                    if parts:
                        module_name = parts[0]
                        for sus in SUSPICIOUS_KERNEL_MODULES:
                            if sus.lower() in module_name.lower():
                                suspicious += 1
                                suspicious_modules.append(module_name)
                                break  # Only count once per module
        except:
            pass
        
        # Reduce log spam: summarize instead of printing each module
        if suspicious == 1:
            print(f"[!] Suspicious kernel module: {suspicious_modules[0]}")
        elif suspicious > 1:
            print(f"[!] {suspicious} suspicious kernel modules detected: {', '.join(suspicious_modules[:3])}{'...' if len(suspicious_modules) > 3 else ''}")
        
        return {'suspicious_kernel_modules': suspicious}

    # ========================================
    # SAVE & CLEANUP
    # ========================================
    def _save_snapshot(self, snapshot):
        """Save snapshot to JSON"""
        filename = f"host_{datetime.fromtimestamp(snapshot['timestamp']).strftime('%Y%m%d_%H%M%S')}.json"
        filepath = DATA_DIR / filename
        
        with open(filepath, 'w') as f:
            json.dump(snapshot, f, indent=2)
        
        print(f"[+] Saved: {filename}")
        return filepath
    
    def cleanup(self):
        """FIX #9: Graceful shutdown - close inotify properly"""
        print("[*] Cleaning up...")
        if self.inotify:
            try:
                # Close all watches
                for wd in self.watch_descriptors.keys():
                    try:
                        self.inotify.rm_watch(wd)
                    except:
                        pass
                # Close inotify
                os.close(self.inotify.fileno())
            except:
                pass
        print("[*] Cleanup complete")


# ============================================
# SIGNAL HANDLERS
# ============================================
def signal_handler(signum, frame):
    """FIX #9: Handle Ctrl+C gracefully"""
    global shutdown_requested
    shutdown_requested = True
    print("\n[*] Shutdown requested...")


# ============================================
# MAIN
# ============================================
def main():
    global shutdown_requested
    
    # Parse arguments
    import argparse
    parser = argparse.ArgumentParser(description='Real-Time IDS Collector v2')
    parser.add_argument('--refresh-checksums', action='store_true',
                       help='Refresh binary checksum baseline')
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print(" Real-Time IDS - 40 Feature Collector (PRODUCTION v2)")
    print("="*70)
    print()
    
    if os.geteuid() != 0:
        print("[!] WARNING: Not running as root")
        print("[!] Some features may be unavailable:")
        print("    - Auth/Audit logs (need read permission)")
        print("    - Scapy packet capture (needs CAP_NET_RAW)")
        print()
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    collector = RealTimeCollector(refresh_checksums=args.refresh_checksums)
    cycle = 0
    
    try:
        while not shutdown_requested:
            cycle += 1
            cycle_start = time.time()
            
            print(f"\n{'='*70}")
            print(f" CYCLE #{cycle}")
            print(f"{'='*70}")
            
            try:
                snapshot, filepath = collector.collect_snapshot()
            except Exception as e:
                print(f"[!] Collection error: {e}")
                import traceback
                traceback.print_exc()
            
            if shutdown_requested:
                break
            
            # Strict timing: ensure exactly 60s between cycle starts
            elapsed = time.time() - cycle_start
            if elapsed < WINDOW_SIZE:
                sleep_time = WINDOW_SIZE - elapsed
                print(f"[*] Sleeping {sleep_time:.1f}s to maintain 60s cycle")
                time.sleep(sleep_time)
            else:
                print(f"[!] WARNING: Cycle took {elapsed:.1f}s (>{WINDOW_SIZE}s)")
    
    finally:
        # FIX #9: Graceful cleanup
        collector.cleanup()
        print("\n[*] Goodbye!")


if __name__ == "__main__":
    main()
