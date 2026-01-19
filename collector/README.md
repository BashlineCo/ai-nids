#Feature Collector Documentation#
##Overview##

##This module is the host-level feature collector for the AI-based Intrusion Detection System. It continuously monitors the system and network to extract behavioral, process, filesystem, authentication, and network features. These features are saved as structured JSON snapshots and later used for machine learning–based anomaly detection (Isolation Forest).##

##The collector is designed to be lightweight, modular, and continuously running, making it suitable for real-time security monitoring and offline model training.##

Collection Strategy

Time-based sliding window (default: 60 seconds)

Continuous execution with short cooldown between cycles

Features engineered to capture abnormal behavior rather than signatures

Safe failure handling (missing logs, permission issues, etc.)

Feature Categories
#1. Authentication & Privilege Activity#

Extracted from /var/log/auth.log (if available).

Feature	Description
auth_log_present	Whether the auth log exists on the system
failed_login_count	Number of failed login attempts in the window
successful_login_count	Number of successful logins
unique_users_attempted	Count of unique users involved in login attempts
root_login_attempts	Number of successful root logins
sudo_command_count	Number of sudo command executions
avg_time_between_logins	Average time gap between login attempts

*Security relevance: Brute force attacks, privilege escalation, credential abuse.*

#2. Process & Execution Behavior#

Monitors running processes and execution patterns.

Feature	Description
process_spawn_rate	Number of processes spawned once in the window
unique_process_count	Total unique process names
shell_spawn_count	Count of spawned shell processes (bash, sh, zsh)
parent_child_anomaly_score	Novel parent-child process relationships
background_process_ratio	Ratio of background processes
orphan_process_count	Processes with PPID = 1
long_running_process_count	Processes running longer than 1 hour

*Security relevance: Malware execution, persistence, privilege abuse, living-off-the-land attacks.*

#3. Command-Line Behavior Analysis#

Analyzes shell command usage patterns.

Feature	Description
unique_command_count	Number of distinct commands executed
avg_command_length	Average command length
encoded_command_ratio	Ratio of base64/hex-encoded commands
suspicious_command_ratio	Ratio of commands containing risky keywords
pipe_usage_count	Number of commands using pipes (`	`)

Suspicious keywords monitored: nc, netcat, curl, wget, scp, ssh, chmod, chown

*Security relevance: Obfuscation, data exfiltration, lateral movement, payload download.*

#4. CPU & Memory Utilization#

Tracks system resource usage trends.

Feature	Description
cpu_usage_mean	Average CPU usage (%)
cpu_spike_count	Number of CPU spikes above 80%
memory_usage_mean	Average memory usage (%)

*Security relevance: Cryptominers, denial-of-service activity, resource abuse.*

#5. Filesystem Activity#

Monitors filesystem changes within watched directories (/home, /tmp).

Feature	Description
file_create_count	Number of files created
file_delete_count	Number of files deleted
hidden_file_count	Number of new hidden files
permission_change_count	File permission changes
disk_write_rate	Disk write bytes per second

*Security relevance: Malware dropper behavior, data tampering, persistence artifacts.*

#6. Network Activity#

Captures host-level network behavior.

Feature	Description
total_network_connections	Total active connections
tcp_connections	TCP connection count
udp_connections	UDP connection count
listening_ports_count	Number of listening ports
established_connections	Established connections
unique_remote_ips	Count of unique remote IPs
bytes_sent_per_sec	Outbound traffic rate
bytes_recv_per_sec	Inbound traffic rate
inbound_outbound_ratio	Traffic direction imbalance

*Security relevance: Command-and-control activity, scanning, data exfiltration.*
