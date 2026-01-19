AI-Based Hybrid Network Intrusion Detection System (NIDS)
🚀 Project Overview

This project is an AI-powered Hybrid Network Intrusion Detection System (NIDS) designed to monitor host-level and network-level behavior and detect anomalies using Machine Learning (Isolation Forest).

Unlike traditional signature-based IDS tools, this system learns normal behavior automatically and flags deviations that may indicate:

Malware activity

Lateral movement

Privilege escalation

Data exfiltration

Brute-force or suspicious authentication behavior

⚠️ Designed as a learning + research-grade cybersecurity project, inspired by real SOC and EDR systems.

🧠 Key Concept

This is a Hybrid NIDS, meaning it combines:

Host-based monitoring (HIDS)

Processes

File system

Authentication logs

Command behavior

Network-based monitoring (NIDS)

Active connections

Traffic rates

Ports and remote IPs

All collected features are fed into a Machine Learning model (Isolation Forest) for anomaly detection.

🛠️ Tech Stack

Python 3

psutil – system & network monitoring

Isolation Forest (scikit-learn) – anomaly detection

Linux (Ubuntu recommended)

JSON-based feature snapshots

📊 Features Collected
🔐 Authentication Features

failed_login_count

successful_login_count

unique_users_attempted

root_login_attempts

sudo_command_count

avg_time_between_logins

auth_log_present ⚠️ (log tampering signal)

⚙️ Process & Behavior Features

process_spawn_rate

unique_process_count

shell_spawn_count

parent_child_anomaly_score

background_process_ratio

orphan_process_count

long_running_process_count

🧪 Command Behavior Features

encoded_command_ratio (base64 / hex usage)

suspicious_command_ratio (wget, curl, nc, etc.)

pipe_usage_count

unique_command_count

avg_command_length

💾 Filesystem Features

file_create_count

file_delete_count

hidden_file_count

permission_change_count

disk_write_rate

🌐 Network (NIDS) Features

total_network_connections

tcp_connections

udp_connections

bytes_sent_per_sec

bytes_recv_per_sec

inbound_outbound_ratio

listening_ports_count

established_connections

unique_remote_ips

These features allow detection of malware beacons, scans, C2 traffic, and data exfiltration.

🤖 Machine Learning Model
Isolation Forest

Unsupervised learning (no labeled attacks needed)

Learns what "normal" behavior looks like

Flags rare or abnormal behavior as anomalies

Why Isolation Forest?

Scales well

Works with high-dimensional data

Commonly used in real SOC anomaly systems

🔁 How the System Works

Collector runs every 60 seconds

Extracts host + network features

Saves snapshot as JSON

ML model scores snapshot

High anomaly score → potential intrusion
