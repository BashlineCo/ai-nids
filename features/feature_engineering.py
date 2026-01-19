def extract_features(raw_data):
    features = {
        # Metadata
        "window_size_sec": raw_data.get("window_size_sec", 60),

        # Login / Authentication
        "auth_log_present": raw_data.get("auth_log_present", 0),
        "failed_login_count": raw_data.get("failed_login_count", 0),
        "successful_login_count": raw_data.get("successful_login_count", 0),
        "unique_users_attempted": raw_data.get("unique_users_attempted", 0),  # <- FIXED
        "root_login_attempts": raw_data.get("root_login_attempts", 0),
        "sudo_command_count": raw_data.get("sudo_command_count", 0),
        "avg_time_between_logins": raw_data.get("avg_time_between_logins", 0.0),

        # Processes & shells
        "process_spawn_rate": raw_data.get("process_spawn_rate", 0),
        "unique_process_count": raw_data.get("unique_process_count", 0),
        "shell_spawn_count": raw_data.get("shell_spawn_count", 0),
        "parent_child_anomaly_score": raw_data.get("parent_child_anomaly_score", 0.0),
        "background_process_ratio": raw_data.get("background_process_ratio", 0.0),
        "orphan_process_count": raw_data.get("orphan_process_count", 0),
        "long_running_process_count": raw_data.get("long_running_process_count", 0),
        "auth_log_present": auth_log_presen

        # Commands / Behavior
        "encoded_command_ratio": raw_data.get("encoded_command_ratio", 0.0),
        "unique_command_count": raw_data.get("unique_command_count", 0),
        "suspicious_command_ratio": raw_data.get("suspicious_command_ratio", 0.0),
        "avg_command_length": raw_data.get("avg_command_length", 0.0),
        "pipe_usage_count": raw_data.get("pipe_usage_count", 0),

        # Resource usage
        "cpu_usage_mean": raw_data.get("cpu_usage_mean", 0.0),
        "cpu_spike_count": raw_data.get("cpu_spike_count", 0),  # <- MATCH anomaly_score.py
        "memory_usage_mean": raw_data.get("memory_usage_mean", 0.0),

        # Filesystem
        "disk_write_rate": raw_data.get("disk_write_rate", 0.0),
        "file_create_count": raw_data.get("file_create_count", 0),
        "file_delete_count": raw_data.get("file_delete_count", 0),
        "hidden_file_count": raw_data.get("hidden_file_count", 0),
        "permission_change_count": raw_data.get("permission_change_count", 0)
        # Network
        "total_network_connections": raw_data.get("total_network_connections", 0),
        "tcp_connections": raw_data.get("tcp_connections", 0),
        "udp_connections": raw_data.get("udp_connections", 0),
        "bytes_sent_per_sec": raw_data.get("bytes_sent_per_sec", 0.0),
        "bytes_recv_per_sec": raw_data.get("bytes_recv_per_sec", 0.0),
        "inbound_outbound_ratio": raw_data.get("inbound_outbound_ratio", 0.0),
        "listening_ports_count": raw_data.get("listening_ports_count", 0),
        "established_connections": raw_data.get("established_connections", 0),
        "unique_remote_ips": raw_data.get("unique_remote_ips", 0)
    }

    return features

