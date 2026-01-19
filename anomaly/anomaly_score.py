import os
import json
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# -----------------------------
# Paths
# -----------------------------
DATA_DIR = "/home/eyerin/projects/ai-nids/data/raw"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")

# -----------------------------
# Features (must match collector)
# -----------------------------
FEATURE_KEYS = [
    "auth_log_present",
    "failed_login_count",
    "successful_login_count",
    "unique_users_attempted",
    "root_login_attempts",
    "sudo_command_count",
    "avg_time_between_logins",
    "process_spawn_rate",
    "unique_process_count",
    "shell_spawn_count",
    "parent_child_anomaly_score",
    "background_process_ratio",
    "orphan_process_count",
    "long_running_process_count",
    "encoded_command_ratio",
    "unique_command_count",
    "suspicious_command_ratio",
    "avg_command_length",
    "pipe_usage_count",
    "cpu_usage_mean",
    "cpu_spike_count",
    "memory_usage_mean",
    "disk_write_rate",
    "file_create_count",
    "file_delete_count",
    "hidden_file_count",
    "permission_change_count"
    "total_network_connections"
    "tcp_connections"
    "udp_connections"
    "bytes_sent_per_sec"
    "bytes_recv_per_sec"
    "inbound_outbound_ratio"
    "listening_ports_count"
    "established_connections"
    "unique_remote_ips",
]

# -----------------------------
# Train Isolation Forest
# -----------------------------
def train(features_list):
    X = []
    for f in features_list:
        row = [float(f.get(k, 0)) for k in FEATURE_KEYS]
        X.append(row)
    X = np.array(X)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_scaled)

    # Save model + scaler
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    return model

# -----------------------------
# Score new data
# -----------------------------
def score(features):
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("Train the model first using train()")

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)

    row = [float(features.get(k, 0)) for k in FEATURE_KEYS]
    X_scaled = scaler.transform([row])

    raw_score = model.decision_function(X_scaled)[0]  # higher = more normal
    anomaly_score = 1 - (raw_score + 1) / 2
    anomaly_score = min(max(anomaly_score, 0.0), 1.0)
    return anomaly_score

# -----------------------------
# Main: score all JSON snapshots
# -----------------------------
if __name__ == "__main__":
    json_files = sorted([f for f in os.listdir(DATA_DIR) if f.endswith(".json")])
    results = []

    for f in json_files:
        path = os.path.join(DATA_DIR, f)
        with open(path) as jf:
            features = json.load(jf)
        anomaly = score(features)
        results.append((f, anomaly))

    # Sort by anomaly descending
    results.sort(key=lambda x: x[1], reverse=True)

    print("[!] Anomaly scores for all snapshots:")
    for fname, score_val in results:
        print(f"{fname}: {score_val:.3f}")

