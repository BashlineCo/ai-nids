import os
import json
import pickle
import numpy as np
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler, MinMaxScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

# -----------------------------
# Configuration
# -----------------------------
DATA_DIR = "/home/eyerin/projects/ai-nids/data/raw"
ARTIFACT_PATH = os.path.join(os.path.dirname(__file__), "nids_model_artifact.pkl")

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
        # logging.FileHandler("nids_detector.log") # Uncomment for file logging
    ]
)

# -----------------------------
# Features Registry
# -----------------------------
FEATURE_KEYS = [
    # Authentication
    "failed_login_count", "root_login_attempts", "sudo_command_count", "unusual_hour_logins",
    # Process
    "unique_pid_count", "unique_process_name_count", "total_process_count", 
    "shell_spawn_count", "orphan_process_count", "parent_child_anomaly_score",
    "encoded_command_ratio", "suspicious_command_ratio", "command_entropy", "pipe_usage_count",
    # Filesystem
    "file_create_count", "file_delete_count", "hidden_file_count", "permission_change_count",
    # Integrity
    "system_binary_mod_count", "checksum_mismatch_count", 
    "suid_binary_execution_count", "shadow_file_accessed",
    # Kernel
    "suspicious_kernel_modules",
    # Resource
    "cpu_usage_mean", "cpu_spike_count", "memory_usage_mean",
    # Network (basic)
    "tcp_connections", "udp_connections", "bytes_sent_per_sec", "bytes_recv_per_sec",
    "listening_ports_count", "established_connections", "failed_connections", "suspicious_local_ports",
    # Network (deep)
    "dns_request_count", "suspicious_user_agents", "tls_handshakes",
    # Syscalls
    "execve_count", "network_syscalls_count", "suspicious_syscalls_count",
]

class AnomalyDetector:
    def __init__(self, contamination="auto"):
        self.contamination = contamination
        self.pipeline = None
        self.score_scaler = None # To normalize raw anomaly scores to 0-100
        self.feature_map = FEATURE_KEYS 
        self.is_fitted = False

    def _extract_features(self, snapshot):
        """
        Extracts features in exact order. 
        Returns None for missing keys (to be handled by Imputer), NOT zero.
        """
        return [float(snapshot.get(k)) if k in snapshot and snapshot.get(k) is not None else np.nan for k in self.feature_map]

    def train(self, snapshots):
        """
        Train the model using a list of feature dictionaries.
        """
        logging.info("Preparing training data...")
        X = []
        for snapshot in snapshots:
            X.append(self._extract_features(snapshot))
        
        X = np.array(X)
        
        # Pipeline: Impute -> Scale -> Model
        # Note: IsolationForest is not a transformer, so we handle it separately
        # or use it as the final estimator. Here we separate preprocessing.
        
        self.preprocessor = Pipeline([
            ('imputer', SimpleImputer(strategy='median')), # Fix: Handle missing data smartly
            ('scaler', RobustScaler()) # Fix: Handle outliers in training data
        ])
        
        X_processed = self.preprocessor.fit_transform(X)

        logging.info(f"Training IsolationForest on {len(X)} records (Contamination: {self.contamination})...")
        self.model = IsolationForest(
            contamination=self.contamination, 
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_processed)
        
        # Fix: Calibrate Score Output
        # We calculate scores on training data to establish a baseline for "0-100" normalization
        raw_scores = -self.model.score_samples(X_processed) # Higher = more anomalous
        self.score_scaler = MinMaxScaler(feature_range=(0, 100))
        self.score_scaler.fit(raw_scores.reshape(-1, 1))

        self.is_fitted = True
        logging.info("Model trained and calibrated.")
        self.save()

    def score(self, snapshot):
        """
        Returns dictionary with normalized severity score (0-100).
        """
        if not self.is_fitted:
            self.load()

        # Validation
        missing = [k for k in self.feature_map if k not in snapshot]
        if missing:
            logging.warning(f"Snapshot missing keys (using median imputation): {missing}")

        # Prepare vector
        row = self._extract_features(snapshot)
        row_array = np.array([row])
        
        # Preprocess
        try:
            X_processed = self.preprocessor.transform(row_array)
        except ValueError as e:
            logging.error(f"Preprocessing failed: {e}")
            return None

        # 1. Binary Decision (Is it anomalous according to the forest?)
        is_anomaly_binary = self.model.predict(X_processed)[0] == -1

        # 2. Raw Score (Higher = More Anomalous)
        raw_score = -self.model.score_samples(X_processed)[0]

        # 3. Normalized Severity (0-100) based on training distribution
        # Clip ensures we don't go below 0 or above 100 drastically if new data is extreme
        severity = self.score_scaler.transform([[raw_score]])[0][0]
        severity = float(np.clip(severity, 0, 100))

        # Heuristic: If binary model says anomaly but score is low, trust binary.
        # If score is high (e.g. > 90), it's critical.
        
        return {
            "severity_score": round(severity, 2),
            "is_anomaly": is_anomaly_binary,
            "raw_score": round(raw_score, 4),
            "status": "CRITICAL" if severity > 80 else ("WARNING" if is_anomaly_binary else "NORMAL")
        }

    def save(self):
        artifact = {
            "model": self.model,
            "preprocessor": self.preprocessor,
            "score_scaler": self.score_scaler,
            "feature_map": self.feature_map,
            "contamination": self.contamination
        }
        with open(ARTIFACT_PATH, "wb") as f:
            pickle.dump(artifact, f)
        logging.info(f"Artifact saved to {ARTIFACT_PATH}")

    def load(self):
        if not os.path.exists(ARTIFACT_PATH):
            raise FileNotFoundError("Model artifact not found. Train first.")
        
        with open(ARTIFACT_PATH, "rb") as f:
            artifact = pickle.load(f)
        
        self.model = artifact["model"]
        self.preprocessor = artifact["preprocessor"]
        self.score_scaler = artifact.get("score_scaler") # Handle legacy artifacts if needed
        self.feature_map = artifact["feature_map"]
        self.contamination = artifact.get("contamination", "auto")
        self.is_fitted = True
        logging.info("Model artifact loaded.")

# -----------------------------
# Data Loader (Generator)
# -----------------------------
def load_snapshots(data_dir):
    """Yields (filename, data) tuples to save memory"""
    json_files = sorted([f for f in os.listdir(data_dir) if f.endswith(".json")])
    for f in json_files:
        path = os.path.join(data_dir, f)
        try:
            with open(path) as jf:
                data = json.load(jf)
                yield f, data
        except (json.JSONDecodeError, OSError) as e:
            logging.error(f"Failed to read {f}: {e}")

# -----------------------------
# Main Execution
# -----------------------------
if __name__ == "__main__":
    detector = AnomalyDetector()

    # TRAIN MODE
    # In a real CLI, use argparse to switch between train/score
    train_mode = True 
    
    if train_mode:
        logging.info("Starting Training Run...")
        # Accumulate data for training (IsoForest requires full dataset for fit)
        training_data = []
        for _, data in load_snapshots(DATA_DIR):
            training_data.append(data)
        
        if training_data:
            detector.train(training_data)
        else:
            logging.error("No training data found.")

    # SCORE MODE
    logging.info("Starting Scoring Run...")
    results = []
    
    # We reload the generator to simulate a fresh stream of data
    for fname, data in load_snapshots(DATA_DIR):
        result = detector.score(data)
        if result:
            results.append((fname, result))

    # Sort by Severity
    results.sort(key=lambda x: x[1]['severity_score'], reverse=True)

    print("\n" + "="*80)
    print(f"{'FILENAME':<35} | {'STATUS':<10} | {'SEVERITY (0-100)':<18} | {'RAW':<8}")
    print("="*80)
    
    for fname, res in results:
        # Visual cues
        status = res['status']
        severity = res['severity_score']
        
        if status == "CRITICAL":
            row_str = f"\033[91m{fname:<35} | {status:<10} | {severity:<18} | {res['raw_score']}\033[0m"
        elif status == "WARNING":
            row_str = f"\033[93m{fname:<35} | {status:<10} | {severity:<18} | {res['raw_score']}\033[0m"
        else:
            row_str = f"{fname:<35} | {status:<10} | {severity:<18} | {res['raw_score']}"
            
        print(row_str)
