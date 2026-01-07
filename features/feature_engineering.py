def extract_features(raw_data): #dict log info, returns dict with engineered features
    features={
        "window_size_sec": raw_data.get("window_size_sec", 60),
        "process_spawn_rate": raw_data.get("process_spawn_rate", 0),
        "unique_process_count": raw_data.get("unique_process_count", 0),
        "shell_spawn_count": raw_data.get("shell_spawn_count", 0),
        "parent_child_anomaly_score": raw_data.get("parent_child_anomaly_score", 0.0),
        "background_process_ratio": raw_data.get("background_process_ratio", 0.0),
        "orphan_process_count": raw_data.get("orphan_process_count", 0),
        "long_running_process_count": raw_data.get("long_running_process_count", 0)
    }
    
    return features



  
