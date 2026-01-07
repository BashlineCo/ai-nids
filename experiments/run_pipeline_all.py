import json
import os
from features.feature_engineering import extract_features
from anomaly.anomaly_score import score

fake_folder = "/home/eyerin/projects/ai-nids/data/fake"

#loops json files
for file_name in os.listdir(fake_folder):
    if file_name.endswith(".json"):
        file_path = os.path.join(fake_folder, file_name)
        
        with open(file_path) as f:
            raw = json.load(f)
        
        features = extract_features(raw)
        anomaly_score = score(features)
        
        print(f"{file_name} -> Anomaly Score: {anomaly_score}")

