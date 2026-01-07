import json
import os
from features.feature_engineering import extract_features
from anomaly.anomaly_score import train

fake_folder = "/home/eyerin/projects/ai-nids/data/fake"
features_list = []

#loads fake jsons, extracts features
for file_name in os.listdir(fake_folder):
    if file_name.endswith(".json"):
        file_path = os.path.join(fake_folder, file_name)
        with open(file_path) as f:
            raw = json.load(f)
        features = extract_features(raw)
        features_list.append(features)

#trains isolationforest
train(features_list)
print(f"Isolation Forest trained on {len(features_list)} samples and model saved.")

