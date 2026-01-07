import json
import random
import os

#json storage
output_folder = "/home/eyerin/projects/ai-nids/data/fake"

#makes folder exist
os.makedirs(output_folder, exist_ok=True)

#no. of jsons
num_files = 50
for i in range(1, num_files + 1):
    fake_data = {
        "window_size_sec": 60,
        "process_spawn_rate": random.randint(0, 10),
        "unique_process_count": random.randint(1, 20),
        "shell_spawn_count": random.randint(0, 5),
        "parent_child_anomaly_score": round(random.uniform(0.0, 1.0), 2),
        "background_process_ratio": round(random.uniform(0.0, 1.0), 2),
        "orphan_process_count": random.randint(0, 3),
        "long_running_process_count": random.randint(0, 5)
    }

    file_name = f"fake_{i}.json"
    file_path = os.path.join(output_folder, file_name)

    with open(file_path, "w") as f:
        json.dump(fake_data, f, indent=4)

print(f"{num_files} fake JSON files generated in {output_folder}")

