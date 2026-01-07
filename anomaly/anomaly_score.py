def score(features):
#dict of engineered feat, returns anomaly score 0-1
    score = 0

    score += features["process_spawn_rate"] * 0.1
    score += features["shell_spawn_count"] * 0.2
    score += features["orphan_process_count"] * 0.3
    score += features["long_running_process_count"] * 0.2

    # normalise to max 1
    return min(score, 1.0)

