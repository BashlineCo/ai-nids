import numpy as np
from sklearn.ensemble import IsolationForest
import os
import pickle

#to load or save trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")

def train(features_list):
    """
    Train Isolation Forest on a list of feature dicts.
    Each element in features_list is a dict of features.
    """
    #dict lists->2d array
    X = np.array([[f["process_spawn_rate"],
                   f["shell_spawn_count"],
                   f["orphan_process_count"],
                   f["long_running_process_count"]] for f in features_list])
    
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    #saves model for later use
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    
    return model

def score(features):
#given a feature dict, returns anomaly score between 0 and 1,1=most anomalous, 0=most normal
#loads the trained model
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Isolation Forest model not found. Train it first with train()")
    
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    
    X = np.array([[features["process_spawn_rate"],
                   features["shell_spawn_count"],
                   features["orphan_process_count"],
                   features["long_running_process_count"]]])
    
 # predict returns -1 for anomaly, 1 for normal
    pred = model.predict(X)[0]
    # decision_function returns higher = more normal, lower = more anomalous
    raw_score = model.decision_function(X)[0]
    
    # convert to 0-1 anomaly score: 1 = most anomalous
    anomaly_score = float((1 - model.score_samples(X)[0]) / 2)  # simple normalization
    if pred == -1:
        anomaly_score = max(anomaly_score, 0.5)  # make anomalies higher than normal
    return anomaly_score
