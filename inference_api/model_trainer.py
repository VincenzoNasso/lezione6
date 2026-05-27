
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

RANDOM_STATE = 42
N_SAMPLES = 10000
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")


def generate_dataset(n_samples: int = N_SAMPLES):
    rng = np.random.default_rng(RANDOM_STATE)

    
    n_benign = int(n_samples * 0.6)
    n_malicious = n_samples - n_benign

    # ---- TRAFFICO BENIGNO ----
    benign = np.column_stack([
        rng.normal(500, 50, n_benign),                        # packet_size
        rng.uniform(1, 10, n_benign),                         # request_rate
        rng.uniform(0.1, 2.0, n_benign),                      # connection_duration
        rng.uniform(3.0, 6.0, n_benign),                      # payload_entropy
        rng.uniform(5, 15, n_benign),                         # header_count
        rng.beta(1, 20, n_benign),                            # error_rate
        rng.integers(1, 6, n_benign).astype(float),           # unique_endpoints
        rng.normal(1000, 200, n_benign),                      # byte_variance
    ])

    # ---- TRAFFICO MALIGNO ----
    malicious = np.column_stack([
        rng.uniform(1400, 2000, n_malicious),                  # packet_size
        rng.uniform(50, 200, n_malicious),                     # request_rate
        rng.uniform(20, 120, n_malicious),                     # connection_duration (Slowloris)
        rng.uniform(6.5, 8.0, n_malicious),                    # payload_entropy (SQLi)
        rng.uniform(20, 50, n_malicious),                      # header_count
        rng.uniform(0.3, 0.9, n_malicious),                    # error_rate
        rng.integers(1, 3, n_malicious).astype(float),         # unique_endpoints (concentrato)
        rng.normal(5000, 800, n_malicious),                    # byte_variance
    ])

    X = np.vstack([benign, malicious])
    y = np.array([0] * n_benign + [1] * n_malicious)

    
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def train():
    print("[model_trainer] Generazione dataset...")
    X, y = generate_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    print(f"[model_trainer] Train: {len(X_train)}, Test: {len(X_test)}")

    clf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=RANDOM_STATE, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("[model_trainer] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    joblib.dump(clf, MODEL_PATH)
    print(f"[model_trainer] Modello salvato in {MODEL_PATH}")


if __name__ == "__main__":
    train()
