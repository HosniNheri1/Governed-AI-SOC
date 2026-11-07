import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix

FEATURES_PATH = "day4_features_fixed.csv"
RANDOM_SEED = 42

FEATURE_COLS = [
    "n_events", "duration_sec", "events_per_sec",
    "mean_interarrival_sec", "std_interarrival_sec",
    "n_unique_victim_ports", "n_flow_events",
    "bytes_toserver", "bytes_toclient",
    "pkts_toserver", "pkts_toclient",
    "tcp_syn_count", "tcp_rst_count", "tcp_fin_count", "tcp_ack_count",
    "n_ftp_events", "n_http_events", "n_ssh_events",
    "ftp_fail_rate", "n_http_post",
]

def main():
    df = pd.read_csv(FEATURES_PATH)
    df = df.fillna(0)

    X = df[FEATURE_COLS].values
    y = df["scenario"].values
    sessions = df["session_id"].values

    print(f"Dataset: {len(df)} sessions, {len(FEATURE_COLS)} features")
    print("Class counts:", pd.Series(y).value_counts().to_dict())

    n_splits = 5
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_SEED)

    all_true, all_pred = [], []

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y), start=1):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        sess_test = sessions[test_idx]

        clf = RandomForestClassifier(
            n_estimators=200, random_state=RANDOM_SEED, class_weight="balanced"
        )
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        all_true.extend(y_test)
        all_pred.extend(y_pred)

        print(f"\n--- Fold {fold} --- test sessions: {list(sess_test)}")
        print(classification_report(y_test, y_pred, zero_division=0))

    print("\n================ AGGREGATE (all folds pooled) ================")
    print(classification_report(all_true, all_pred, zero_division=0))

    labels = sorted(set(y))
    cm = confusion_matrix(all_true, all_pred, labels=labels)
    print("Confusion matrix (rows=true, cols=pred):")
    print("Labels:", labels)
    print(cm)

    print("\n================ Isolation Forest (benign-only training) ================")
    benign_mask = y == "benign"
    iso = IsolationForest(random_state=RANDOM_SEED, contamination="auto")
    iso.fit(X[benign_mask])

    iso_pred_raw = iso.predict(X)
    iso_pred = np.where(iso_pred_raw == -1, "attack", "benign")
    y_binary = np.where(y == "benign", "benign", "attack")

    print(classification_report(y_binary, iso_pred, zero_division=0))
    print("Confusion matrix (rows=true, cols=pred), labels=[attack,benign]:")
    print(confusion_matrix(y_binary, iso_pred, labels=["attack", "benign"]))

    print("\n================ Feature importance (last fold's RF) ================")
    importances = sorted(
        zip(FEATURE_COLS, clf.feature_importances_), key=lambda t: -t[1]
    )
    for name, imp in importances:
        print(f"  {name:30s} {imp:.4f}")

if __name__ == "__main__":
    main()
