import pandas as pd
import joblib
import json

FEATURES_PATH = "day4_features_fixed.csv"
MODEL_OUT = "model_rf.joblib"
META_OUT = "model_meta.json"
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
    from sklearn.ensemble import RandomForestClassifier

    df = pd.read_csv(FEATURES_PATH).fillna(0)
    X = df[FEATURE_COLS].values
    y = df["scenario"].values

    clf = RandomForestClassifier(
        n_estimators=200, random_state=RANDOM_SEED, class_weight="balanced"
    )
    clf.fit(X, y)

    joblib.dump(clf, MODEL_OUT)

    meta = {
        "feature_cols": FEATURE_COLS,
        "classes": sorted(set(y)),
        "n_training_sessions": len(df),
        "random_seed": RANDOM_SEED,
        "note": (
            "Trained on all 32 lab sessions (Day 3 data collection, "
            "5 classes). Day 5 cross-validated metrics (not this "
            "final fit) are the ones to cite for performance claims - "
            "this final model is for serving, not for reporting scores."
        ),
    }
    with open(META_OUT, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"Saved {MODEL_OUT} and {META_OUT}")
    print(f"Trained on {len(df)} sessions, classes: {sorted(set(y))}")

if __name__ == "__main__":
    main()
