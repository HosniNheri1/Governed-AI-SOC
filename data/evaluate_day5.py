import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_score, recall_score, f1_score

LABELED_PATH = "day4_labeled_fixed.csv"
FEATURES_PATH = "day4_features_fixed.csv"
RANDOM_SEED = 42

LOCAL_SIDS = {9000001, 9000002, 9000003, 9000004}

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

def suricata_flags_per_session(labeled_path):
    df = pd.read_csv(labeled_path, low_memory=False)
    df = df[df["scenario"] != "unlabeled"]

    sid_col = "alert.signature_id"
    if sid_col not in df.columns:
        raise RuntimeError(f"Column {sid_col} not found - check labeled CSV columns")

    df["_local_alert"] = df[sid_col].isin(LOCAL_SIDS)
    flags = df.groupby("session_id")["_local_alert"].any()
    return flags

def model_oof_predictions(features_path):
    df = pd.read_csv(features_path).fillna(0)
    X = df[FEATURE_COLS].values
    y = df["scenario"].values
    sessions = df["session_id"].values

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    oof_pred = {}

    for train_idx, test_idx in skf.split(X, y):
        clf = RandomForestClassifier(
            n_estimators=200, random_state=RANDOM_SEED, class_weight="balanced"
        )
        clf.fit(X[train_idx], y[train_idx])
        preds = clf.predict(X[test_idx])
        for sid, p in zip(sessions[test_idx], preds):
            oof_pred[sid] = p

    return oof_pred, dict(zip(sessions, y))

def binary_metrics(y_true, y_pred, name):
    p = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
    r = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label=1, zero_division=0)

    tp = sum((t == 1 and p_ == 1) for t, p_ in zip(y_true, y_pred))
    fp = sum((t == 0 and p_ == 1) for t, p_ in zip(y_true, y_pred))
    fn = sum((t == 1 and p_ == 0) for t, p_ in zip(y_true, y_pred))
    tn = sum((t == 0 and p_ == 0) for t, p_ in zip(y_true, y_pred))
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print(f"\n--- {name} ---")
    print(f"Precision: {p:.3f}  Recall: {r:.3f}  F1: {f1:.3f}  FPR: {fpr:.3f}")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    return {"name": name, "precision": p, "recall": r, "f1": f1, "fpr": fpr,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}

def main():
    suricata_flags = suricata_flags_per_session(LABELED_PATH)
    oof_pred, true_scenario = model_oof_predictions(FEATURES_PATH)

    rows = []
    for session_id, scenario in true_scenario.items():
        true_binary = 0 if scenario == "benign" else 1
        suricata_flag = int(suricata_flags.get(session_id, False))
        model_label = oof_pred.get(session_id)
        model_flag = 0 if model_label == "benign" else 1
        hybrid_flag = int(suricata_flag or model_flag)

        rows.append({
            "session_id": session_id,
            "scenario": scenario,
            "true_binary": true_binary,
            "suricata_flag": suricata_flag,
            "model_flag": model_flag,
            "model_label": model_label,
            "hybrid_flag": hybrid_flag,
        })

    results = pd.DataFrame(rows)
    print("Per-session detection table:")
    print(results.to_string(index=False))

    y_true = results["true_binary"].tolist()

    summary = []
    summary.append(binary_metrics(y_true, results["suricata_flag"].tolist(), "Suricata alone"))
    summary.append(binary_metrics(y_true, results["model_flag"].tolist(), "Model alone (RF, out-of-fold)"))
    summary.append(binary_metrics(y_true, results["hybrid_flag"].tolist(), "Hybrid (Suricata OR model)"))

    print("\n================ SUMMARY TABLE ================")
    summary_df = pd.DataFrame(summary)[["name", "precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn"]]
    print(summary_df.to_string(index=False))

    print("\n================ GAP ANALYSIS ================")
    missed_by_suricata = results[(results["true_binary"] == 1) & (results["suricata_flag"] == 0)]
    missed_by_model = results[(results["true_binary"] == 1) & (results["model_flag"] == 0)]
    print("\nAttack sessions Suricata MISSED (model may or may not have caught):")
    print(missed_by_suricata[["session_id", "scenario", "model_flag"]].to_string(index=False)
          if len(missed_by_suricata) else "  (none)")
    print("\nAttack sessions the MODEL missed (Suricata may or may not have caught):")
    print(missed_by_model[["session_id", "scenario", "suricata_flag"]].to_string(index=False)
          if len(missed_by_model) else "  (none)")

    false_positives = results[(results["true_binary"] == 0) & (results["hybrid_flag"] == 1)]
    print("\nBenign sessions flagged by the HYBRID detector (false positives):")
    print(false_positives[["session_id", "suricata_flag", "model_flag"]].to_string(index=False)
          if len(false_positives) else "  (none)")

    results.to_csv("day5_evaluation_results.csv", index=False)
    summary_df.to_csv("day5_evaluation_summary.csv", index=False)
    print("\nSaved day5_evaluation_results.csv and day5_evaluation_summary.csv")

if __name__ == "__main__":
    main()
