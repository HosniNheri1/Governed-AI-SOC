import math
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix

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

def wilson_ci(successes, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) / n) + (z**2 / (4 * n**2)))) / denom
    return (max(0.0, center - half), min(1.0, center + half))

def suricata_flags_per_session(labeled_path):
    df = pd.read_csv(labeled_path, low_memory=False)
    df = df[df["scenario"] != "unlabeled"]
    sid_col = "alert.signature_id"
    if sid_col not in df.columns:
        raise RuntimeError(f"Column {sid_col} not found")
    df["_local_alert"] = df[sid_col].isin(LOCAL_SIDS)
    return df.groupby("session_id")["_local_alert"].any()

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

def held_out_split_eval(features_path, n_test_per_class=1):
    df = pd.read_csv(features_path).fillna(0)

    test_idx = []
    for scenario, group in df.groupby("scenario"):
        sorted_group = group.sort_values("session_id")
        test_idx.extend(sorted_group.index[:n_test_per_class].tolist())

    test_mask = df.index.isin(test_idx)
    train_df, test_df = df[~test_mask], df[test_mask]

    X_train = train_df[FEATURE_COLS].values
    y_train = train_df["scenario"].values
    X_test = test_df[FEATURE_COLS].values
    y_test = test_df["scenario"].values
    test_sessions = test_df["session_id"].values

    clf = RandomForestClassifier(
        n_estimators=200, random_state=RANDOM_SEED, class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print(f"\nHeld-out test set: {len(test_df)} sessions "
          f"({n_test_per_class} per class), trained on remaining {len(train_df)}")
    print("Test sessions:", list(test_sessions))
    print(classification_report(y_test, y_pred, zero_division=0))
    return clf

def per_class_report_with_ci(y_true, y_pred, labels):
    print("\n{:<18s} {:>10s} {:>10s} {:>10s} {:>22s} {:>22s}".format(
        "class", "precision", "recall", "f1", "recall 95% CI", "FPR 95% CI"))
    for lab in labels:
        tp = sum((t == lab and p == lab) for t, p in zip(y_true, y_pred))
        fn = sum((t == lab and p != lab) for t, p in zip(y_true, y_pred))
        fp = sum((t != lab and p == lab) for t, p in zip(y_true, y_pred))
        tn = sum((t != lab and p != lab) for t, p in zip(y_true, y_pred))

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0

        recall_ci = wilson_ci(tp, tp + fn)
        fpr_ci = wilson_ci(fp, fp + tn)

        print("{:<18s} {:>10.3f} {:>10.3f} {:>10.3f} {:>22s} {:>22s}".format(
            lab, precision, recall, f1,
            f"[{recall_ci[0]:.3f}, {recall_ci[1]:.3f}]",
            f"[{fpr_ci[0]:.3f}, {fpr_ci[1]:.3f}]"
        ))

def binary_metrics_with_ci(y_true, y_pred, name):
    tp = sum((t == 1 and p == 1) for t, p in zip(y_true, y_pred))
    fp = sum((t == 0 and p == 1) for t, p in zip(y_true, y_pred))
    fn = sum((t == 1 and p == 0) for t, p in zip(y_true, y_pred))
    tn = sum((t == 0 and p == 0) for t, p in zip(y_true, y_pred))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    recall_ci = wilson_ci(tp, tp + fn)
    fpr_ci = wilson_ci(fp, fp + tn)

    print(f"\n--- {name} ---")
    print(f"Precision: {precision:.3f}  Recall: {recall:.3f} (95% CI {recall_ci[0]:.3f}-{recall_ci[1]:.3f})  "
          f"F1: {f1:.3f}  FPR: {fpr:.3f} (95% CI {fpr_ci[0]:.3f}-{fpr_ci[1]:.3f})")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    return {
        "name": name, "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "recall_ci_low": recall_ci[0], "recall_ci_high": recall_ci[1],
        "fpr_ci_low": fpr_ci[0], "fpr_ci_high": fpr_ci[1],
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }

def main():
    suricata_flags = suricata_flags_per_session(LABELED_PATH)
    oof_pred, true_scenario = model_oof_predictions(FEATURES_PATH)

    rows = []
    for session_id, scenario in true_scenario.items():
        true_binary = 0 if scenario == "benign" else 1
        suricata_flag = int(suricata_flags.get(session_id, False))
        model_label = oof_pred.get(session_id)
        model_flag = 0 if model_label == "benign" else 1
        hybrid_or = int(suricata_flag or model_flag)
        hybrid_and = int(suricata_flag and model_flag)

        rows.append({
            "session_id": session_id, "scenario": scenario, "true_binary": true_binary,
            "suricata_flag": suricata_flag, "model_flag": model_flag,
            "model_label": model_label,
            "hybrid_or_flag": hybrid_or, "hybrid_and_flag": hybrid_and,
        })

    results = pd.DataFrame(rows)
    print("=" * 70)
    print("PER-SESSION DETECTION TABLE")
    print("=" * 70)
    print(results.to_string(index=False))

    y_true = results["true_binary"].tolist()

    print("\n" + "=" * 70)
    print("BINARY METRICS (attack vs benign) WITH 95% CONFIDENCE INTERVALS")
    print("=" * 70)
    summary = []
    summary.append(binary_metrics_with_ci(y_true, results["suricata_flag"].tolist(), "Suricata alone"))
    summary.append(binary_metrics_with_ci(y_true, results["model_flag"].tolist(), "Model alone (RF, out-of-fold)"))
    summary.append(binary_metrics_with_ci(y_true, results["hybrid_or_flag"].tolist(), "Hybrid OR (either detector flags)"))
    summary.append(binary_metrics_with_ci(y_true, results["hybrid_and_flag"].tolist(), "Hybrid AND (both must agree)"))

    summary_df = pd.DataFrame(summary)
    print("\n--- Summary table ---")
    print(summary_df[["name", "precision", "recall", "fpr", "tp", "fp", "fn", "tn"]].to_string(index=False))

    print("\n" + "=" * 70)
    print("PER-CLASS MULTICLASS REPORT (out-of-fold predictions, one-vs-rest)")
    print("=" * 70)
    all_true_labels = [true_scenario[sid] for sid in results["session_id"]]
    all_pred_labels = [oof_pred[sid] for sid in results["session_id"]]
    labels = sorted(set(all_true_labels))
    per_class_report_with_ci(all_true_labels, all_pred_labels, labels)

    cm = confusion_matrix(all_true_labels, all_pred_labels, labels=labels)
    print("\nConfusion matrix (rows=true, cols=pred):")
    print("Labels:", labels)
    print(cm)

    print("\n" + "=" * 70)
    print("HELD-OUT TEST SET (single deterministic split, not cross-validation)")
    print("=" * 70)
    print("NOTE: with only 5-8 sessions/class, holding out 1/class leaves very")
    print("few training examples - this split is reported for protocol")
    print("transparency (R-08), not as a replacement for the CV numbers above.")
    held_out_split_eval(FEATURES_PATH, n_test_per_class=1)

    print("\n" + "=" * 70)
    print("GAP ANALYSIS")
    print("=" * 70)
    missed_by_suricata = results[(results["true_binary"] == 1) & (results["suricata_flag"] == 0)]
    missed_by_model = results[(results["true_binary"] == 1) & (results["model_flag"] == 0)]
    print("\nAttack sessions Suricata MISSED:")
    print(missed_by_suricata[["session_id", "scenario", "model_flag"]].to_string(index=False)
          if len(missed_by_suricata) else "  (none)")
    print("\nAttack sessions the MODEL missed:")
    print(missed_by_model[["session_id", "scenario", "suricata_flag"]].to_string(index=False)
          if len(missed_by_model) else "  (none)")

    fp_or = results[(results["true_binary"] == 0) & (results["hybrid_or_flag"] == 1)]
    fp_and = results[(results["true_binary"] == 0) & (results["hybrid_and_flag"] == 1)]
    print("\nBenign sessions flagged by Hybrid OR (false positives):")
    print(fp_or[["session_id", "suricata_flag", "model_flag"]].to_string(index=False) if len(fp_or) else "  (none)")
    print("\nBenign sessions flagged by Hybrid AND (false positives):")
    print(fp_and[["session_id", "suricata_flag", "model_flag"]].to_string(index=False) if len(fp_and) else "  (none)")

    results.to_csv("day5_evaluation_results_v2.csv", index=False)
    summary_df.to_csv("day5_evaluation_summary_v2.csv", index=False)
    print("\nSaved day5_evaluation_results_v2.csv and day5_evaluation_summary_v2.csv")

if __name__ == "__main__":
    main()
