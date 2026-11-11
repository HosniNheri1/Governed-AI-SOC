"""Day 5 evaluation: Suricata alone vs model alone vs hybrid (OR and AND).

Protocols
  A. Out-of-fold (OOF) 5-fold stratified CV by session  -> same as the first version
  B. Reserved test set: >= 1 session of every class never used for training
  C. Ablation: OOF without protocol-specific counters (leakage check)

Outputs (CSV):
  day5_evaluation_results.csv    per-session table (OOF, adds hybrid_and_flag)
  day5_evaluation_summary.csv    binary metrics, OOF, 4 systems + one-sided 95% bounds
  day5_per_class.csv             per-class precision/recall/F1 of the model (OOF)
  day5_suricata_per_class.csv    Suricata recall per attack class
  day5_holdout_summary.csv       binary metrics on the reserved test set
  day5_ablation_summary.csv      model/hybrid metrics with and without protocol counters
"""
import numpy as np
import pandas as pd
from scipy.stats import beta
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             classification_report, confusion_matrix)

LABELED_PATH = "day4_labeled_fixed.csv"
FEATURES_PATH = "day4_features_fixed.csv"
RANDOM_SEED = 42
N_FOLDS = 5
HOLDOUT_FRACTION = 0.30   # per class, at least 1 session, at least 2 left for training
N_HOLDOUT_REPEATS = 20    # extra random reserved splits, to show how noisy one split is

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
# Counters that can reveal the attacked protocol, hence the label. Dropped in the ablation.
PROTOCOL_COLS = ["n_ftp_events", "n_http_events", "n_ssh_events",
                 "ftp_fail_rate", "n_http_post"]
ABLATED_COLS = [c for c in FEATURE_COLS if c not in PROTOCOL_COLS]


# ---------------------------------------------------------------- helpers
def new_rf():
    return RandomForestClassifier(n_estimators=200, random_state=RANDOM_SEED,
                                  class_weight="balanced")


def recall_lower_bound(k, n, alpha=0.05):
    """One-sided (1-alpha) Clopper-Pearson lower bound for k successes in n."""
    return float(beta.ppf(alpha, k, n - k + 1)) if k > 0 and n > 0 else 0.0


def rate_upper_bound(k, n, alpha=0.05):
    """One-sided (1-alpha) Clopper-Pearson upper bound for k events in n."""
    return float(beta.ppf(1 - alpha, k + 1, n - k)) if n > 0 and k < n else 1.0


def suricata_flags_per_session(labeled_path):
    df = pd.read_csv(labeled_path, low_memory=False)
    df = df[df["scenario"] != "unlabeled"].copy()
    sid_col = "alert.signature_id"
    if sid_col not in df.columns:
        raise RuntimeError(f"Column {sid_col} not found - check labeled CSV columns")
    df["_local_alert"] = df[sid_col].isin(LOCAL_SIDS)
    return df.groupby("session_id")["_local_alert"].any()


def load_features(features_path):
    df = pd.read_csv(features_path).fillna(0)
    return df.reset_index(drop=True)


def oof_predictions(df, cols):
    X = df[cols].values
    y = df["scenario"].values
    sessions = df["session_id"].values
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    pred = {}
    for tr, te in skf.split(X, y):
        clf = new_rf().fit(X[tr], y[tr])
        for sid, p in zip(sessions[te], clf.predict(X[te])):
            pred[sid] = p
    return pred


def reserved_split(df, seed):
    """Test-only sessions: per class, max(1, round(fraction*n)), keeping >= 2 for training."""
    rng = np.random.RandomState(seed)
    test_idx = []
    for _, idx in df.groupby("scenario").indices.items():
        n = len(idx)
        n_test = min(max(1, int(round(HOLDOUT_FRACTION * n))), max(n - 2, 1))
        test_idx.extend(rng.permutation(idx)[:n_test])
    test_idx = np.array(sorted(test_idx))
    train_idx = np.setdiff1d(np.arange(len(df)), test_idx)
    return train_idx, test_idx


def metrics(y_true, y_pred, name):
    y_true, y_pred = list(y_true), list(y_pred)
    tp = sum(t == 1 and p == 1 for t, p in zip(y_true, y_pred))
    fp = sum(t == 0 and p == 1 for t, p in zip(y_true, y_pred))
    fn = sum(t == 1 and p == 0 for t, p in zip(y_true, y_pred))
    tn = sum(t == 0 and p == 0 for t, p in zip(y_true, y_pred))
    return {
        "name": name,
        "precision": precision_score(y_true, y_pred, pos_label=1, zero_division=0),
        "recall": recall_score(y_true, y_pred, pos_label=1, zero_division=0),
        "f1": f1_score(y_true, y_pred, pos_label=1, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall_lower95": recall_lower_bound(tp, tp + fn),
        "fpr_upper95": rate_upper_bound(fp, fp + tn),
    }


def systems_table(results, label):
    y = results["true_binary"].tolist()
    rows = [
        metrics(y, results["suricata_flag"], "Suricata alone"),
        metrics(y, results["model_flag"], "Model alone (RF)"),
        metrics(y, results["hybrid_flag"], "Hybrid OR (Suricata or model)"),
        metrics(y, results["hybrid_and_flag"], "Hybrid AND (Suricata and model)"),
    ]
    df = pd.DataFrame(rows)
    print(f"\n================ {label} ================")
    print(df.round(3).to_string(index=False))
    return df


def build_results(df, flags, pred):
    rows = []
    for sid, scenario in zip(df["session_id"], df["scenario"]):
        sflag = int(flags.get(sid, False))
        mlabel = pred.get(sid)
        mflag = 0 if mlabel == "benign" else 1
        rows.append({
            "session_id": sid, "scenario": scenario,
            "true_binary": 0 if scenario == "benign" else 1,
            "suricata_flag": sflag, "model_flag": mflag, "model_label": mlabel,
            "hybrid_flag": int(sflag or mflag),
            "hybrid_and_flag": int(sflag and mflag),
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- main
def main():
    flags = suricata_flags_per_session(LABELED_PATH)
    df = load_features(FEATURES_PATH)
    print(f"{len(df)} sessions; class counts:\n{df['scenario'].value_counts().to_string()}")
    print("Baseline definition: Suricata alone = alerts from local SIDs", sorted(LOCAL_SIDS))

    # ---- Protocol A: OOF
    pred = oof_predictions(df, FEATURE_COLS)
    results = build_results(df, flags, pred)
    print("\nPer-session detection table (OOF):")
    print(results.to_string(index=False))
    summary = systems_table(results, "A. OOF SUMMARY (5-fold stratified, by session)")

    # ---- Per-class model report (multiclass) and Suricata recall per class
    labels = sorted(results["scenario"].unique())
    rep = classification_report(results["scenario"], results["model_label"],
                                labels=labels, output_dict=True, zero_division=0)
    per_class = pd.DataFrame(rep).T.loc[labels + ["accuracy", "macro avg", "weighted avg"]]
    print("\n================ PER-CLASS (model, OOF) ================")
    print(per_class.round(3).to_string())
    cm = pd.DataFrame(confusion_matrix(results["scenario"], results["model_label"], labels=labels),
                      index=[f"true_{l}" for l in labels], columns=[f"pred_{l}" for l in labels])
    print("\nConfusion matrix (rows = true, columns = predicted):")
    print(cm.to_string())

    att = results[results["true_binary"] == 1]
    sur_pc = att.groupby("scenario").agg(sessions=("suricata_flag", "size"),
                                         suricata_detected=("suricata_flag", "sum"),
                                         model_detected=("model_flag", "sum"),
                                         hybrid_or_detected=("hybrid_flag", "sum"))
    sur_pc["suricata_recall"] = sur_pc["suricata_detected"] / sur_pc["sessions"]
    sur_pc["model_recall"] = sur_pc["model_detected"] / sur_pc["sessions"]
    print("\n================ PER-CLASS DETECTION (attack classes) ================")
    print(sur_pc.round(3).to_string())

    # ---- Gap analysis
    print("\n================ GAP ANALYSIS ================")
    for title, mask, cols in [
        ("Attack sessions Suricata MISSED", (results.true_binary == 1) & (results.suricata_flag == 0),
         ["session_id", "scenario", "model_flag"]),
        ("Attack sessions the MODEL missed", (results.true_binary == 1) & (results.model_flag == 0),
         ["session_id", "scenario", "suricata_flag"]),
        ("Benign sessions flagged by the HYBRID OR (false positives)",
         (results.true_binary == 0) & (results.hybrid_flag == 1),
         ["session_id", "suricata_flag", "model_flag"]),
    ]:
        sub = results[mask]
        print(f"\n{title}:")
        print(sub[cols].to_string(index=False) if len(sub) else "  (none)")

    # ---- Protocol B: reserved test set
    train_idx, test_idx = reserved_split(df, RANDOM_SEED)
    clf = new_rf().fit(df.loc[train_idx, FEATURE_COLS].values, df.loc[train_idx, "scenario"].values)
    test_df = df.loc[test_idx]
    test_pred = dict(zip(test_df["session_id"], clf.predict(test_df[FEATURE_COLS].values)))
    hold = build_results(test_df, flags, test_pred)
    print("\nReserved test sessions per class:")
    print(hold["scenario"].value_counts().to_string())
    hold_summary = systems_table(hold, f"B. RESERVED TEST SET ({len(hold)} sessions, never used for training)")

    # repeated random reserved splits, to show variance of a single small split
    rep_rows = []
    for k in range(N_HOLDOUT_REPEATS):
        tr, te = reserved_split(df, RANDOM_SEED + 1 + k)
        c = new_rf().fit(df.loc[tr, FEATURE_COLS].values, df.loc[tr, "scenario"].values)
        t = df.loc[te]
        h = build_results(t, flags, dict(zip(t["session_id"], c.predict(t[FEATURE_COLS].values))))
        y = h["true_binary"].tolist()
        m, s, o = (metrics(y, h["model_flag"], "m"), metrics(y, h["suricata_flag"], "s"),
                   metrics(y, h["hybrid_flag"], "o"))
        rep_rows.append({"model_recall": m["recall"], "model_fpr": m["fpr"],
                         "suricata_recall": s["recall"], "hybrid_recall": o["recall"]})
    rep_df = pd.DataFrame(rep_rows)
    print(f"\nB'. {N_HOLDOUT_REPEATS} repeated reserved splits (different seeds): mean / min / max")
    print(pd.DataFrame({"mean": rep_df.mean(), "min": rep_df.min(), "max": rep_df.max()}).round(3).to_string())

    # ---- Protocol C: ablation of protocol counters
    pred_abl = oof_predictions(df, ABLATED_COLS)
    abl = build_results(df, flags, pred_abl)
    y = abl["true_binary"].tolist()
    abl_rows = []
    for tag, r in [("with protocol counters", results), ("without protocol counters", abl)]:
        for name, col in [("Model alone", "model_flag"), ("Hybrid OR", "hybrid_flag")]:
            m = metrics(y, r[col], name)
            m["name"] = f"{name} - {tag}"
            m["multiclass_accuracy"] = float((r["scenario"] == r["model_label"]).mean())
            abl_rows.append(m)
    abl_summary = pd.DataFrame(abl_rows)
    print("\n================ C. ABLATION (leakage check) ================")
    print(f"Dropped: {PROTOCOL_COLS}")
    print(abl_summary.round(3).to_string(index=False))
    print("Reading: a large drop without these counters means the score leans on protocol-specific "
          "counts, which can reveal the label directly.")

    # ---- Save
    results.to_csv("day5_evaluation_results.csv", index=False)
    summary.to_csv("day5_evaluation_summary.csv", index=False)
    per_class.to_csv("day5_per_class.csv")
    sur_pc.to_csv("day5_suricata_per_class.csv")
    hold_summary.to_csv("day5_holdout_summary.csv", index=False)
    abl_summary.to_csv("day5_ablation_summary.csv", index=False)
    print("\nSaved: day5_evaluation_results.csv, day5_evaluation_summary.csv, day5_per_class.csv, "
          "day5_suricata_per_class.csv, day5_holdout_summary.csv, day5_ablation_summary.csv")
    print("Limits: small, synthetic, single-lab data; bounds are one-sided 95% Clopper-Pearson.")


if __name__ == "__main__":
    main()
