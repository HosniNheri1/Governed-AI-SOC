import pandas as pd

RAW_PATH = "day4_raw_export.csv"
LOG_PATH = "collection_log_clean.csv"
OUT_LABELED = "day4_labeled_fixed.csv"
OUT_TRIMMED = "day4_labeled_trimmed_fixed.csv"
OUT_FINAL = "day4_dataset_final_fixed.csv"

BUFFER_SECONDS = 5

def main():
    raw = pd.read_csv(RAW_PATH, low_memory=False)
    log = pd.read_csv(LOG_PATH)

    raw["_time"] = pd.to_datetime(raw["_time"], utc=True, errors="coerce")
    if "flow.start" in raw.columns:
        raw["flow.start"] = pd.to_datetime(raw["flow.start"], utc=True, errors="coerce")

    raw["_effective_time"] = raw["_time"]
    if "flow.start" in raw.columns:
        has_flow_start = raw["flow.start"].notna()
        raw.loc[has_flow_start, "_effective_time"] = raw.loc[has_flow_start, "flow.start"]

    log["start_time"] = pd.to_datetime(log["start_time"], utc=True)
    log["end_time"] = pd.to_datetime(log["end_time"], utc=True)
    log["window_start"] = log["start_time"] - pd.Timedelta(seconds=BUFFER_SECONDS)
    log["window_end"] = log["end_time"] + pd.Timedelta(seconds=BUFFER_SECONDS)

    def label_row(ts):
        if pd.isna(ts):
            return pd.Series({"scenario": None, "session_id": None})
        match = log[(log["window_start"] <= ts) & (ts <= log["window_end"])]
        if len(match) == 0:
            return pd.Series({"scenario": "unlabeled", "session_id": None})
        row = match.iloc[0]
        return pd.Series({"scenario": row["scenario"], "session_id": row["session_id"]})

    labels = raw["_effective_time"].apply(label_row)
    raw = pd.concat([raw, labels], axis=1)

    print("Label distribution (corrected timing):")
    print(raw["scenario"].value_counts(dropna=False))
    print("\nRows per scenario per event_type:")
    print(raw.groupby(["scenario", "event_type"]).size())

    raw.to_csv(OUT_LABELED, index=False)
    print(f"\nSaved {OUT_LABELED} - {len(raw)} rows")

    useful_cols = [c for c in [
        "scenario", "session_id", "_time", "_effective_time", "event_type",
        "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto",
        "alert.signature", "alert.signature_id", "alert.category", "flow_id",
        "flow.start", "flow.end",
    ] if c in raw.columns]
    trimmed = raw[useful_cols]
    trimmed.to_csv(OUT_TRIMMED, index=False)

    clean = trimmed[trimmed["scenario"] != "unlabeled"].copy()
    clean.to_csv(OUT_FINAL, index=False)
    print(f"\nDataset final (corrige): {len(clean)} lignes")
    print(clean["scenario"].value_counts())
    print("\nSessions distinctes par scenario:")
    print(clean.groupby("scenario")["session_id"].nunique())

if __name__ == "__main__":
    main()
