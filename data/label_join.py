import pandas as pd

raw = pd.read_csv("day3_raw_export.csv", low_memory=False)
log = pd.read_csv("collection_log_clean.csv")

raw['_time'] = pd.to_datetime(raw['_time'], utc=True, errors='coerce')
log['start_time'] = pd.to_datetime(log['start_time'], utc=True)
log['end_time'] = pd.to_datetime(log['end_time'], utc=True)

BUFFER_SECONDS = 5
log['window_start'] = log['start_time'] - pd.Timedelta(seconds=BUFFER_SECONDS)
log['window_end'] = log['end_time'] + pd.Timedelta(seconds=BUFFER_SECONDS)

def label_row(ts):
    if pd.isna(ts):
        return pd.Series({'scenario': None, 'session_id': None})
    match = log[(log['window_start'] <= ts) & (ts <= log['window_end'])]
    if len(match) == 0:
        return pd.Series({'scenario': 'unlabeled', 'session_id': None})
    row = match.iloc[0]
    return pd.Series({'scenario': row['scenario'], 'session_id': row['session_id']})

labels = raw['_time'].apply(label_row)
raw = pd.concat([raw, labels], axis=1)

print("Label distribution:")
print(raw['scenario'].value_counts(dropna=False))
print("\nRows per scenario per event_type:")
print(raw.groupby(['scenario', 'event_type']).size())

raw.to_csv("day3_labeled.csv", index=False)
print("\nSaved day3_labeled.csv —", len(raw), "rows,", len(raw.columns), "columns")

useful_cols = [c for c in [
    'scenario','session_id','_time','event_type','src_ip','src_port',
    'dest_ip','dest_port','proto','app_proto',
    'alert.signature','alert.signature_id','alert.category','flow_id'
] if c in raw.columns]
trimmed = raw[useful_cols]
trimmed.to_csv("day3_labeled_trimmed.csv", index=False)
print("Saved day3_labeled_trimmed.csv —", len(trimmed), "rows,", len(trimmed.columns), "columns")
