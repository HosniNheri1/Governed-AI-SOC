import pandas as pd

raw = pd.read_csv("day4_labeled.csv", low_memory=False)
clean = raw[raw['scenario'] != 'unlabeled'].copy()

print("=== Colonnes disponibles liées au réseau / timing / taille ===")
candidates = [c for c in raw.columns if any(k in c.lower() for k in
    ['byte', 'pkt', 'port', 'proto', 'flow', 'duration', 'age', 'state',
     'tcp', 'dest', 'src', 'app_proto', 'ftp', 'http', 'ssh', 'direction'])]
for c in sorted(candidates):
    non_null = clean[c].notna().sum()
    print(f"{c:40s} non-null: {non_null:5d} / {len(clean)}")

print("\n=== Exemple de ligne par event_type ===")
for et in clean['event_type'].unique():
    sub = clean[clean['event_type'] == et].iloc[0]
    print(f"\n--- {et} ---")
    for c in ['src_ip','src_port','dest_ip','dest_port','proto','app_proto']:
        if c in sub.index:
            print(f"  {c}: {sub[c]}")
