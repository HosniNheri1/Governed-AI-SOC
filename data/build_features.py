import pandas as pd
import numpy as np

RAW_PATH = "day4_labeled_fixed.csv"
OUT_PATH = "day4_features_fixed.csv"
VICTIM_IP = "172.30.0.10"

def parse_ftp_reply_codes(series):
    def first_digit(val):
        if pd.isna(val):
            return np.nan
        try:
            code = int(float(val))
            return int(str(code)[0])
        except (ValueError, TypeError):
            return np.nan
    return series.apply(first_digit)

def build_features(df):
    df = df.copy()
    df["_time"] = pd.to_datetime(df["_time"], utc=True, errors="coerce")

    if "ftp.completion_code{}" in df.columns:
        df["_ftp_reply_first_digit"] = parse_ftp_reply_codes(df["ftp.completion_code{}"])
    else:
        df["_ftp_reply_first_digit"] = np.nan

    def victim_port(row):
        if row.get("dest_ip") == VICTIM_IP:
            return row.get("dest_port")
        if row.get("src_ip") == VICTIM_IP:
            return row.get("src_port")
        return np.nan

    df["_victim_port"] = df.apply(victim_port, axis=1)

    rows = []
    for session_id, g in df.groupby("session_id"):
        g = g.sort_values("_time")
        scenario = g["scenario"].iloc[0]

        n_events = len(g)
        duration = (g["_time"].max() - g["_time"].min()).total_seconds()
        duration = max(duration, 0.001)

        diffs = g["_time"].diff().dt.total_seconds().dropna()
        mean_iat = diffs.mean() if len(diffs) else 0.0
        std_iat = diffs.std() if len(diffs) > 1 else 0.0

        n_unique_victim_ports = g["_victim_port"].nunique(dropna=True)
        n_flow_events = (g["event_type"] == "flow").sum()

        bytes_toserver = g.get("flow.bytes_toserver", pd.Series(dtype=float)).sum()
        bytes_toclient = g.get("flow.bytes_toclient", pd.Series(dtype=float)).sum()
        pkts_toserver = g.get("flow.pkts_toserver", pd.Series(dtype=float)).sum()
        pkts_toclient = g.get("flow.pkts_toclient", pd.Series(dtype=float)).sum()

        tcp_syn = pd.to_numeric(g.get("tcp.syn", pd.Series(dtype=float)), errors="coerce").sum()
        tcp_rst = pd.to_numeric(g.get("tcp.rst", pd.Series(dtype=float)), errors="coerce").sum()
        tcp_fin = pd.to_numeric(g.get("tcp.fin", pd.Series(dtype=float)), errors="coerce").sum()
        tcp_ack = pd.to_numeric(g.get("tcp.ack", pd.Series(dtype=float)), errors="coerce").sum()

        n_ftp = (g["event_type"] == "ftp").sum()
        n_http = (g["event_type"] == "http").sum()
        n_ssh = (g["event_type"] == "ssh").sum()

        ftp_fail = (g["_ftp_reply_first_digit"] >= 4).sum()
        ftp_total_replies = g["_ftp_reply_first_digit"].notna().sum()
        ftp_fail_rate = ftp_fail / ftp_total_replies if ftp_total_replies else 0.0

        n_http_post = (g.get("http.http_method", pd.Series(dtype=object)) == "POST").sum()

        rows.append({
            "session_id": session_id,
            "scenario": scenario,
            "n_events": n_events,
            "duration_sec": duration,
            "events_per_sec": n_events / duration,
            "mean_interarrival_sec": mean_iat,
            "std_interarrival_sec": std_iat,
            "n_unique_victim_ports": n_unique_victim_ports,
            "n_flow_events": n_flow_events,
            "bytes_toserver": bytes_toserver,
            "bytes_toclient": bytes_toclient,
            "pkts_toserver": pkts_toserver,
            "pkts_toclient": pkts_toclient,
            "tcp_syn_count": tcp_syn,
            "tcp_rst_count": tcp_rst,
            "tcp_fin_count": tcp_fin,
            "tcp_ack_count": tcp_ack,
            "n_ftp_events": n_ftp,
            "n_http_events": n_http,
            "n_ssh_events": n_ssh,
            "ftp_fail_rate": ftp_fail_rate,
            "n_http_post": n_http_post,
        })

    return pd.DataFrame(rows)

def main():
    df = pd.read_csv(RAW_PATH, low_memory=False)
    df = df[df["scenario"] != "unlabeled"].copy()

    feats = build_features(df)
    feats.to_csv(OUT_PATH, index=False)

    print(f"Built {len(feats)} session-level feature rows -> {OUT_PATH}")
    print("\nClass distribution (by session, not by row):")
    print(feats["scenario"].value_counts())

if __name__ == "__main__":
    main()
