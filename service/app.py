import os
import secrets
from fastapi import Depends, Header
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import pandas as pd
import numpy as np
import joblib
import json

app = FastAPI(title="Governed AI-Assisted SOC - Detection Scoring API")

API_KEY = os.environ.get("SOC_API_KEY")
if not API_KEY:
    raise RuntimeError("SOC_API_KEY is not set")

def require_api_key(x_api_key: str = Header(default="")):
    if not secrets.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

MODEL_PATH = "model_rf.joblib"
META_PATH = "model_meta.json"
VICTIM_IP_DEFAULT = "172.30.0.10"

ALERT_THRESHOLD = float(os.environ.get("ALERT_THRESHOLD", "0.7"))

_model = None
_meta = None

def _load():
    global _model, _meta
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    if _meta is None:
        with open(META_PATH) as f:
            _meta = json.load(f)
    return _model, _meta

class ScoreRequest(BaseModel):
    session_id: str
    victim_ip: str = VICTIM_IP_DEFAULT
    events: List[dict]

class ScoreResponse(BaseModel):
    session_id: str
    label: str
    score: float
    class_probabilities: dict
    n_events_scored: int
    alert: bool
    threshold: float

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

def build_feature_vector(events, victim_ip, feature_cols):
    if not events:
        raise ValueError("events list is empty - cannot score a session with no data")

    g = pd.DataFrame(events)
    if "_time" not in g.columns:
        raise ValueError("each event needs a _time field")
    g["_time"] = pd.to_datetime(g["_time"], utc=True, errors="coerce")
    g = g.sort_values("_time")

    if "ftp.completion_code{}" in g.columns:
        g["_ftp_reply_first_digit"] = parse_ftp_reply_codes(g["ftp.completion_code{}"])
    else:
        g["_ftp_reply_first_digit"] = np.nan

    def victim_port(row):
        if row.get("dest_ip") == victim_ip:
            return row.get("dest_port")
        if row.get("src_ip") == victim_ip:
            return row.get("src_port")
        return np.nan

    g["_victim_port"] = g.apply(victim_port, axis=1)

    n_events = len(g)
    duration = (g["_time"].max() - g["_time"].min()).total_seconds()
    duration = max(duration, 0.001)

    diffs = g["_time"].diff().dt.total_seconds().dropna()
    mean_iat = diffs.mean() if len(diffs) else 0.0
    std_iat = diffs.std() if len(diffs) > 1 else 0.0

    n_unique_victim_ports = g["_victim_port"].nunique(dropna=True)
    n_flow_events = (g.get("event_type") == "flow").sum() if "event_type" in g.columns else 0

    bytes_toserver = pd.to_numeric(g.get("flow.bytes_toserver", pd.Series(dtype=float)), errors="coerce").sum()
    bytes_toclient = pd.to_numeric(g.get("flow.bytes_toclient", pd.Series(dtype=float)), errors="coerce").sum()
    pkts_toserver = pd.to_numeric(g.get("flow.pkts_toserver", pd.Series(dtype=float)), errors="coerce").sum()
    pkts_toclient = pd.to_numeric(g.get("flow.pkts_toclient", pd.Series(dtype=float)), errors="coerce").sum()

    tcp_syn = pd.to_numeric(g.get("tcp.syn", pd.Series(dtype=float)), errors="coerce").sum()
    tcp_rst = pd.to_numeric(g.get("tcp.rst", pd.Series(dtype=float)), errors="coerce").sum()
    tcp_fin = pd.to_numeric(g.get("tcp.fin", pd.Series(dtype=float)), errors="coerce").sum()
    tcp_ack = pd.to_numeric(g.get("tcp.ack", pd.Series(dtype=float)), errors="coerce").sum()

    n_ftp = (g.get("event_type") == "ftp").sum() if "event_type" in g.columns else 0
    n_http = (g.get("event_type") == "http").sum() if "event_type" in g.columns else 0
    n_ssh = (g.get("event_type") == "ssh").sum() if "event_type" in g.columns else 0

    ftp_fail = (g["_ftp_reply_first_digit"] >= 4).sum()
    ftp_total_replies = g["_ftp_reply_first_digit"].notna().sum()
    ftp_fail_rate = ftp_fail / ftp_total_replies if ftp_total_replies else 0.0

    n_http_post = (g.get("http.http_method", pd.Series(dtype=object)) == "POST").sum()

    row = {
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
    }

    return pd.DataFrame([row])[feature_cols]

@app.get("/health", dependencies=[Depends(require_api_key)])
def health():
    try:
        model, meta = _load()
        return {"status": "ok", "classes": meta["classes"], "n_training_sessions": meta["n_training_sessions"]}
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Model not loaded - run train_final_model.py first")

@app.post("/score", response_model=ScoreResponse, dependencies=[Depends(require_api_key)])
def score(req: ScoreRequest):
    model, meta = _load()
    feature_cols = meta["feature_cols"]

    try:
        X = build_feature_vector(req.events, req.victim_ip, feature_cols)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    label = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    class_probs = dict(zip(model.classes_, proba.tolist()))
    top_score = max(proba)
    alert = bool(label != "benign" and float(top_score) >= ALERT_THRESHOLD)

    return ScoreResponse(
        session_id=req.session_id,
        label=label,
        score=round(float(top_score), 4),
        class_probabilities={k: round(v, 4) for k, v in class_probs.items()},
        n_events_scored=len(req.events),        alert=alert,
        threshold=ALERT_THRESHOLD,
    )
