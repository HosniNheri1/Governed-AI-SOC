# Decision Log

| ID | Date | Decision | Reason | Alternatives |
|---|---|---|---|---|
| D-01 | Day 1 | Unit of analysis = source IP per 60 s window | Matches how brute force and scans appear in logs | Per-flow features (more data, more leakage risk) |
| D-02 | Day 1 | Split by session_id | Avoid leakage and inflated scores | Random split (rejected) |
| D-03 | Day 1 | Blocking is simulated, human approves | Safety, and serves as ISO 42001 human oversight evidence | Automatic block (rejected) |
