# Day 9 — Integration

**Status:** draft for review.
**Inputs:** `data/day5_evaluation_results_v2.csv`, `data/day5_evaluation_summary_v2.csv`, `grc/27001/risk_register.md`, `grc/27001/soa_partial.md`, `grc/27001/incident_response_procedure.md`, `grc/27001/internal_audit_checklist.md`, `grc/42001/01-04`, `evidence/README.md` and the five masked Day 6 screenshots.
**Wording:** implemented on a defined lab scope, not certified. Results come from small, synthetic, single-lab data.

## 1. Traceability matrix

One row per scenario, per the roadmap's template. Risk IDs are cited from **both** registers where they diverge in number (see Finding F9 below) — the ISO 27001 ID is canonical for the scenario row; the ISO 42001 ID is given in brackets where a distinct AI-specific entry exists for the same concern.

| Scenario | Detection | Risk ID (27001 / 42001) | ISO 27001 control | ISO 42001 element | Evidence |
|---|---|---|---|---|---|
| Nmap SYN scan | Suricata rule 9000001 (recall 5/6), model (recall 5/6 exact-label, 6/6 binary) | R-01 / R-01 | 8.16, 8.20 | Monitoring plan (M6) | `day5_evaluation_results_v2.csv`, per-class table in model card §5.2 |
| Slow scan (`-T2`, 500 ports) | Model only — Suricata's threshold rule (20 SYN/5s) never fires at this rate; model correctly labels the session `nmap_syn_scan` | R-02 / R-02 **(contradiction — see F10)** | 8.16 | AI risk assessment | `day5_evaluation_results_v2.csv` row `sess_20261107_131120_30504`: `suricata_flag=0, model_flag=1, model_label=nmap_syn_scan` |
| SSH brute force | Suricata rules fire only at `-t4`/`-t6` (3/7 ≈ 0.43 recall); model 7/7; automated Splunk→Shuffle workflow with human approval | R-03 / R-03 | 8.5, 8.16, 5.24–5.28 | Human oversight | `R-03_splunk_webhook_log.png`, `R-03_approval_continue.png`, `R-03_decline_aborted.png` (with its stated reservation), `R-03_fastapi_score_masque.png` |
| FTP / HTTP brute force | Suricata rules fire only at high parallelism (ftp 3/6, http 3/5); model 11/11; **no automated response** — `src_ip` is the victim's address on these two rules, so automating a block would target `victim1` | R-04 / R-04 | 8.5, 8.15 | Data quality | `day5_evaluation_results_v2.csv`, `incident_response_procedure.md` §6 (manual path) |
| Benign baseline | No alert expected; 0/8 false positives observed for Suricata, model, and both hybrid combinations | R-05 / R-05 | 8.15 | Model card §5.1 | FPR row, with the one-sided 95% upper bound (31.2%) stated alongside the point estimate |
| Model drift | Not yet measured; no second collection window exists to compare against | R-06 / R-06 | 8.16 | Monitoring plan (M4, M5) | None yet — this is a measurement hole, not a measured low score |
| Adversarial evasion | Documented risk only; not exercised | R-07 / R-07 | 8.29 | AI risk assessment | Risk register entry only |
| Ingestion / telemetry gap | Capture chain (Suricata, `victim1`, login server) stops between sessions with no alert; observed 3-day staleness on 2026-11-11 | R-08 *(27001)* | 8.15 | Monitoring plan (M1), restart checklist | `latest(_time)` search, incident log line in `04-monitoring-plan.md` §6 |
| Tunnel / SaaS exposure | Scoring endpoint reachable through a public tunnel; Shuffle workflow and its stored secrets live outside the lab boundary | R-09 *(27001)* = R-10 *(42001, different number)* | 8.20, 8.5, 5.23 | Third-party management | `scope_context.md` §3.3; masked tunnel/webhook captures |
| Optimistic evaluation protocol | Cross-validation (not a reserved test set); per-session unit (not the 60s window in the original research design); protocol-specific counters may leak the label | *(no 27001 entry)* R-08 *(42001)* | — | AI risk assessment | `evaluate_day5_v2.py` held-out-split section; F5 in the audit checklist |
| Human oversight not fully provable | `simulated-block` historically hard-coded `"decision":"approve"`; a decline ends `ABORTED` with no reason retained | *(no 27001 entry, though R-03's treatment references it)* R-09 *(42001)* | — | Human oversight | `02-ai-risk-and-impact-assessment.md` gap G-1; `R-03_decline_aborted.png` with its reservation |

## 2. Dashboard

No Splunk dashboard has been built yet — this section is the specification to build it from, not a screenshot of a finished panel, since building it requires clicking through the Splunk UI directly on the lab host.

### Panel 1 — Alerts by scenario (last 7 days)
```spl
index=main sourcetype="suricata:eve" event_type=alert
| eval scenario=case(
    'alert.signature_id'==9000001, "nmap_syn_scan",
    'alert.signature_id'==9000002, "ssh_bruteforce",
    'alert.signature_id'==9000003, "ftp_bruteforce",
    'alert.signature_id'==9000004, "http_bruteforce",
    1==1, "other (incl. ET noise)")
| timechart span=1h count by scenario
```
Exclude the `ET INFO Python BaseHTTP ServerBanner` noise (344 of 396 alerts per the Day 6 audit) from any headline count — keep it visible in this panel only to show it is accounted for, not hidden.

### Panel 2 — Model scores (from Shuffle executions, if logged to Splunk)
Currently **not available**: the model's score is only visible inside the Shuffle execution log (`ml-score-session` node), not forwarded to Splunk. Building this panel requires either (a) adding an HTTP Event Collector call from the Shuffle workflow back to Splunk after scoring, or (b) accepting this panel as a gap (see F11 below) until that forwarding exists.

### Panel 3 — Analyst decisions
Same limitation as Panel 2: `simulated-block`'s decision field is currently static (gap G-1 in the 42001 risk assessment), so a dashboard panel built from it today would show "approve" for every run regardless of the real outcome. **Do not build this panel until G-1 is fixed**, or it will misrepresent the human-oversight evidence it is meant to support.

### Panel 4 — Ingestion freshness (buildable now)
```spl
index=main sourcetype="suricata:eve"
| stats latest(_time) as latest
| eval lag_min=round((now()-latest)/60,1)
| eval status=if(lag_min>15, "STALE", "OK")
```
This is the one panel with no upstream dependency — build it first.

## 3. Gap analysis

### 3.1 Findings carried over from the internal audit checklist (not re-derived, just indexed here)
F1 through F8 are already written in `internal_audit_checklist.md` §D and are not repeated in full here. Status as of this integration pass:

| ID | Short description | Status after this session |
|---|---|---|
| F1 | 27001 R-02 contradicted Day 5 | **Resolved** in `risk_register.md` (revised 2026-11-11) |
| F2 | 5.24 marked Implemented before the IR procedure existed | Procedure now exists (`incident_response_procedure.md`), but §7's dry runs are still unfilled — 5.24 should stay **Partial** |
| F3 | 8.16 evidence is SSH-only | Still accurate; `soa_partial.md` already states this correctly as Partial |
| F4 | Clear-text credentials in the playbook | **Not yet confirmed fixed** — needs a grep of the actual repository, not just the documents reviewed here |
| F5 | CV may mix sessions from the same run across train/test | Partially addressed: `evaluate_day5_v2.py` adds a held-out split (1 session/class) and reports both protocols, but does not implement `GroupKFold` by a run identifier as F5 recommended. **Open** |
| F6 | "Avenloft" possible client name reference | Not visible in the documents reviewed in this session — confirm directly in the repo text |
| F7 | Single-person segregation-of-duties gap | Documented consistently across `scope_context.md` §4b, `01-ai-policy-and-roles.md` §3, `incident_response_procedure.md` §2. **Adequately disclosed** |
| F8 | Shuffle cloud / tunnel exposure not in the original scope wording | **Resolved** — `scope_context.md` §4 now carries corrected wording, and R-09 exists in the 27001 register |

### 3.2 New findings from this integration pass

**F9 — Risk ID numbering collision between the two registers. RESOLVED (see commit history).** `grc/27001/risk_register.md` uses R-01 to R-09 for lab-operational risks. `grc/42001/02-ai-risk-and-impact-assessment.md` independently uses R-01 to R-14 for AI-specific risks, and R-08/R-09 in that document do **not** refer to the same risks as R-08/R-09 in the 27001 register (ingestion staleness and tunnel exposure, respectively) — they refer to "optimistic evaluation protocol" and "human oversight not provable." A reader citing "R-09" without saying which register means is citing an ambiguous reference. *Recommendation:* prefix the AI-specific register's IDs distinctly (e.g., `AI-01` to `AI-07` for the ones with no 27001 counterpart) before publication, and keep shared concerns (ingestion, tunnel exposure) under one shared ID cited in both documents rather than re-numbered independently.

**F10 — The ISO 42001 register's R-02 is stale relative to the ISO 27001 register's corrected R-02 and the Day 5 v2 results.** `02-ai-risk-and-impact-assessment.md` still states the slow-scan scenario is "Unmeasured" and rates it Likelihood 3 / Impact 4 / Score 12 on that basis. This was true before the dataset was expanded to 32 sessions (the original 10-session Day 3 pull had no slow scan), but is no longer true: `sess_20261107_131120_30504` is a slow scan (`-T2`, 500 ports, 202s), present in `day4_features_fixed.csv` and correctly labeled by the model in the Day 5 v2 evaluation. This entry needs rewriting to match the already-corrected 27001 R-02 wording, and its score should drop from the AI register's current 12 to reflect a measured (if single-sample) result rather than an unmeasured one — while still flagging the small sample size, consistent with F1's original correction.

**F11 — Day 9 dashboard cannot show model scores or real analyst decisions yet.** Both panels described as roadmap deliverables for Day 9 ("alerts by scenario, model scores, analyst decisions") depend on fixes that are still open: forwarding the Shuffle score back to Splunk (not built), and writing the real `Analyst-approval` outcome into the decision record instead of a static value (gap G-1, already tracked in the 42001 treatment plan). Building those two panels before G-1 is fixed would create a dashboard that visually looks complete while silently misrepresenting the oversight evidence — worse than not having the panel at all. *Recommendation:* ship the dashboard with Panels 1 and 4 only for now, and note Panels 2/3 as "blocked on G-1" directly in the dashboard's own description text, not just in this document.

**F12 — The `incident_response_procedure.md` §7 dry-run table is empty.** Three planned dry runs (SSH approve, SSH decline, slow-scan manual path) have rows reserved but no dates or results filled in, and the document's own text says control 5.24 should stay "Partial" until they are run once end to end. The real `R-03_approval_continue.png` and `R-03_decline_aborted.png` captures functionally satisfy dry runs 1 and 2's evidence requirement (with the F1-equivalent reservation already written for the decline capture), but the table itself was never updated to point to them. *Recommendation:* fill in §7's table now, referencing the existing captures, rather than treating the dry runs as still-outstanding work when most of the evidence already exists.

### 3.3 What is covered, partial, or out of scope (summary, cross-referencing `soa_partial.md`)

- **Covered with evidence:** SSH brute-force detection-through-decision chain (R-03), ingestion to Splunk (8.15), evidence collection and masking (5.28).
- **Partial:** monitoring (8.16, SSH-only automation), network segregation (8.22, sensors in host network mode), secure authentication (8.5, default credentials not yet confirmed removed per F4), cloud service use (5.23, no formal supplier assessment beyond terms of use).
- **Out of scope by choice, not gap:** all Annex A controls not selected in `soa_partial.md`; real blocking; adversarial-ML experimentation beyond R-07's documented entry; segregation of duties (5.3), explicitly accepted as a one-person-lab limitation.
- **Measurement holes (distinct from low scores):** model drift (R-06, no second collection window yet), adversarial evasion (R-07, never tested). Per the roadmap's own risk register, an unmeasured risk is not the same as a low risk, and both registers should keep stating that distinction rather than letting silence read as reassurance.

## 4. Definition of done — Day 9 exit criterion check

Roadmap's stated exit criterion: *"no matrix row is missing evidence or an honest 'not covered' note."*

| Row | Evidence present? |
|---|---|
| Nmap SYN scan | Yes |
| Slow scan | Yes, after F10's correction is applied to the 42001 document |
| SSH brute force | Yes |
| FTP/HTTP brute force | Yes (detection metrics); explicitly "no automated response" for the response half |
| Benign baseline | Yes |
| Model drift | Honest "not covered / unmeasured" note, no evidence to show |
| Adversarial evasion | Honest "not covered / documented only" note, no evidence to show |
| Ingestion gap | Yes |
| Tunnel/SaaS exposure | Yes |

Every row has either evidence or an explicit "not covered" note. The exit criterion is met, conditional on F10's correction being applied before publication (currently the 42001 document's own text contradicts the matrix row above it).
