# AI Policy and Roles

Document: grc/42001/01-ai-policy-and-roles.md | Version 0.1 | 2026-11-11 | Status: Draft
Related ISO/IEC 42001 topics: AI policy (clause 5.2), roles and responsibilities (5.3), AI objectives (6.2); Annex A themes on policies, internal organization, use of AI systems.
Wording rule: this is an implementation on a defined lab scope. It is not a certification claim.

## 1. Purpose and scope

This policy governs one AI system: the **session scorer**, a Random Forest classifier served by a FastAPI endpoint (`service/`) and called by the Shuffle workflow `governed-soc-alert-triage`. It scores a source-IP session built from Suricata events and returns a label and a score.

In scope: the model, its training data, the evaluation protocol, the serving endpoint, the Shuffle workflow, the human approval step, and the monitoring plan.
Out of scope: production data, real blocking of traffic, certification, adversarial-ML experiments beyond a documented risk entry.
Environment: isolated lab only (victim and attacker hosts on 172.30.0.0/24). All attacks run only inside this lab.

## 2. Policy statements

| ID | Statement | Where it is exercised (evidence) |
|---|---|---|
| P1 | The model is advisory. It never blocks traffic on its own. The only response action is a simulated block, taken after an analyst decision. | Shuffle export: trigger `Analyst-approval` sits between `ml-score-session` and `simulated-block` |
| P2 | Every block action requires a recorded human decision: approve or reject, timestamp, analyst, session and score. | Shuffle logs; see gap G-1 in the risk assessment (the decision field is currently static) |
| P3 | Suricata stays the primary detection control. The hybrid is defined as Suricata OR model, so the model can only add detections, never remove a Suricata alert. | `evaluate_day5.py` (`hybrid_flag = suricata_flag OR model_flag`) |
| P4 | Performance claims cite a metrics table from `evaluation/` and state that data is small, synthetic and single-lab. | `day5_evaluation_summary.csv`, model card section 5 |
| P5 | Only lab-generated data is used. Each run has a `session_id` and an entry in the collection log. | `data/collection_log.csv`, `day4_labeled_fixed.csv` |
| P6 | A model change (retraining, new features, new threshold) requires a repeat of the session-based evaluation, a new model card version, and approval by the retraining approver. | Monitoring plan section 5 |
| P7 | Secrets (API keys, passwords) are never committed. Workflow exports are masked before they enter the repository. | Risk R-09; evidence/README.md |
| P8 | Known failure modes are written in the model card and updated after every incident. | Model card section 7 |

## 3. Roles

| Role | Responsibility | Current holder |
|---|---|---|
| AI system owner | Accountable for the system, this policy, and risk acceptance | Hosni Nheri |
| Model validator | Runs and signs off the evaluation; checks leakage and protocol compliance | Hosni Nheri (see limitation) |
| Retraining approver | Approves any model change after reading the new evaluation | Hosni Nheri (see limitation) |
| SOC analyst (human oversight) | Reviews each scored alert and approves or rejects the simulated block | Hosni Nheri |
| Data steward | Maintains collection log, labels, data dictionary, provenance | Hosni Nheri |

**Limitation.** One person holds all roles, so there is no segregation of duties between building, validating and approving. Compensating measures: the evaluation protocol was fixed before results (`01-research-design.md`), the metrics are reproducible from the committed scripts, and a second reviewer is still an open decision in the roadmap (section 10). If a second person joins, they take the model validator role first.

## 4. AI objectives (measurable)

| Objective | Measure | Day 5 baseline |
|---|---|---|
| O1 Detect more attack sessions than Suricata alone | Recall on attack sessions | Suricata 14/24 = 0.583; model 24/24 = 1.000; hybrid 24/24 = 1.000 |
| O2 Keep false alarms at or below Suricata alone | FPR on benign sessions | 0/8 for all three systems |
| O3 Keep a human in the loop for every response | Share of block actions with a complete decision record | Target 100%; current evidence incomplete (gap G-1) |
| O4 Keep the pipeline observable | Ingestion lag in Splunk | Observed failure on 2026-11-11: latest event 2026-11-08 16:49:16, about 3 days stale |

The research-design decision rule (recall improves on at least one class, FPR within 1 point of Suricata) is met on the Day 5 data. Because the sample is small, this is a lab result, not evidence of production performance.

## 5. Annex A theme coverage (scoped to the lab)

Control numbers should be checked against the purchased standard text before publication.

| Annex A theme | How the lab exercises it | Status |
|---|---|---|
| Policies related to AI | This document | Draft |
| Internal organization, roles | Section 3 | Partial (single person) |
| Impact assessment | `02-ai-risk-and-impact-assessment.md` | Draft |
| AI system life cycle | Model card, evaluation protocol, monitoring plan | Partial (no model version or hash recorded yet) |
| Data for AI systems | Collection log, labels, provenance in model card section 3 | Partial |
| Information for interested parties | Model card | Draft |
| Use of AI systems, human oversight | Shuffle approval step and decision log | Partial (gap G-1) |
| Third-party and supplier relationships | Component list in risk AI-05 | Partial |

## 6. Review

The owner reviews this policy at every model change and at least monthly while the lab is active. Each review adds a dated line to the change log below.

| Date | Change |
|---|---|
| 2026-11-11 | Version 0.1, first draft |
