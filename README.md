# Governed AI-Assisted SOC

ISO/IEC 27001:2022 and ISO/IEC 42001:2023 applied to a Suricata + Splunk + Shuffle lab with an ML detection layer.

> Academic / portfolio project. All attacks run only inside an isolated lab. ISO work is an implementation on a defined scope, not a certification.

## Research question

Does an ML detector add value over Suricata rules alone for detecting scans and brute force in a small network, and how can the detector be governed under ISO 42001 while the SOC operates under ISO 27001?

## Status

| Day | Phase | Status |
|---|---|---|
| 1 | Scope and skeleton | in progress |
| 2 | Repeatable attacks and ingestion | todo |
| 3 | Data collection and labeling | todo |
| 4 | Features and models | todo |
| 5 | Evaluation | todo |
| 6 | Serving and SOAR | todo |
| 7 | ISO 27001 | todo |
| 8 | ISO 42001 | todo |
| 9 | Integration | todo |
| 10 | Publication | todo |

## Repository layout

| Path | Purpose |
|---|---|
| `docs/` | Scope, research design, architecture, decision log |
| `lab/` | Lab configuration and health check |
| `attacks/` | Nmap and Hydra scripts, benign-traffic generator |
| `data/` | Collection log, data dictionary, labeled dataset |
| `notebooks/` | Features, training, evaluation |
| `service/` | FastAPI model service |
| `shuffle/` | Exported SOAR workflow |
| `grc/27001`, `grc/42001` | Management-system documents |
| `grc/integration` | Traceability matrix, gap analysis |
| `evidence/` | Screenshots and logs, named by matrix row |

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Reproducing

Filled in on Day 10.
