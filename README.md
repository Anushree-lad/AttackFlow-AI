# AttackFlow AI — Prototype v0.1

A working end-to-end prototype of the pipeline: raw events → preprocessing →
unsupervised anomaly detection → event correlation → attack sequence
reconstruction → risk scoring → analyst dashboard.

## Why synthetic data

Public IDS datasets (CICIDS2017, UNSW-NB15, NSL-KDD) label individual flows,
not multi-step attack *campaigns* — which is exactly what this project needs
to reconstruct. So `generate_data.py` simulates realistic background traffic
plus a handful of injected multi-stage campaigns (recon → brute-force access
→ lateral movement → exfiltration) with known ground truth. This lets you
validate the correlation and reconstruction logic against a known answer
*before* pointing it at real traffic, where you won't have ground truth to
check against.

**Swap `data/events.csv` for a real dataset or live log export whenever
you're ready** — every downstream stage only expects a CSV with the same
columns (see the header of `generate_data.py`).

## Run it

```bash
pip install -r requirements.txt
python3 generate_data.py      # creates data/events.csv
python3 pipeline.py           # runs the 6-stage pipeline, writes output/sequences.json
python3 build_dashboard.py    # builds output/dashboard.html
```

Then open `output/dashboard.html` in any browser. No server needed.

## Project structure

```
attackflow_ai/
├── generate_data.py     # Stage 1 stand-in: synthetic event generator
├── pipeline.py           # Stages 2–6: the actual system
├── build_dashboard.py    # Renders output/sequences.json as an HTML console
├── data/events.csv       # Generated input data
├── output/
│   ├── sequences.json    # Machine-readable reconstructed sequences
│   └── dashboard.html    # Human-readable console
└── requirements.txt
```

## How each stage works right now (and what to improve first)

| Stage | Current approach | Weakest point — improve here first |
|---|---|---|
| **Preprocessing** | Rolling per-source-IP behavioral features (port diversity, event frequency), computed causally (no lookahead) | Add per-user/identity features once you have auth logs, not just network flow |
| **Anomaly detection** | `IsolationForest` on 8 features, unsupervised | Contamination rate (6%) is a guess — tune against a labeled validation set |
| **Correlation** | Union-find over shared IP + time window (20 min) | Purely IP/time based — add identity and ATT&CK technique similarity as extra correlation signals |
| **Sequence reconstruction** | Hand-written rules mapping features → kill-chain stage (recon / access / lateral movement / exfiltration) | This is the biggest shortcut in the prototype — real deployments need either labeled training data for a stage classifier or a much richer rule set |
| **Risk scoring** | Weighted formula: max kill-chain severity + host breadth + anomaly confidence | Not calibrated against real incident outcomes — validate against historical incidents before trusting the numbers |

**The honest caveat, carried over from the strategy conversation:** the
correlation → reconstruction → risk-scoring chain is the hard, unproven part
of this whole idea. This prototype makes it work on synthetic data with
known ground truth. Getting it to work on real, messy traffic — without
drowning analysts in false positives — is the actual R&D problem, not a
solved detail.

## Next steps, roughly in order

1. **Validate against a labeled dataset.** Swap in a real dataset with at
   least session/campaign-level labels if you can find or construct one,
   and measure precision/recall on sequence reconstruction — not just
   per-event anomaly detection.
2. **Replace the rule-based stage classifier (Stage 5)** with a trained
   model once you have (or manually label) enough multi-stage examples.
3. **Tune the anomaly contamination rate and correlation window** against
   real false-positive/false-negative rates instead of the current guesses.
4. **Add a feedback loop** — let an analyst mark a sequence "confirmed
   attack" or "false positive" in the dashboard, and feed that back into
   the models.
