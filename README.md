# AI-Driven Log Anomaly Detector

A small machine learning pipeline that learns what normal network/security log activity looks like and flags unusual sessions (long durations, huge packet counts, many failed logins). It uses an Isolation Forest from scikit-learn, with a command line interface for training and analysis. It is evaluated on the NSL-KDD intrusion detection benchmark and compared against a One-Class SVM.

## Project structure

```
ai-log-anomaly-detector/
├── data/
│   ├── malicious_logs.csv      # tiny 7-row sample from the blueprint
│   └── nsl-kdd/                # downloaded by src/download_nsl_kdd.py (not committed)
├── models/                     # trained models are saved here
├── results/
│   ├── nsl_kdd_results.json    # all metrics from the benchmark run
│   └── nsl_kdd_roc.png         # ROC curves
├── src/
│   ├── engine.py               # preprocessing, training, detection
│   ├── app.py                  # command line interface
│   ├── generate_data.py        # synthetic data generator (normal + attacks)
│   ├── download_nsl_kdd.py     # fetches the NSL-KDD benchmark files
│   └── evaluate.py             # benchmark evaluation and ROC figure
├── tests/                      # pytest suite
└── requirements.txt
```

## Setup

```
pip install -r requirements.txt
```

## Usage

Quick demo on the small sample:

```
python src/app.py --mode train --input data/malicious_logs.csv --contamination 0.3
python src/app.py --mode analyze --input data/malicious_logs.csv
```

Synthetic data demo:

```
python src/generate_data.py --rows 1000 --out data/synthetic_logs.csv
python src/app.py --mode train --input data/synthetic_logs.csv
python src/app.py --mode analyze --input data/synthetic_logs.csv
```

Benchmark evaluation on real data (about 20 seconds):

```
python src/download_nsl_kdd.py
python src/evaluate.py
```

Run the tests:

```
python -m pytest
```

## How it works

1. **Features:** by default `duration`, `packet_count`, `byte_size`, `failed_logins`. Missing columns become 0 and unparseable values are treated as 0. The engine accepts any feature list.
2. **Scaling:** features are standardized with `StandardScaler`, fitted on training data only.
3. **Model:** `IsolationForest` isolates unusual points in fewer random splits. `contamination` sets the share of training data treated as anomalous, which fixes the detection threshold.
4. **Output:** each row gets an `anomaly_status` (`NORMAL` or `CRITICAL ANOMALY`) and a `risk_score` from 0 to 100 (higher is more anomalous).

## Evaluation on NSL-KDD

**Protocol.** Each detector is trained only on the 67,343 normal connections in `KDDTrain+`, then scored on `KDDTest+` (22,544 connections: 9,711 normal and 12,833 attacks, including attack types that never appear in training). Labels are used only to measure results, never to train.

**Detectors.** Isolation Forest (`contamination=0.05`, trained on all 67,343 normal rows) and a One-Class SVM with an RBF kernel (`nu=0.05`, trained on a random 10,000-row sample of the normal rows because kernel SVMs scale poorly).

**Feature sets.**

- `mapped4`: the pipeline's four features, mapped from NSL-KDD (`duration`; `count` as packet count; `src_bytes + dst_bytes` as byte size; `num_failed_logins`).
- `numeric38`: all 38 numeric NSL-KDD columns.
- `numeric38_protocol`: those plus one-hot protocol (41 features).
- `numeric38_all_cat`: those plus one-hot protocol, flag, and service (122 features).

Categories are taken from the training set only, so categories that appear only in the test set encode as all zeros.

| Detector | Features | Precision | Recall | F1 | ROC AUC |
|---|---|---|---|---|---|
| Isolation Forest | mapped4 | 0.885 | 0.318 | 0.468 | 0.727 |
| Isolation Forest | numeric38 | 0.972 | 0.650 | 0.779 | 0.924 |
| Isolation Forest | numeric38_protocol | 0.971 | 0.668 | 0.791 | 0.929 |
| Isolation Forest | numeric38_all_cat | 0.931 | 0.650 | 0.766 | 0.938 |
| One-Class SVM | mapped4 | 0.847 | 0.267 | 0.406 | 0.697 |
| One-Class SVM | numeric38 | 0.930 | 0.738 | 0.823 | 0.890 |
| One-Class SVM | numeric38_protocol | 0.931 | 0.759 | 0.836 | 0.889 |
| One-Class SVM | numeric38_all_cat | 0.918 | 0.877 | 0.897 | 0.943 |

![ROC curves on the NSL-KDD test set](results/nsl_kdd_roc.png)

Recall by attack type with the full feature set (`numeric38_all_cat`), for the most common attacks in the test set:

| Attack | Test count | Isolation Forest | One-Class SVM |
|---|---|---|---|
| neptune | 4,657 | 1.00 | 1.00 |
| guess_passwd | 1,231 | 0.02 | 0.98 |
| mscan | 996 | 0.96 | 0.95 |
| warezmaster | 944 | 0.06 | 0.54 |
| apache2 | 737 | 0.93 | 1.00 |
| satan | 735 | 0.98 | 0.99 |
| processtable | 685 | 0.38 | 0.84 |
| smurf | 665 | 0.36 | 1.00 |

**Reading the results**

- The four-feature version misses most attacks for both detectors (recall under 0.35, ROC AUC about 0.70). Those four columns alone are not enough for this dataset.
- Using all 38 numeric features is the biggest improvement (Isolation Forest ROC AUC 0.73 to 0.92). Adding protocol helps a little, and adding flag and service helps a little more for Isolation Forest.
- On the numeric-only feature sets, Isolation Forest ranks traffic better than the One-Class SVM (ROC AUC 0.92 vs 0.89). With flag and service added, the two are about tied (0.938 vs 0.943), a gap too small to read much into from a single run.
- The One-Class SVM's recall jump with the full feature set, especially on guess_passwd (0.98 vs 0.02), probably comes from service rarity rather than from detecting password guessing. 750 of the 1,231 guess_passwd test rows use the `pop_3` service, which is only 0.28% of normal training traffic. A detector can flag those rows simply because the service is unusual. This was not isolated further.
- The recall gains come with more false alarms. With the full feature set the One-Class SVM flags 999 of 9,711 normal connections (10.3%) and Isolation Forest flags 620 (6.4%). Because the two detectors sit at different thresholds, compare ROC AUC (which ignores the threshold) rather than precision or recall.
- Both detectors do well on flood and scan style attacks (neptune, satan, mscan, apache2) and poorly on attacks that look like ordinary sessions in these statistics, such as warezmaster.
- NSL-KDD's test set is 57% attacks, far more than real traffic, so precision here would be much lower on a realistic mix. Recall and ROC AUC are the more transferable numbers.
- Results come from one run with a fixed random seed. Variation across seeds was not measured, and the One-Class SVM was trained on a 10,000-row subsample while Isolation Forest used all normal rows.

Dataset: Tavallaee, Bagheri, Lu, Ghorbani, "A Detailed Analysis of the KDD CUP 99 Data Set", IEEE CISDA 2009 (Canadian Institute for Cybersecurity, University of New Brunswick). The download script fetches it from a public GitHub mirror.

## Other notes

- With only 7 rows, the default `contamination=0.05` flags just one of the two attack rows in the sample. Setting `--contamination 0.3` flags both.
- The synthetic data is generated, so it only shows that the pipeline works.

## Ideas for next steps

- Repeat the evaluation over several random seeds and report the spread.
- Test whether the service effect is real: evaluate with and without the rare-service rows, or hold out entire services.
- Add a supervised baseline (for example a random forest) as a reference ceiling, and try an autoencoder detector.
- Build a simple dashboard around the saved model and risk scores.
