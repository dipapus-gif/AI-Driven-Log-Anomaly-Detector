"""Command line interface for the log anomaly detector."""

import argparse
import os

import pandas as pd

from engine import LogAnomalyEngine

DISPLAY_COLS = ["duration", "packet_count", "byte_size", "failed_logins", "risk_score"]


def main():
    parser = argparse.ArgumentParser(
        description="AI-Driven Security Log Anomaly Detection Pipeline"
    )
    parser.add_argument("--mode", choices=["train", "analyze"], required=True)
    parser.add_argument("--input", required=True, help="Path to a CSV of logs")
    parser.add_argument("--model", default="models/anomaly_model.pkl")
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Expected fraction of anomalies in training data (train mode)",
    )
    args = parser.parse_args()

    if args.mode == "train":
        engine = LogAnomalyEngine(contamination=args.contamination)
        try:
            engine.train(args.input, args.model)
        except Exception as e:
            print(f"[-] Training failed: {e}")
            raise SystemExit(1)
        return

    # analyze mode
    if not os.path.exists(args.model):
        print(f"[-] Missing model file: {args.model}. Run --mode train first.")
        raise SystemExit(1)
    if not os.path.exists(args.input):
        print(f"[-] Missing input file: {args.input}")
        raise SystemExit(1)

    engine = LogAnomalyEngine()
    live_df = pd.read_csv(args.input)
    results_df = engine.detect_anomalies(live_df, args.model)
    anomalies = results_df[results_df["anomaly_status"] == "CRITICAL ANOMALY"]

    print("\n" + "=" * 50)
    print(" DETECTION TELEMETRY SUMMARY")
    print("=" * 50)
    print(f"Rows analyzed: {len(results_df)} | Anomalies: {len(anomalies)}")
    if not anomalies.empty:
        print(anomalies[DISPLAY_COLS].to_string(index=False))
    else:
        print("[+] System baseline secure.")


if __name__ == "__main__":
    main()
