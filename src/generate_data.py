"""Generate a larger synthetic log dataset (normal traffic plus injected attacks).

Usage: python src/generate_data.py --rows 1000 --out data/synthetic_logs.csv
"""

import argparse
import os

import numpy as np
import pandas as pd


def generate(rows=1000, attack_fraction=0.05, seed=42):
    rng = np.random.default_rng(seed)
    n_attack = max(1, int(rows * attack_fraction))
    n_normal = rows - n_attack

    normal = pd.DataFrame(
        {
            "duration": rng.gamma(2.0, 0.3, n_normal),
            "packet_count": rng.poisson(12, n_normal),
            "byte_size": rng.normal(1200, 300, n_normal).clip(100),
            "failed_logins": rng.choice([0, 0, 0, 0, 1], n_normal),
            "label": 0,
        }
    )
    attack = pd.DataFrame(
        {
            "duration": rng.uniform(60, 150, n_attack),
            "packet_count": rng.integers(2000, 6000, n_attack),
            "byte_size": rng.uniform(5e5, 1.2e6, n_attack),
            "failed_logins": rng.integers(4, 12, n_attack),
            "label": 1,
        }
    )
    return pd.concat([normal, attack]).sample(frac=1, random_state=seed).reset_index(drop=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=1000)
    parser.add_argument("--out", default="data/synthetic_logs.csv")
    args = parser.parse_args()
    df = generate(args.rows)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"[+] Wrote {len(df)} rows ({int(df.label.sum())} attacks) to {args.out}")
