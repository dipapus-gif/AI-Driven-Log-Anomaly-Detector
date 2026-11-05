"""Evaluate anomaly detectors on the NSL-KDD intrusion detection benchmark.

Protocol (novelty detection): train only on NORMAL traffic from KDDTrain+,
then score KDDTest+, which contains normal traffic plus attacks (including
attack types that never appear in training). Labels are used only to measure
results, never to train.

Two detectors (Isolation Forest, One-Class SVM) are compared across four
feature sets. Writes results/nsl_kdd_results.json and results/nsl_kdd_roc.png.

Usage:
    python src/download_nsl_kdd.py
    python src/evaluate.py
"""

import argparse
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.svm import OneClassSVM  # noqa: E402

from engine import FEATURES, LogAnomalyEngine, select_features  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack", "level",
]
CATEGORICAL = ["protocol_type", "service", "flag"]
NUMERIC_FEATURES = [c for c in NSL_KDD_COLUMNS[:41] if c not in CATEGORICAL]

DETECTORS = {"isolation_forest": "Isolation Forest", "ocsvm": "One-Class SVM"}
FEATURE_SET_LABELS = {
    "mapped4": "4 mapped features",
    "numeric38": "38 numeric features",
    "numeric38_protocol": "38 numeric + protocol",
    "numeric38_all_cat": "38 numeric + protocol, flag, service",
}


def load_nsl_kdd(path):
    """Load an NSL-KDD file and add the pipeline's four feature columns.

    Mapping: duration -> duration, count -> packet_count,
    src_bytes + dst_bytes -> byte_size, num_failed_logins -> failed_logins.
    Also adds `label` (0 = normal, 1 = attack).
    """
    df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
    df["packet_count"] = df["count"]
    df["byte_size"] = df["src_bytes"] + df["dst_bytes"]
    df["failed_logins"] = df["num_failed_logins"]
    df["label"] = (df["attack"] != "normal").astype(int)
    return df


def category_levels(train_df):
    """Categories seen in training for each categorical column."""
    return {col: sorted(train_df[col].unique()) for col in CATEGORICAL}


def add_one_hot(df, levels):
    """Add `col=value` 0/1 columns for the training categories only.

    Categories that appear only in `df` get no column (they encode as all
    zeros), and training categories absent from `df` are all-zero columns, so
    train and test always share the same columns.
    """
    new = {
        f"{col}={val}": (df[col] == val).astype(int)
        for col, vals in levels.items()
        for val in vals
    }
    return pd.concat([df, pd.DataFrame(new, index=df.index)], axis=1)


def build_feature_sets(levels):
    def enc(col):
        return [f"{col}={v}" for v in levels[col]]

    return {
        "mapped4": list(FEATURES),
        "numeric38": list(NUMERIC_FEATURES),
        "numeric38_protocol": NUMERIC_FEATURES + enc("protocol_type"),
        "numeric38_all_cat": NUMERIC_FEATURES
        + enc("protocol_type") + enc("flag") + enc("service"),
    }


def score_predictions(y_true, flagged, risk):
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, flagged, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_true, flagged, labels=[0, 1]).ravel()
    return {
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(y_true, risk)), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def per_attack_recall(test_df, flagged, top=8):
    attacks = test_df.assign(flagged=flagged)
    attacks = attacks[attacks["label"] == 1]
    grouped = attacks.groupby("attack")["flagged"].agg(["size", "mean"])
    grouped = grouped.sort_values("size", ascending=False).head(top)
    return {
        name: {"count": int(row["size"]), "recall": round(float(row["mean"]), 4)}
        for name, row in grouped.iterrows()
    }


def run_isolation_forest(name, features, train_normal, test_df, contamination, model_dir):
    engine = LogAnomalyEngine(contamination=contamination, features=features)
    engine.fit(train_normal)
    model_path = os.path.join(model_dir, f"nsl_kdd_if_{name}.pkl")
    engine.save(model_path)
    scored = engine.detect_anomalies(test_df, model_path)
    flagged = (scored["anomaly_status"] == "CRITICAL ANOMALY").astype(int).values
    return flagged, scored["risk_score"].values


def run_ocsvm(features, train_normal, test_df, nu, n_train, seed=42):
    """One-Class SVM (RBF). Fit on a random subsample of the normal rows
    because the kernel SVM scales poorly with training size. `nu` plays the
    same role as Isolation Forest's contamination."""
    sample = train_normal.sample(n=min(n_train, len(train_normal)), random_state=seed)
    scaler = StandardScaler().fit(select_features(sample, features))
    svm = OneClassSVM(kernel="rbf", gamma="scale", nu=nu)
    svm.fit(scaler.transform(select_features(sample, features)))
    decision = svm.decision_function(scaler.transform(select_features(test_df, features)))
    flagged = (decision < 0).astype(int)
    return flagged, -decision  # higher = more anomalous


def plot_roc(curves, results, out_path):
    """2x2 small multiples (one panel per feature set), one color per detector."""
    surface, ink, ink2, muted = "#fcfcfb", "#0b0b0b", "#52514e", "#898781"
    grid, axis_c = "#e1e0d9", "#c3c2b7"
    colors = {"isolation_forest": "#2a78d6", "ocsvm": "#eb6834"}

    fig, axes = plt.subplots(2, 2, figsize=(9.2, 8.6), sharex=True, sharey=True)
    fig.patch.set_facecolor(surface)
    for ax, fs in zip(axes.ravel(), FEATURE_SET_LABELS):
        ax.set_facecolor(surface)
        ax.grid(True, color=grid, linewidth=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(axis_c)
        ax.tick_params(colors=muted, length=0, labelsize=9)
        ax.plot([0, 1], [0, 1], color=axis_c, linewidth=1.0, zorder=1)  # chance
        for det, label in DETECTORS.items():
            if (det, fs) not in curves:
                continue
            fpr, tpr = curves[(det, fs)]
            r = results[det][fs]
            ax.plot(
                fpr, tpr, color=colors[det], linewidth=1.8, zorder=2,
                label=f"{label}  (AUC {r['roc_auc']:.2f})",
            )
            # operating point at the detector's chosen threshold
            op_fpr = r["fp"] / (r["fp"] + r["tn"])
            op_tpr = r["tp"] / (r["tp"] + r["fn"])
            ax.scatter(
                [op_fpr], [op_tpr], s=42, color=colors[det],
                edgecolor=surface, linewidth=1.6, zorder=3,
            )
        ax.set_title(
            FEATURE_SET_LABELS[fs], loc="left", fontsize=10.5,
            color=ink, fontweight="bold", pad=8,
        )
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.02)
        legend = ax.legend(loc="lower right", frameon=False, fontsize=9)
        for text in legend.get_texts():
            text.set_color(ink2)
    for ax in axes[1]:
        ax.set_xlabel("Normal traffic flagged (false alarm rate)", color=ink2, fontsize=9.5)
    for ax in axes[:, 0]:
        ax.set_ylabel("Attacks caught (recall)", color=ink2, fontsize=9.5)

    fig.suptitle(
        "ROC curves on the NSL-KDD test set", x=0.065, ha="left",
        fontsize=13, color=ink, fontweight="bold", y=0.985,
    )
    fig.text(
        0.065, 0.015,
        "Trained on normal traffic only. Dots mark each detector's chosen threshold; "
        "the gray diagonal is chance.",
        fontsize=8.5, color=muted, ha="left",
    )
    fig.tight_layout(rect=(0.02, 0.04, 1, 0.96))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fig.savefig(out_path, dpi=160, facecolor=surface)
    plt.close(fig)


def print_summary(results):
    print(f"\n{'detector':<18}{'features':<22}{'n':>4}{'prec':>8}{'recall':>8}{'f1':>8}{'auc':>8}")
    for det, label in DETECTORS.items():
        for fs, r in results.get(det, {}).items():
            print(
                f"{label:<18}{fs:<22}{r['n_features']:>4}{r['precision']:>8.3f}"
                f"{r['recall']:>8.3f}{r['f1']:>8.3f}{r['roc_auc']:>8.3f}"
            )
    for det, label in DETECTORS.items():
        if det not in results:
            continue
        fs, r = max(results[det].items(), key=lambda kv: kv[1]["roc_auc"])
        print(f"\n[{label} | best by AUC: {fs}] confusion matrix (rows = actual)")
        print("              normal   attack")
        print(f"  normal    {r['tn']:>8} {r['fp']:>8}")
        print(f"  attack    {r['fn']:>8} {r['tp']:>8}")
        print("  recall by attack type:")
        for atk, v in r["per_attack_recall"].items():
            print(f"    {atk:<16}{v['count']:>6}  {v['recall']:.2f}")


def main():
    default_dir = os.path.join(PROJECT_ROOT, "data", "nsl-kdd")
    results_dir = os.path.join(PROJECT_ROOT, "results")
    parser = argparse.ArgumentParser(description="Evaluate on NSL-KDD")
    parser.add_argument("--train", default=os.path.join(default_dir, "KDDTrain+.txt"))
    parser.add_argument("--test", default=os.path.join(default_dir, "KDDTest+.txt"))
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Isolation Forest contamination and One-Class SVM nu")
    parser.add_argument("--ocsvm-rows", type=int, default=10000,
                        help="Normal training rows sampled for the One-Class SVM")
    parser.add_argument("--no-ocsvm", action="store_true", help="Skip the One-Class SVM")
    parser.add_argument("--model-dir", default=os.path.join(PROJECT_ROOT, "models"))
    parser.add_argument("--out", default=os.path.join(results_dir, "nsl_kdd_results.json"))
    parser.add_argument("--plot", default=os.path.join(results_dir, "nsl_kdd_roc.png"))
    args = parser.parse_args()

    for path in (args.train, args.test):
        if not os.path.exists(path):
            print(f"[-] Missing {path}. Run: python src/download_nsl_kdd.py")
            raise SystemExit(1)

    train_df = load_nsl_kdd(args.train)
    test_df = load_nsl_kdd(args.test)
    levels = category_levels(train_df)
    train_df = add_one_hot(train_df, levels)
    test_df = add_one_hot(test_df, levels)
    train_normal = train_df[train_df["label"] == 0]
    feature_sets = build_feature_sets(levels)
    print(
        f"Train (normal only): {len(train_normal)} rows | "
        f"Test: {len(test_df)} rows, {int(test_df['label'].sum())} attacks "
        f"({test_df['label'].mean():.1%})"
    )

    detectors = ["isolation_forest"] + ([] if args.no_ocsvm else ["ocsvm"])
    results = {det: {} for det in detectors}
    curves = {}
    for det in detectors:
        for fs, feats in feature_sets.items():
            print(f"[*] {DETECTORS[det]} on {fs} ({len(feats)} features)")
            if det == "isolation_forest":
                flagged, risk = run_isolation_forest(
                    fs, feats, train_normal, test_df, args.contamination, args.model_dir
                )
            else:
                flagged, risk = run_ocsvm(
                    feats, train_normal, test_df, args.contamination, args.ocsvm_rows
                )
            res = score_predictions(test_df["label"], flagged, risk)
            res["n_features"] = len(feats)
            res["per_attack_recall"] = per_attack_recall(test_df, flagged)
            results[det][fs] = res
            fpr, tpr, _ = roc_curve(test_df["label"], risk)
            curves[(det, fs)] = (fpr, tpr)

    print_summary(results)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(
            {
                "contamination": args.contamination,
                "ocsvm_train_rows": args.ocsvm_rows,
                "results": results,
            },
            fh, indent=2,
        )
    plot_roc(curves, results, args.plot)
    print(f"\n[+] Results saved to {args.out}")
    print(f"[+] ROC figure saved to {args.plot}")


if __name__ == "__main__":
    main()
