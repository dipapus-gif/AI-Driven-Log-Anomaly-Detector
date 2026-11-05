"""Streamlit dashboard for the log anomaly detector.

Run:  streamlit run src/dashboard.py
"""

import altair as alt
import pandas as pd
import streamlit as st

from generate_data import generate
from pipeline import (
    FLAGGED,
    ROC_PATH,
    InputError,
    benchmark_table,
    load_benchmark,
    train_engine,
    validate_logs,
)

st.set_page_config(page_title="Log Anomaly Detector", page_icon="🛡️", layout="wide")


@st.cache_data
def cached_benchmark():
    return load_benchmark()


def read_csv(upload):
    try:
        return pd.read_csv(upload)
    except Exception:
        raise InputError("Could not read that file as a CSV.")


def run_pipeline(source, contamination, demo_rows, train_upload, analyze_upload):
    """Train and score; returns (scored DataFrame, engine)."""
    if source == "Synthetic demo":
        df = generate(rows=demo_rows, attack_fraction=contamination)
        train_df = analyze_df = df
    else:
        if train_upload is None:
            raise InputError("Upload a training CSV in the sidebar first.")
        train_df = read_csv(train_upload)
        analyze_df = read_csv(analyze_upload) if analyze_upload else train_df
    engine = train_engine(train_df, contamination)
    return engine.score(validate_logs(analyze_df)), engine


st.title("🛡️ Log Anomaly Detector")
st.caption(
    "An Isolation Forest learns what normal network activity looks like, then flags "
    "sessions that don't fit: long durations, packet floods, repeated failed logins."
)

with st.sidebar:
    st.header("Data")
    source = st.radio("Source", ["Synthetic demo", "Upload CSV"])
    contamination = st.slider(
        "Expected share of anomalies", 0.01, 0.30, 0.05, 0.01,
        help="Sets how aggressively the model flags. In the demo it is also the share of injected attacks.",
    )
    demo_rows = train_upload = analyze_upload = None
    if source == "Synthetic demo":
        demo_rows = st.slider("Rows", 200, 10_000, 1_000, 100)
    else:
        train_upload = st.file_uploader("Training logs (mostly normal)", type="csv")
        analyze_upload = st.file_uploader(
            "Logs to analyze (optional)", type="csv",
            help="Leave empty to score the training file itself.",
        )
        st.caption("Columns used: duration, packet_count, byte_size, failed_logins")
    run = st.button("Train & analyze", type="primary", width="stretch")

if run:
    try:
        with st.spinner("Training and scoring…"):
            st.session_state["result"] = run_pipeline(
                source, contamination, demo_rows, train_upload, analyze_upload
            )
        st.session_state.pop("error", None)
    except InputError as e:
        st.session_state["error"] = str(e)

detect_tab, bench_tab = st.tabs(["Detection", "Benchmark (NSL-KDD)"])

with detect_tab:
    if "error" in st.session_state:
        st.error(st.session_state["error"])
    elif "result" not in st.session_state:
        st.info("Pick a data source in the sidebar and press **Train & analyze**. The synthetic demo works with no files.")
    else:
        scored, engine = st.session_state["result"]
        flagged_mask = scored["anomaly_status"] == FLAGGED
        flagged = scored[flagged_mask].sort_values("risk_score", ascending=False)

        cols = st.columns(4)
        cols[0].metric("Rows analyzed", f"{len(scored):,}")
        cols[1].metric("Flagged", f"{int(flagged_mask.sum()):,}")
        cols[2].metric("Flag rate", f"{flagged_mask.mean():.1%}")
        cols[3].metric("Risk threshold", f"{engine.risk_threshold:.1f}")

        if "label" in scored.columns and scored["label"].isin([0, 1]).all() and scored["label"].sum() > 0:
            attacks = scored["label"] == 1
            caught = int((flagged_mask & attacks).sum())
            st.success(
                f"Labels found in the data: caught **{caught} of {int(attacks.sum())}** attacks "
                f"with **{int((flagged_mask & ~attacks).sum())}** false alarms."
            )

        st.subheader("Risk score distribution")
        chart = (
            alt.Chart(scored[["risk_score"]])
            .mark_bar()
            .encode(
                alt.X("risk_score:Q", bin=alt.Bin(step=5, extent=[0, 100]), title="Risk score (higher = more unusual)"),
                alt.Y("count():Q", title="Sessions"),
            )
        )
        rule = (
            alt.Chart(pd.DataFrame({"t": [engine.risk_threshold]}))
            .mark_rule(color="#e0553a", strokeDash=[6, 4], size=2)
            .encode(x="t:Q")
        )
        st.altair_chart(chart + rule, width="stretch")
        st.caption("Dashed line: sessions scoring above it are flagged.")

        st.subheader(f"Flagged sessions ({len(flagged):,})")
        if flagged.empty:
            st.write("Nothing flagged. Baseline looks clean.")
        else:
            shown = flagged[engine.features + ["risk_score"]].copy()
            shown.insert(0, "row", shown.index + 1)
            st.dataframe(shown, hide_index=True, width="stretch", height=380)
            st.download_button(
                "Download flagged sessions (CSV)",
                flagged.to_csv(index=False).encode(),
                file_name="flagged_sessions.csv",
                mime="text/csv",
            )

with bench_tab:
    results = cached_benchmark()
    if results is None:
        st.warning("No benchmark results found. Run `python src/download_nsl_kdd.py` then `python src/evaluate.py`.")
    else:
        st.write(
            "Both detectors train on normal traffic only and are scored on the NSL-KDD test set. "
            "Richer features help a lot, and the two detectors trade places depending on the feature set."
        )
        table = benchmark_table(results)
        metric = st.radio("Compare by", ["F1", "ROC AUC", "Precision", "Recall"], horizontal=True)
        order = list(dict.fromkeys(table["Feature set"]))
        st.altair_chart(
            alt.Chart(table)
            .mark_bar()
            .encode(
                x=alt.X("Feature set:N", sort=order, title=None, axis=alt.Axis(labelAngle=0, labelLimit=160)),
                xOffset="Detector:N",
                y=alt.Y(f"{metric}:Q", scale=alt.Scale(domain=[0, 1])),
                color=alt.Color("Detector:N", scale=alt.Scale(range=["#2d7be5", "#ea6a3c"])),
                tooltip=["Feature set", "Detector", metric],
            ),
            width="stretch",
        )
        st.dataframe(table, hide_index=True, width="stretch")
        if ROC_PATH.exists():
            st.image(str(ROC_PATH), caption="ROC curves on the NSL-KDD test set. Dots mark each detector's chosen threshold.")
