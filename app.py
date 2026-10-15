import streamlit as st
import pandas as pd
import plotly.express as px
from traceguard.engine import analyze_text, demo_log_text, build_report

st.set_page_config(page_title="TraceGuard AI", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp { background: #08111f; color: #e7eefb; }
[data-testid="stSidebar"] { background: #0d192b; }
div[data-testid="stMetric"] { background:#101f34; border:1px solid #203753; padding:16px; border-radius:12px; }
.block-container { padding-top: 1.4rem; }
h1,h2,h3 { color:#f2f6ff; }
.small-muted { color:#8fa5c2; font-size:0.9rem; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ TraceGuard AI")
st.caption("Evidence-first security log investigation · Local proof of concept")
st.info("Learning/demo tool only. Findings are heuristic indicators, not proof of compromise. Analyze only logs you are authorized to access.")

with st.sidebar:
    st.header("Investigation")
    source = st.radio("Input source", ["Load demo dataset", "Upload a log file"])
    uploaded = None
    if source == "Upload a log file":
        uploaded = st.file_uploader("Choose .log or .txt", type=["log", "txt"])
    st.markdown("---")
    st.caption("Detection is performed locally with transparent rules. No API key required.")

if source == "Load demo dataset":
    text = demo_log_text()
    st.success("Demo dataset loaded — contains intentionally simulated events.")
elif uploaded is not None:
    text = uploaded.getvalue().decode("utf-8", errors="replace")
else:
    text = ""
    st.warning("Upload a .log or .txt file to begin.")

if text:
    result = analyze_text(text)
    events = result["events"]
    findings = result["findings"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events analyzed", len(events))
    c2.metric("Flagged events", len(findings))
    c3.metric("High severity", sum(f["severity"] == "High" for f in findings))
    c4.metric("Unique source IPs", len({e["ip"] for e in events if e.get("ip")}))
    st.markdown("### Investigation overview")
    if events:
        df = pd.DataFrame(events)
        if "timestamp" in df and df["timestamp"].notna().any():
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            timeline = df.dropna(subset=["timestamp"])
            if not timeline.empty:
                counts = timeline.set_index("timestamp").resample("5min").size().reset_index(name="Events")
                st.plotly_chart(px.area(counts, x="timestamp", y="Events", title="Event volume over time",
                                        template="plotly_dark"), use_container_width=True)
        sev_counts = pd.DataFrame([{"Severity": s, "Count": sum(f["severity"] == s for f in findings)}
                                   for s in ["High", "Medium", "Low"]])
        col_a, col_b = st.columns([1, 1])
        with col_a:
            st.plotly_chart(px.bar(sev_counts, x="Severity", y="Count", title="Findings by severity",
                                   template="plotly_dark", color="Severity"), use_container_width=True)
        with col_b:
            st.markdown("#### Detection notes")
            st.write("Rules flag repeated authentication failures, HTTP probing patterns, and suspicious command-like strings.")
            st.caption("A rule match is a lead for review, not a definitive security verdict.")
    st.markdown("### Findings")
    if findings:
        for idx, f in enumerate(findings, 1):
            with st.expander(f'{f["severity"]} · {f["title"]} · {f["count"]} event(s)', expanded=(idx == 1)):
                st.write(f["explanation"])
                st.markdown("**Evidence**")
                for line in f["evidence"][:8]:
                    st.code(line, language="text")
                st.markdown("**Suggested defensive next steps**")
                for action in f["actions"]:
                    st.write(f"• {action}")
    else:
        st.success("No configured detection rules matched. This does not guarantee the logs are safe.")

    st.markdown("### Event table")
    if events:
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
    report = build_report(result)
    st.download_button("⬇️ Download investigation report (.md)", data=report,
                       file_name="traceguard-investigation-report.md", mime="text/markdown")
    st.download_button("⬇️ Download findings (.csv)",
                       data=pd.DataFrame(findings).drop(columns=["evidence", "actions"], errors="ignore").to_csv(index=False),
                       file_name="traceguard-findings.csv", mime="text/csv")
else:
    st.markdown("### What this proof of concept does")
    st.write("Load the simulated dataset or upload a text log to parse events, inspect transparent rule matches, and export a report.")
    st.markdown("- Local processing; no external service required\n- Evidence included for each finding\n- CSV and Markdown exports")
