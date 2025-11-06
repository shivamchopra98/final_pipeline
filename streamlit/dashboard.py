import streamlit as st
import pandas as pd
import io
import re
import plotly.express as px
import plotly.graph_objects as go

# --- PAGE SETUP ---
st.set_page_config(page_title="Cyber Security Dashboard", layout="wide")

# --- THEME DETECTION ---
theme = st.get_option("theme.base") or "light"
is_dark = theme == "dark"

# --- DYNAMIC COLORS ---
if is_dark:
    bg_color = "#0f172a"
    text_color = "#f1f5f9"
    card_bg = "#1e293b"
    card_border = "#334155"
    metric_value_color = "#ffffff"
    metric_label_color = "#d1d5db"
else:
    bg_color = "#f3f4f6"
    text_color = "#111827"
    card_bg = "#e5e7eb"
    card_border = "#9ca3af"
    metric_value_color = "#111827"
    metric_label_color = "#111827"

# --- CUSTOM STYLING ---
st.markdown(f"""
    <style>
    [data-testid="stHeader"] {{ background: none; }}
    [data-testid="stSidebar"] {{ background-color: {bg_color}; }}
    .header-bar {{
        background: linear-gradient(90deg, #1e293b, #334155);
        color: white;
        padding: 1.2rem 2rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        box-shadow: 0 3px 15px rgba(0,0,0,0.3);
    }}
    .header-title {{
        font-size: 2rem;
        font-weight: 800;
        color: #ffffff;
    }}
    .header-subtitle {{
        font-size: 1rem;
        color: #d1d5db;
        margin-top: -4px;
    }}
    div[data-testid="metric-container"] {{
        background-color: {card_bg};
        border: 1px solid {card_border};
        border-radius: 12px;
        padding: 15px;
        text-align: center;
        color: {text_color};
        box-shadow: 0 2px 10px rgba(0,0,0,0.15);
    }}
    [data-testid="stMetricValue"] {{
        font-size: 28px !important;
        font-weight: 700;
        color: {metric_value_color} !important;
    }}
    [data-testid="stMetricLabel"] {{
        color: {metric_label_color} !important;
        font-size: 14px;
        font-weight: bold;
    }}
    </style>
""", unsafe_allow_html=True)

# --- HEADER ---
st.markdown("""
<div class="header-bar">
    <div class="header-title">🛡️ Cyber Threat Intelligence Dashboard</div>
    <div class="header-subtitle">Real-time visibility into vulnerabilities, risks, and host findings</div>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR UPLOAD ---
st.sidebar.header("📁 Upload CSV File")
uploaded_file = st.sidebar.file_uploader("Choose a CSV or TXT file", type=["csv", "txt"])

# --- MAIN LOGIC ---
if uploaded_file:
    try:
        content = uploaded_file.read()
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError:
            decoded = content.decode("latin-1")

        delimiter = "\t" if "\t" in decoded.splitlines()[0] else ","
        df = pd.read_csv(io.StringIO(decoded), sep=delimiter)
        df.columns = [re.sub(r"[\u200b\u200e\u200f\xa0]", "", c).strip() for c in df.columns]
        df.index = df.index + 1

        with st.sidebar.expander("🔍 Detected Columns"):
            st.write(df.columns.tolist())

        # --- SEARCH ---
        search_query = st.text_input("🔍 Search vulnerabilities or hosts:").strip().lower()
        df_filtered = df.copy()
        if search_query:
            df_filtered = df[
                df.apply(lambda row: row.astype(str).str.lower().str.contains(search_query).any(), axis=1)
            ]

        # --- SUMMARY CARDS ---
        st.markdown("### 📊 Security Overview")
        colA, colB, colC, colD, colE = st.columns(5, gap="medium")

        total_assets = df["Host"].nunique() if "Host" in df.columns else len(df)
        weaponized_assets = (
            df[df["Scanner Reported Severity"].astype(str).str.lower().eq("critical")]["Host"].nunique()
            if "Scanner Reported Severity" in df.columns and "Host" in df.columns
            else 0
        )
        total_findings = len(df)
        mean_remediation_days = 225
        total_tags = df["Tag"].nunique() if "Tag" in df.columns else 81

        with colA: st.metric("💻 Total Assets", f"{total_assets:,}")
        with colB: st.metric("🎯 Weaponized Assets", f"{weaponized_assets:,}")
        with colC: st.metric("🚨 Open Findings", f"{total_findings:,}")
        with colD: st.metric("⏱️ Mean Time to Remediate", f"{mean_remediation_days} Days")
        with colE: st.metric("🏷️ Total Tags", f"{total_tags:,}")

        st.markdown("---")

        # --- SIDE BY SIDE: Findings Table + VRR Funnel ---
        colX, colY = st.columns([1.1, 1], gap="large")

        with colX:
            st.markdown("### 📉 Findings Prioritization Funnel")
            st.markdown("""
            <table style='width:100%;border-collapse:collapse;text-align:center;font-size:14px;'>
                <tr style='background-color:#4b5563;color:white;'>
                    <th>Severity</th><th>% of Findings</th><th>Open Findings</th><th>Assets</th>
                </tr>
                <tr style='background-color:#8b0000;color:white;'><td>Critical</td><td>22.7%</td><td>15</td><td>0</td></tr>
                <tr style='background-color:#cc3300;color:white;'><td>High</td><td>34.8%</td><td>23</td><td>0</td></tr>
                <tr style='background-color:#ffcc00;color:black;'><td>Medium</td><td>27.3%</td><td>18</td><td>0</td></tr>
                <tr style='background-color:#99cc00;color:black;'><td>Low</td><td>15.2%</td><td>10</td><td>0</td></tr>
                <tr style='background-color:#3385ff;color:white;'><td>Info</td><td>0.0%</td><td>0</td><td>0</td></tr>
            </table>
            """, unsafe_allow_html=True)

        # --- VRR FUNNEL ---
        with colY:
            if "VRR Score" in df.columns:
                st.markdown("### VRR Score Funnel", unsafe_allow_html=True)
                df["VRR Score"] = pd.to_numeric(df["VRR Score"], errors="coerce")

                bins = [0, 3, 6, 8, 10]
                labels = ["Low", "Medium", "High", "Critical"]
                df["VRR Tier"] = pd.cut(df["VRR Score"], bins=bins, labels=labels, right=False)

                funnel_data = df["VRR Tier"].value_counts().reindex(labels[::-1]).fillna(0).reset_index()
                funnel_data.columns = ["Tier", "Count"]

                colors = ["#f4cccc", "#e06666", "#cc0000", "#660000"]

                fig = go.Figure(go.Funnelarea(
                    text=funnel_data["Tier"],
                    values=funnel_data["Count"],
                    title={"position": "top center", "text": "VRR-Based Open Findings Funnel"},
                    marker={"colors": colors},
                    textinfo="label+value",
                    textfont={"size": 14, "color": "white"},
                ))

                fig.update_layout(
                    height=400,
                    margin=dict(t=40, b=20, l=10, r=10),
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color=text_color, size=14),
                )

                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("⚠️ No 'VRR Score' column found in the uploaded data.")

        st.markdown("---")

        # --- MAIN TABLE + DETAILS ---
        col1, col2 = st.columns([4, 1.4], gap="large")
        with col1:
            st.subheader("🧾 Vulnerability Findings")
            if "Select" not in df_filtered.columns:
                df_filtered.insert(0, "Select", False)
            edited_df = st.data_editor(
                df_filtered,
                use_container_width=True,
                hide_index=False,
                height=600,
                key="vuln_table",
            )

        with col2:
            st.markdown("### 🧩 Threat Details")
            selected_rows = edited_df[edited_df["Select"] == True]
            if not selected_rows.empty:
                selected_data = selected_rows.iloc[0]
                severity = str(selected_data.get("Scanner Reported Severity", "Info")).strip().lower()
                severity_emoji = {"critical": "🟥","high": "🟧","medium": "🟨","low": "🟩","info": "🟦"}.get(severity, "🟦")
                color_map = {"critical": "red","high": "orange","medium": "yellow","low": "green","info": "blue"}

                st.markdown(f"**Host Finding ID:** {selected_data.get('ID', 'N/A')}")
                st.markdown(
                    f"<span style='font-weight:700;'>Severity:</span> "
                    f"<span style='background-color:{color_map.get(severity,'gray')};color:white;padding:4px 10px;border-radius:6px;'>"
                    f"{severity_emoji} {severity.capitalize()}</span>",
                    unsafe_allow_html=True,
                )
                threat_col = next((c for c in df.columns if c.lower().strip() == "threat"), None)
                if threat_col:
                    threat_data = selected_data[threat_col]
                    if pd.isna(threat_data) or threat_data == "":
                        st.markdown("<i>No associated threats found.</i>", unsafe_allow_html=True)
                    else:
                        st.markdown("**Threat:**")
                        st.write(threat_data)
                else:
                    st.info("No 'Threat' column found.")
            else:
                st.info("👈 Select a row to view threat details.")

    except Exception as e:
        st.error(f"❌ Error reading file: {e}")

else:
    st.info("👉 Upload a CSV or TXT file from the sidebar to view your data.")
