import streamlit as st
import pandas as pd
import io
import ast
import re

st.set_page_config(page_title="Cyber Security Dashboard", layout="wide")

# 💅 Custom CSS for cyber dashboard aesthetics
st.markdown("""
    <style>
    body {
        font-family: 'Segoe UI', sans-serif;
        background-color: #f4f6f8;
    }

    /* Header bar */
    .header-bar {
        background: linear-gradient(90deg, #0f172a, #1e293b);
        color: white;
        padding: 1.2rem 2rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        box-shadow: 0 2px 12px rgba(0,0,0,0.3);
    }
    .header-title {
        font-size: 1.9rem;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
    .header-subtitle {
        font-size: 0.9rem;
        color: #94a3b8;
        margin-top: -4px;
    }

    /* Detail card */
    .detail-card {
        background-color: #ffffff;
        border: 1px solid #e5e7eb;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.05);
        font-family: 'Segoe UI', sans-serif;
        color: #333;
    }

    .section-title {
        font-weight: 600;
        color: #374151;
        margin-top: 10px;
        margin-bottom: 5px;
    }

    .badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 14px;
        font-size: 13px;
        font-weight: 600;
        color: white;
    }

    .critical { background-color: #dc2626; }
    .high { background-color: #f97316; }
    .medium { background-color: #eab308; color: black; }
    .low { background-color: #22c55e; }
    .info { background-color: #3b82f6; }

    .subtext {
        font-size: 13px;
        color: #6b7280;
    }

    hr {
        border: none;
        border-top: 1px solid #e5e7eb;
        margin: 10px 0;
    }

    </style>
""", unsafe_allow_html=True)

# 🧠 Dashboard Header
st.markdown("""
<div class="header-bar">
    <div class="header-title">🛡️ Cyber Threat Intelligence Dashboard</div>
    <div class="header-subtitle">Real-time visibility into vulnerabilities, risks, and host findings</div>
</div>
""", unsafe_allow_html=True)

# Sidebar upload
st.sidebar.header("📁 Upload CSV File")
uploaded_file = st.sidebar.file_uploader("Choose a CSV or TXT file", type=["csv", "txt"])

if uploaded_file:
    try:
        content = uploaded_file.read()
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError:
            decoded = content.decode("latin-1")

        delimiter = "\t" if "\t" in decoded.splitlines()[0] else ","
        df = pd.read_csv(io.StringIO(decoded), sep=delimiter)

        # Clean invisible characters
        df.columns = [re.sub(r"[\u200b\u200e\u200f\xa0]", "", c).strip() for c in df.columns]
        df.index = df.index + 1

        with st.sidebar.expander("🔍 Detected Columns"):
            st.write(df.columns.tolist())

        # Convert URL-like columns to markdown links
        for col in df.columns:
            if any(x in col.lower() for x in ["see", "link", "url"]):
                df[col] = df[col].apply(
                    lambda x: f"[{x}]({x})"
                    if isinstance(x, str) and x.startswith(("http://", "https://"))
                    else x
                )

        visible_cols = df.columns.tolist()
        search_query = st.text_input("🔍 Search vulnerabilities or hosts:").strip().lower()

        df_filtered = df.copy()
        if search_query:
            df_filtered = df[
                df.apply(lambda row: row.astype(str).str.lower().str.contains(search_query).any(), axis=1)
            ]

        # Columns - smaller right panel for details
        col1, col2 = st.columns([4, 1.3], gap="large")

        with col1:
            st.subheader("🧾 Vulnerability Findings")
            df_filtered["Select"] = False
            edited_df = st.data_editor(
                df_filtered[["Select"] + visible_cols],
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
                threat_col = next((c for c in df.columns if c.lower().strip() == "threat"), None)

                st.markdown('<div class="detail-card">', unsafe_allow_html=True)

                # Host Finding
                st.markdown(f"**Host Finding ID:** {selected_data.get('ID', 'N/A')}")

                # Scanner and Plugin
                st.markdown(f"<span class='section-title'>Scanner:</span> {selected_data.get('Scanner Name', 'Unknown')}", unsafe_allow_html=True)
                st.markdown(f"<span class='section-title'>Plugin:</span> {selected_data.get('Scanner Plugin', 'N/A')}", unsafe_allow_html=True)
                st.markdown("<hr>", unsafe_allow_html=True)

                # 🟡 Severity Handling with emoji indicators
                raw_sev = str(selected_data.get("Severity", "Info")).strip().lower()
                pretty_sev = raw_sev.capitalize() if raw_sev else "Info"

                severity_emoji = {
                    "critical": "🟥",
                    "high": "🟧",
                    "medium": "🟨",
                    "low": "🟩",
                    "info": "🟦"
                }.get(raw_sev, "🟦")

                color = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                    "info": "info"
                }.get(raw_sev, "info")

                st.markdown(
                    f"<span class='section-title'>Severity:</span> "
                    f"<span class='badge {color}'>{severity_emoji} {pretty_sev}</span>",
                    unsafe_allow_html=True
                )

                st.markdown("<hr>", unsafe_allow_html=True)

                # Description
                desc = selected_data.get("Description", "No description available.")
                st.markdown("<span class='section-title'>Description:</span>", unsafe_allow_html=True)
                st.markdown(f"<div class='subtext'>{desc}</div>", unsafe_allow_html=True)

                # Threats
                if threat_col:
                    threat_data = selected_data[threat_col]
                    if pd.isna(threat_data) or threat_data == "":
                        st.markdown("<br><i>No associated threats found.</i>", unsafe_allow_html=True)
                    else:
                        st.markdown("<span class='section-title'>Associated Threats:</span>", unsafe_allow_html=True)
                        try:
                            parsed = ast.literal_eval(threat_data) if isinstance(threat_data, str) else []
                            if isinstance(parsed, list):
                                for t in parsed:
                                    st.markdown(f"- {t}")
                            else:
                                st.write(threat_data)
                        except Exception:
                            st.write(threat_data)

                st.markdown("</div>", unsafe_allow_html=True)

            else:
                st.info("👈 Select a row to view threat details.")

        st.caption(f"✅ Columns detected: {', '.join(df.columns)}")

    except Exception as e:
        st.error(f"❌ Error reading file: {e}")

else:
    st.info("👉 Upload a CSV or TXT file from the sidebar to view your data.")
