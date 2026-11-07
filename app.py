import streamlit as st
from agent import investigate

# ----------------------------------
# 1. PAGE CONFIGURATION (MUST BE FIRST)
# ----------------------------------
st.set_page_config(
    page_title="Digital Fraud Detection and Investigation System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------------------------
# 2. CUSTOM UI STYLING & CLEANUP
# ----------------------------------
st.markdown("""
    <style>
    /* Hide top header bar and default footer */
    header {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Professional metric styling */
    [data-testid="stMetricValue"] {
        font-size: 26px;
        font-weight: 700;
    }
    </style>
""", unsafe_allow_html=True)

# ----------------------------------
# 3. SIDEBAR NAVIGATION & STATUS
# ----------------------------------
with st.sidebar:
    st.markdown("### ⚙️ Control Panel")
    
    # Dropdown selector for AI Engine Mode
    st.session_state["ai_mode"] = st.selectbox(
        "AI Engine Mode", 
        ["Groq Cloud (Live Demo)", "Ollama (Local Host)"],
        help="Switch to Groq Cloud for the deployed link, or Ollama if running on your local machine."
    )
    
    st.divider()
    st.caption("🟢 System Status: Connected")
    st.caption("🔒 Enterprise Security Edition")

# ----------------------------------
# 4. PAGE TITLE CONTAINER
# ----------------------------------
with st.container(border=True):
    st.markdown(":blue[🛡️ CYBERSECURITY | THREAT INTELLIGENCE]")
    st.title("Digital Fraud Detection and Investigation System")
    st.write(
        "Intelligent investigation of suspicious messages, "
        "phishing indicators and potentially fraudulent URLs."
    )

# ----------------------------------
# 5. USER INPUT
# ----------------------------------
st.markdown("### 🔹 :blue[Enter Suspicious Information]")

message = st.text_area(
    "Paste a suspicious SMS or email:",
    placeholder="Example: Your account is blocked. Verify your details..."
)

url = st.text_input(
    "Enter a suspicious website URL:",
    placeholder="https://example.com"
)

# ----------------------------------
# 6. INVESTIGATION BUTTON & EXECUTION
# ----------------------------------
if st.button("🚀 Start Investigation", type="primary"):

    if not message.strip() and not url.strip():
        st.warning("Please enter a message or URL to investigate.")

    else:
        with st.spinner("Agent is investigating..."):
            report = investigate(message, url)

        st.success("Agent investigation completed!")

        st.markdown("## 📊 :blue[Investigation Results]")
        st.caption("Detailed analysis and threat intelligence report")

        # ----------------------------------
        # AGENT DECISION AND SELECTED TOOLS
        # ----------------------------------
        st.write("### 🧠 Agent Decision & Selected Tools")
        st.info(report.get("agent_decision", "No decision available."))

        for tool in report.get("investigation_plan", []):
            st.write("🔹", tool)

        st.divider()

        # ----------------------------------
        # INVESTIGATION PROCESS
        # ----------------------------------
        st.write("### 🔍 Agent Reasoning & Investigation Process")

        for stage in report.get("investigation_stages", []):
            st.write("🔹", stage)

        st.divider()

        # ----------------------------------
        # ACTIONS PERFORMED
        # ----------------------------------
        st.write("### Actions Performed")

        for action in report.get("actions_taken", []):
            st.write("✅", action)

        st.divider()

        # ----------------------------------
        # OVERALL RISK ASSESSMENT
        # ----------------------------------
        st.markdown("### 📊 :blue[Overall Risk Assessment]")
        st.caption("Preliminary threat level based on detected indicators")

        risk_level = report.get("risk_level", "Unknown")
        risk_score = report.get("risk_score", 0)

        st.metric(
            label="🎯 Overall Risk Score",
            value=f"{risk_score} / 12",
            help="Score based on detected suspicious indicators."
        )

        if risk_level == "High":
            st.error("🚨 HIGH RISK — Immediate Attention Required")
        elif risk_level == "Medium":
            st.warning("⚠️ MEDIUM RISK — Further Investigation Needed")
        elif risk_level == "Low":
            st.success("🟢 LOW RISK — No Major Threat Indicators")
        else:
            st.info("Risk assessment unavailable.")

        st.caption(
            "Risk levels are preliminary assessments based on "
            "the current detection rules and analysis."
        )

        st.divider()

        # ----------------------------------
        # EVIDENCE-BASED CLASSIFICATION
        # ----------------------------------
        if report.get("verified_classification"):
            st.subheader("🧠 Evidence-Based Scam Classification")
            with st.container(border=True):
                classification = report["verified_classification"]

                if classification == "Likely Scam":
                    st.error("🔴 " + classification)
                elif classification == "Suspicious":
                    st.warning("🟠 " + classification)
                else:
                    st.success("🟢 " + classification)

                st.write(report.get("classification_note", ""))
                st.caption("This classification is generated using Python evidence checks.")

            st.divider()

        # ----------------------------------
        # MESSAGE ANALYSIS (Properly Indented)
        # ----------------------------------
        if report.get("message_analysis"):
            st.subheader("📨 Message Analysis")

            with st.container(border=True):
                st.write(report["message_analysis"])
                st.info(
                    f"Final Evidence-Based Classification: "
                    f"{report.get('verified_classification', 'Not Classified')}"
                )

            st.divider()

        # ----------------------------------
        # URL INVESTIGATION
        # ----------------------------------
        url_analysis = report.get("url_analysis")

        if url_analysis:
            st.write("### 🔗 URL Investigation")

            if isinstance(url_analysis, dict):
                st.write(
                    "**Assessment:**",
                    url_analysis.get("risk", "Assessment unavailable")
                )

                if url_analysis.get("message"):
                    st.write(url_analysis["message"])

                url_findings = url_analysis.get("findings", [])

                if url_findings:
                    st.write("### Evidence and Suspicious Indicators")

                    for item in url_findings:
                        if isinstance(item, dict):
                            st.warning(f"⚠️ {item.get('finding', 'Suspicious indicator')}")
                            st.write("**Evidence:**", item.get("evidence", "Not specified"))
                            st.write("**Reason:**", item.get("reason", "No explanation available."))
                        else:
                            st.warning(str(item))
                        st.divider()
                else:
                    st.success("No basic suspicious indicators were detected by URL checks.")
            else:
                st.write(url_analysis)

        st.divider()

        # ----------------------------------
        # EVIDENCE CORRELATION
        # ----------------------------------
        st.subheader("🔗 Evidence Correlation & Intelligence")
        correlations = report.get("evidence_correlations", [])

        if correlations:
            for item in correlations:
                if isinstance(item, dict):
                    st.markdown(f"**{item.get('title', 'Evidence correlation')}**")
                    st.write(item.get("explanation", "No explanation available."))
                else:
                    st.write(item)
                st.divider()
        else:
            st.info("No evidence correlations were identified from the supplied inputs.")

        # ----------------------------------
        # MESSAGE EVIDENCE
        # ----------------------------------
        st.write("### 🔎 Message Evidence")
        message_evidence = report.get("message_evidence", [])

        if message_evidence:
            for item in message_evidence:
                st.warning(f"⚠️ {item['category']}")
                st.write("**Detected phrase:**", item["evidence"])
                st.write("**Explanation:**", item["explanation"])
                st.divider()
        else:
            st.info("No message evidence detected.")

        # ----------------------------------
        # SAFETY RECOMMENDATIONS
        # ----------------------------------
        st.write("### 🛡️ Safety Recommendations")
        recommendations = report.get("safety_recommendations", [])

        if recommendations:
            for recommendation in recommendations:
                st.success(f"✓ {recommendation}")
        else:
            st.warning("No safety recommendations generated.")

        st.divider()