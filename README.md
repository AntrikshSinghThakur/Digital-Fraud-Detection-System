# Digital Fraud Detection & Investigation System
An advanced, hybrid AI-powered security engine designed to analyze consumer text messages and URLs for potential financial fraud, phishing attempts, and digital scams.

## 🛡️ Core Features
- **Multi-Stage Evidence Extraction:** Custom Python-based analytics parsing for high-risk indicators (OTP requests, credentials harvesting, unauthorized UPI/fee demands).
- **Hybrid AI Core:** Supports high-speed remote cloud evaluation via the **Groq API** and secure offline processing via **Ollama (Llama 3.2)**.
- **Dynamic Risk Scoring:** Algorithmic computation flagging threats into clear Low, Medium, and High-risk bounds with accompanying situational safety recommendations.

## ⚙️ Project Architecture
- `app.py`: The user dashboard interface built entirely on Streamlit.
- `agent.py`: The central investigation hub orchestrating data extraction and final risk levels.
- `Scam_analyzer.py`: The integration module driving the cloud and local LLM chat engines.
- `evidence_analyzer.py`: The rule-based scoring module evaluating string metrics and financial indicators.

## 🚀 Deployed Link
This project is officially live and deployed via **https://digital-fraud-detection-system-hpj4zjj6loe55xpqyo6h2b.streamlit.app/**.
