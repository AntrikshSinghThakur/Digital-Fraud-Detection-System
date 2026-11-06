import streamlit as st
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:1b"

def analyze_message(message):
    prompt = f"""
You are a cybersecurity investigator analysing consumer
messages for possible scams.

Analyse the actual meaning and instructions in the message.
Do not classify based on keywords alone.

MESSAGE:
{message}

Return all eight sections below.

1. MESSAGE INTENT
Explain what the sender wants the recipient to do.

2. AI SCAM CLASSIFICATION
Choose exactly one:
- Likely Scam
- Suspicious
- No Clear Scam Evidence

Classification rules:

LIKELY SCAM:
Use only when there is clear evidence of deception, such as
a request to reveal an OTP, password, PIN, banking credentials,
make an unexpected payment, or visit a suspicious link.

SUSPICIOUS:
Use when meaningful warning signs exist, but there is not
enough evidence to establish a likely scam.

NO CLEAR SCAM EVIDENCE:
Use when the message contains ordinary communication and
no meaningful evidence of deception.

IMPORTANT:
- "Share your OTP" is a request.
- "Never share your OTP" is a protective warning.
- If a message explicitly asks the recipient to submit,
  provide, enter, or reveal their password, OTP, PIN,
  or banking credentials, treat this as strong evidence
  of a likely scam.
- Do not describe an explicit request for credentials
  as a protective warning.
- Always check the MESSAGE text before writing your
  evidence and classification.
- Never claim that the message contains a protective
  warning unless those exact words appear in the message.
- Mentioning a password is not requesting a password.
- Mentioning banking security does not prove phishing.
- A formal tone does not prove fraud.
- Do not invent urgency, threats, or suspicious links.
- Do not invent requests absent from the message.

3. EVIDENCE SUPPORTING CLASSIFICATION
Quote exact phrases from the message.
Explain what each phrase demonstrates.
If there is no meaningful evidence, say so.

4. POSSIBLE SCAM TECHNIQUES
Identify only techniques supported by exact evidence.
If none are supported, write:
"No clear scam technique identified."

5. CONTEXTUAL REASONING
Explain the complete message's purpose.
Distinguish between requesting sensitive information
and warning someone not to disclose it.

6. UNCERTAINTY ASSESSMENT
Explain what cannot be verified from the text alone.
Do not claim fraud is proven.

7. SAFETY RECOMMENDATIONS
Provide five practical safety recommendations.
Include using official banking channels and never sharing
passwords, PINs, or OTPs.

8. FINAL INVESTIGATION SUMMARY
Summarise the intent, classification, evidence,
techniques, and uncertainty.

FINAL CHECK:
Make sure your classification agrees with your evidence.
Do not select Likely Scam without clear supporting evidence.
"""

    # Read the selection from Streamlit UI session state (defaults to Groq Cloud for web demo)
    ai_mode = st.session_state.get("ai_mode", "Groq Cloud (Live Demo)")

    # ==========================================
    # ENGINE 1: GROQ CLOUD API (For Streamlit Cloud deployment)
    # ==========================================
    if ai_mode == "Groq Cloud (Live Demo)":
        try:
            from groq import Groq
            
            # Pulls key securely from Streamlit Cloud Advanced Settings -> Secrets
            client = Groq(api_key=st.secrets["GROQ_API_KEY"])
            
            completion = client.chat.completions.create(
                model="llama3-8b-8192", 
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=450
            )
            
            result = completion.choices.message.content.strip()
            return filter_refusals(result)
            
        except Exception as error:
            return f"Groq Cloud API Connection Error: {error}. Please ensure GROQ_API_KEY is configured in Streamlit Secrets."

    # ==========================================
    # ENGINE 2: LOCAL OLLAMA (For your local host testing)
    # ==========================================
    else:
        try:
            response = requests.post(
                OLLAMA_URL,
                json={
                    "model": MODEL_NAME,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 450,
                        "num_ctx": 2048
                    }
                },
                timeout=180
            )

            response.raise_for_status()
            result = response.json().get("response", "").strip()
            return filter_refusals(result)

        except requests.exceptions.RequestException as error:
            return (
                f"AI connection error: {error}\n\n"
                "Ollama is not running on localhost. If you are viewing the live web link, "
                "please switch the 'AI Engine Mode' toggle to 'Groq Cloud (Live Demo)' in the sidebar."
            )

def filter_refusals(result):
    if not result:
        return (
            "AI analysis could not be completed.\n\n"
            "Please use the independent Python evidence-based "
            "classification shown by the system."
        )

    refusal_phrases = [
        "i cannot provide a final classification",
        "i can't provide a final classification",
        "i cannot assist with identifying scam",
        "i can't assist with identifying scam",
        "can i help you with anything else"
    ]

    if any(phrase in result.lower() for phrase in refusal_phrases):
        return (
            "AI MODEL REFUSAL\n\n"
            "The AI model did not complete the investigation.\n\n"
            "No AI-generated classification is available. "
            "Please refer to the independent Python "
            "evidence-based classification and risk assessment."
        )

    return result