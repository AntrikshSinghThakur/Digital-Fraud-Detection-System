from Scam_analyzer import analyze_message
from URL_checker import check_url

from evidence_analyzer import (
    extract_evidence,
    generate_recommendations,
    correlate_evidence,
    classify_message
)

def investigate(message="", url=""):

    report = {
        "message_analysis": None,
        "message_evidence": [],
        "url_analysis": None,
        "evidence_correlations": [],
        "safety_recommendations": [],
        "actions_taken": [],
        "investigation_plan": [],
        "agent_decision": "",
        "risk_level": "Low",
        "risk_score": 0,
        "risk_reasons": [],
        "verified_classification": "Not Classified",
        "classification_note": "",
        "investigation_stages": [
            "Input received",
            "Message evidence extraction",
            "AI message analysis",
            "URL investigation",
            "Evidence correlation",
            "Risk assessment",
            "Safety recommendations"
        ]
    }

    risk_score = 0

    has_message = bool(message and message.strip())
    has_url = bool(url and url.strip())

    findings = []
    url_findings = []

    # ==========================================
    # STAGE 1: MESSAGE INVESTIGATION
    # ==========================================

    if has_message:

        findings = extract_evidence(message)

        report["message_evidence"] = findings

        report["actions_taken"].append(
            "Message evidence extraction completed."
        )

        print("DEBUG MESSAGE FINDINGS:", findings)

        # --------------------------------------
        # Risk calculation for message evidence
        # --------------------------------------

        strong_count = sum(
            1 for item in findings
            if item.get("strength") == "Strong"
        )

        weak_count = sum(
            1 for item in findings
            if item.get("strength") != "Strong"
        )

        message_risk = (
            (strong_count * 5) +
            (weak_count * 2)
        )

        # Maximum message contribution: 8
        message_risk = min(message_risk, 8)
        print("DEBUG STRONG COUNT:", strong_count)
        print("DEBUG WEAK COUNT:", weak_count)
        print("DEBUG RISK THRESHOLDS: Low=0-3, Medium=4-7, High=8-12")
        print("DEBUG MESSAGE RISK:", message_risk)

        risk_score += message_risk

        for item in findings:

            report["risk_reasons"].append(
                f"{item['category']}: {item['evidence']}"
            )

        # --------------------------------------
        # Generate safety recommendations
        # --------------------------------------

        recommendations = generate_recommendations(findings)

        report["safety_recommendations"] = recommendations

        print(
            "DEBUG GENERATED RECOMMENDATIONS:",
            recommendations
        )

        # --------------------------------------
        # AI message analysis
        # --------------------------------------

        try:

            report["message_analysis"] = analyze_message(message)

            report["actions_taken"].append(
                "AI message analysis completed."
            )

        except Exception as e:

            report["message_analysis"] = (
                f"AI analysis unavailable: {str(e)}"
            )

            print("AI ANALYSIS ERROR:", e)

    # ==========================================
    # STAGE 2: URL INVESTIGATION
    # ==========================================

    if has_url:

        try:

            report["url_analysis"] = check_url(url)

            report["actions_taken"].append(
                "URL investigation completed."
            )

            if isinstance(report["url_analysis"], dict):

                url_findings = report["url_analysis"].get(
                    "findings", []
                )

                if not isinstance(url_findings, list):
                    url_findings = []

            print("DEBUG URL FINDINGS:", url_findings)

        except Exception as e:

            report["url_analysis"] = {
                "error": str(e),
                "findings": []
            }

            print("URL CHECK ERROR:", e)

    # ==========================================
    # STAGE 3: URL RISK CALCULATION
    # ==========================================

    url_risk = min(len(url_findings) * 2, 4)

    risk_score += url_risk

    for item in url_findings:

        if isinstance(item, dict):

            evidence = item.get(
                "evidence",
                item.get("description", str(item))
            )

        else:
            evidence = str(item)

        report["risk_reasons"].append(
            f"URL finding: {evidence}"
        )

    # ==========================================
    # STAGE 4: EVIDENCE CORRELATION
    # ==========================================

    try:

        report["evidence_correlations"] = correlate_evidence(
            report["message_evidence"],
            url_findings
        )

        report["actions_taken"].append(
            "Evidence correlation completed."
        )

    except Exception as e:

        report["evidence_correlations"] = []

        print("CORRELATION ERROR:", e)

    # ==========================================
    # STAGE 5: CLASSIFICATION
    # ==========================================

    if has_message or has_url:

        try:

            classification_result = classify_message(
                message,
                findings,
                url_findings
            )

            report["verified_classification"] = (
                classification_result.get(
                    "classification",
                    "Not Classified"
                )
            )

            report["classification_note"] = (
                classification_result.get(
                    "reason",
                    "Classification based on detected evidence."
                )
            )

        except Exception as e:

            report["verified_classification"] = "Not Classified"

            report["classification_note"] = (
                f"Classification unavailable: {str(e)}"
            )

            print("CLASSIFICATION ERROR:", e)

    # ==========================================
    # STAGE 6: FINAL RISK ASSESSMENT
    # ==========================================

    # Strict maximum risk score: 12
    risk_score = min(risk_score, 12)

    report["risk_score"] = risk_score

    if risk_score >= 8:
        report["risk_level"] = "High"

    elif risk_score >= 4:
        report["risk_level"] = "Medium"

    else:
        report["risk_level"] = "Low"

    print("TEST:", risk_score, report["risk_level"])

    # ==========================================
    # STAGE 7: AGENT DECISION
    # ==========================================

    if report["risk_level"] == "High":

        report["agent_decision"] = (
            "High risk detected. Do not interact with "
            "the suspicious message or URL. Verify through "
            "official channels."
        )

    elif report["risk_level"] == "Medium":

        report["agent_decision"] = (
            "Suspicious indicators detected. Investigate "
            "further before taking any action."
        )

    else:

        report["agent_decision"] = (
            "No strong indicators of fraud detected. "
            "Continue exercising caution."
        )

    # ==========================================
    # STAGE 8: INVESTIGATION PLAN
    # ==========================================

    report["investigation_plan"] = [
        "Review detected message evidence.",
        "Verify suspicious requests through official channels.",
        "Check suspicious URLs before opening them.",
        "Review message and URL evidence correlations.",
        "Follow the generated safety recommendations."
    ]

    # ==========================================
    # FINAL REPORT
    # ==========================================

    print(
        "DEBUG FINAL RISK SCORE:",
        report["risk_score"],
        "/ 12"
    )

    print(
        "DEBUG FINAL RISK LEVEL:",
        report["risk_level"]
    )

    print(
        "DEBUG FINAL RECOMMENDATIONS:",
        report["safety_recommendations"]
    )

    return report