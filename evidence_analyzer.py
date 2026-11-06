def extract_evidence(message):
    findings = []
    cleaned_text = message.lower()

    strong_indicators = {
        "OTP request": [
            "enter your account details and otp", "enter your otp", "enter otp",
            "account details and otp", "submit your otp", "type your otp",
            "input your otp", "provide otp", "enter the otp", "share the otp",
            "send your otp", "otp"
        ],
        "Password request": [
            "enter your password", "share your password", "provide your password",
            "submit your password", "confirm your password", "password"
        ],
        "PIN request": [
            "enter your pin", "share your pin", "provide your pin",
            "submit your pin", "upi pin", "atm pin"
        ],
        "Financial Payment Request": [
            "pay a refundable training", "documentation fee", "processing fee",
            "verification fee", "pay immediately", "transfer money",
            "send money", "pay via upi", "refundable training",
            "registration fee", "security deposit"
        ]
    }

    weak_indicators = {
        "Urgency or fear": [
            "urgent alert", "urgent", "immediately", "within 2 hours",
            "will be suspended", "account blockage", "avoid account blockage",
            "account blocked", "account suspended", "act now", "expired"
        ],
        "Reward or prize claim": [
            "congratulations", "eligible for a reward", "reward",
            "won a prize", "claim your prize", "you have won",
            "free reward", "cash prize"
        ],
        "Account verification": [
            "verify your account", "confirm your account", "update your account",
            "kyc verification", "kyc has expired", "verification has expired",
            "complete your kyc", "update kyc"
        ],
        "Delivery or Parcel Verification": [
            "parcel delivery is currently on hold", "parcel delivery is on hold",
            "delivery is on hold", "verify your delivery details",
            "verify your delivery address", "address verification issue",
            "confirm your delivery address", "update your delivery address",
            "delivery details", "avoid further delays", "delivery will be cancelled"
        ]
    }

    protective_phrases = [
        "never share your otp", "do not share your otp", "don't share your otp",
        "never share your password", "do not share your password", "don't share your password",
        "never share your pin", "do not share your pin", "don't share your pin",
        "bank will never ask for your otp", "bank will never ask for your password",
        "never enter your otp", "do not enter your otp", "don't enter your otp"
    ]

    analysis_text = cleaned_text
    for warning in protective_phrases:
        analysis_text = analysis_text.replace(warning, "")

    def get_longest_matches(phrases, text):
        matched_phrases = [p for p in phrases if p in text]
        matched_phrases = [p for p in matched_phrases if not any(p != other and p in other for other in matched_phrases)]
        return matched_phrases

    for category, phrases in strong_indicators.items():
        matched_phrases = get_longest_matches(phrases, analysis_text)
        for phrase in matched_phrases:
            findings.append({
                "category": category,
                "evidence": phrase,
                "strength": "Strong",
                "explanation": f"The message contains '{phrase}', which appears to request sensitive information or fraudulent payment. This requires investigation."
            })

    for category, phrases in weak_indicators.items():
        matched_phrases = get_longest_matches(phrases, analysis_text)
        for phrase in matched_phrases:
            findings.append({
                "category": category,
                "evidence": phrase,
                "strength": "Weak",
                "explanation": f"The message contains '{phrase}'. This may be a warning sign, but does not independently establish fraud."
            })

    return findings

def generate_recommendations(findings):
    recommendations = [
        "Do not share OTPs, passwords or PINs with anyone.",
        "Verify unexpected requests through official channels.",
        "Avoid clicking links in unverified messages.",
        "Do not make payments in response to pressure.",
        "Report suspected phishing messages to the relevant organisation."
    ]
    categories = [item["category"] for item in findings]

    if "OTP request" in categories:
        recommendations.insert(0, "Never share an OTP, even with someone claiming to be from your bank.")
    if "Password request" in categories:
        recommendations.insert(0, "Do not enter your password through a link in an unsolicited message.")
    if "PIN request" in categories:
        recommendations.insert(0, "Never disclose your banking PIN or UPI PIN.")
    if "Prize or reward claim" in categories:
        recommendations.insert(0, "Verify prize claims with the official organisation before responding.")
    if "Financial Payment Request" in categories:
        recommendations.insert(0, "Never transfer funds or UPI payments for upfront employment or onboarding verification.")

    return list(dict.fromkeys(recommendations))

def correlate_evidence(message_findings, url_findings):
    correlations = []
    if message_findings and url_findings:
        correlations.append({
            "title": "Combined Message and URL Indicators",
            "explanation": "The message contains suspicious indicators, and the supplied URL also has suspicious characteristics. Together, these findings provide multiple reasons for further investigation."
        })
    if message_findings:
        categories = [item["category"] for item in message_findings]
        if "OTP request" in categories and "Urgency or fear" in categories:
            correlations.append({
                "title": "OTP Request with Urgency",
                "explanation": "The message requests an OTP while creating urgency. This combination can indicate a social engineering attempt."
            })
    if url_findings:
        correlations.append({
            "title": "Suspicious URL Characteristics",
            "explanation": "The URL contains structural indicators that should be examined before opening it."
        })
    return correlations

def classify_message(message, findings, url_findings=None):
    url_findings = url_findings or []
    findings = findings or []
    text = message.lower()

    payment_requests = ["pay immediately", "transfer money", "send money", "pay a processing fee", "pay a verification fee", "documentation fee"]
    has_payment_request = any(phrase in text for phrase in payment_requests)

    meaningful_findings = [item for item in findings if item.get("strength") == "Strong"]
    meaningful_url_findings = [item for item in url_findings if isinstance(item, dict) and item.get("strength") == "Strong"]

    if meaningful_findings or has_payment_request:
        return {
            "classification": "Likely Scam", 
            "reason": "The message contains a direct request for sensitive information or an unexpected payment."
        }
    if meaningful_url_findings:
        return {
            "classification": "Suspicious", 
            "reason": "Strong URL warning signs were identified. Further verification is recommended."
        }
    if findings or url_findings:
        return {
            "classification": "Suspicious", 
            "reason": "Potential warning signs were identified, but they do not independently prove fraud."
        }
    return {
        "classification": "No Clear Scam Evidence", 
        "reason": "No meaningful scam indicators were identified by the current evidence checks. This does not guarantee that the message is safe."
    }