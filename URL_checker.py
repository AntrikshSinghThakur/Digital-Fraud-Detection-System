from urllib.parse import urlparse
from urllib.parse import unquote
import ipaddress


def check_url(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.hostname

    findings = []

    if not domain:
        return {
            "risk": "Invalid URL",
            "findings": [],
            "evidence": [],
            "message": "The URL could not be parsed."
        }

    def add_finding(name, evidence, reason):
        findings.append({
            "finding": name,
            "evidence": evidence,
            "reason": reason
        })

    # 1. Check for IP address instead of domain
    try:
        ipaddress.ip_address(domain)
        add_finding(
            "IP address used instead of a domain",
            domain,
            "IP-based links can make the website's identity harder to recognise."
        )
    except ValueError:
        pass

    # 2. Check for unusually long URL
    if len(url) > 100:
        add_finding(
            "Unusually long URL",
            url,
            "Long URLs can hide misleading or complicated link destinations."
        )

    # 3. Check for @ symbol
    if "@" in url:
        add_finding(
            "URL contains an @ symbol",
            "@",
            "The @ symbol can be used to make a URL look misleading."
        )

    # 4. Check for URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd"
    ]

    if domain.lower() in shorteners:
        add_finding(
            "URL shortener detected",
            domain,
            "Shortened links hide the original destination until expanded."
        )

    # 5. Check for suspicious words in domain
    suspicious_words = [
        "verify",
        "login",
        "secure",
        "account",
        "update"
    ]

    matched_words = [
        word for word in suspicious_words
        if word in domain.lower()
    ]

    if matched_words:
        add_finding(
            "Suspicious words found in domain",
            ", ".join(matched_words),
            "These words are sometimes used in phishing links to imitate account or security pages."
        )

    # 6. Check for excessive subdomains
    if len(domain.split(".")) > 4:
        add_finding(
            "Many subdomains detected",
            domain,
            "An unusually complex domain structure can make the actual website identity harder to recognise."
        )
            # 8. Check for misleading brand names in subdomains

    domain_parts = domain.lower().split(".")

    known_brands = [
        "paypal",
        "google",
        "amazon",
        "microsoft",
        "facebook",
        "instagram",
        "netflix",
        "apple"
    ]
    # 10. Check for lookalike brand domains

    lookalike_patterns = {
        "paypa1": "paypal",
        "arnazon": "amazon",
        "g00gle": "google",
        "micr0soft": "microsoft",
        "faceb00k": "facebook"
    }

    for suspicious_name, original_brand in lookalike_patterns.items():
        if suspicious_name in domain.lower():
            add_finding(
                "Possible lookalike brand domain",
                domain,
                f"The domain contains '{suspicious_name}', "
                f"which resembles the brand name '{original_brand}'. "
                "This may indicate brand impersonation."
            )
            break

    if len(domain_parts) > 2:
        subdomains = domain_parts[:-2]

        for brand in known_brands:
            if brand in subdomains:
                add_finding(
                    "Possible brand impersonation in subdomain",
                    domain,
                    f"The brand name '{brand}' appears in the subdomain, "
                    "but the main domain does not establish that the "
                    "website belongs to that brand."
                )
                break
                # 9. Check for encoded URL characters

    decoded_url = unquote(url)

    if decoded_url != url:
        add_finding(
            "Encoded characters detected in URL",
            url,
            "The URL contains percent-encoded characters. "
            "Encoding can be legitimate, but may also be used "
            "to hide parts of a suspicious URL."
        )
            # 10. Check for common lookalike brand spellings

    lookalike_patterns = {
        "paypal": ["paypa1", "paypaI"],
        "google": ["g00gle", "goog1e"],
        "amazon": ["amaz0n", "amazom"],
        "microsoft": ["micros0ft", "rnicrosoft"],
        "apple": ["app1e"],
        "netflix": ["netf1ix"],
    }

    domain_lower = domain.lower()

    for brand, patterns in lookalike_patterns.items():
        for pattern in patterns:
            if pattern.lower() in domain_lower:
                add_finding(
                    "Possible lookalike brand domain",
                    domain,
                    f"The domain contains '{pattern}', which resembles "
                    f"the spelling of the brand '{brand}'. "
                    "This may indicate brand impersonation, but "
                    "does not prove the domain is malicious."
                )
                break
        else:
            continue
        break

    # 7. Check for missing HTTPS
    if parsed.scheme.lower() != "https":
        add_finding(
            "HTTPS is not being used",
            parsed.scheme,
            "The connection may not be encrypted. This alone does not prove the website is fraudulent."
        )

    if findings:
        risk = "Suspicious indicators found"
    else:
        risk = "No basic suspicious indicators found"

    return {
        "risk": risk,
        "findings": findings,
        "evidence": [item["evidence"] for item in findings],
        "message": (
            "Potential warning signs were identified."
            if findings else
            "No basic warning signs were detected by these checks."
        )
    }