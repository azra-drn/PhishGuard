import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "verify", "urgent", "password", "bank", "suspended",
    "click here", "login", "confirm", "limited time", "reset"
]

CREDENTIAL_WORDS = [
    "password", "login", "sign in", "verify account", "confirm credentials",
    "username", "account verification"
]

THREAT_URGENCY_WORDS = [
    "suspended", "final reminder", "urgent action required", "within 24 hours",
    "payment failed", "expires today", "immediately", "locked", "unauthorized activity"
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]
SUSPICIOUS_TLDS = [".zip", ".click", ".work", ".country", ".gq", ".tk"]
SUSPICIOUS_SENDER_KEYWORDS = ["secure", "verify", "update", "billing", "auth", "login", "support"]

RULE_LIBRARY = [
    {
        "name": "Very long URL",
        "category": "URL-based",
        "points": 15,
        "description": "Long URLs can be used to hide suspicious paths or misleading structures."
    },
    {
        "name": "Too many subdomains",
        "category": "URL-based",
        "points": 15,
        "description": "Excessive subdomains can imitate legitimate brands or hide the true domain."
    },
    {
        "name": "IP address used instead of domain",
        "category": "URL-based",
        "points": 30,
        "description": "Phishing links may use raw IP addresses instead of recognisable domains."
    },
    {
        "name": "Shortened URL detected",
        "category": "URL-based",
        "points": 20,
        "description": "URL shorteners can hide the real destination of a link."
    },
    {
        "name": "Suspicious top-level domain",
        "category": "URL-based",
        "points": 20,
        "description": "Certain top-level domains appear more frequently in malicious campaigns."
    },
    {
        "name": "@ symbol used in URL",
        "category": "URL-based",
        "points": 10,
        "description": "The @ symbol in a URL can obscure the real destination."
    },
    {
        "name": "Non-secure HTTP link",
        "category": "URL-based",
        "points": 10,
        "description": "HTTP links provide less trust than HTTPS and can indicate risky behaviour."
    },
    {
        "name": "Suspicious sender-domain keyword",
        "category": "Sender-based",
        "points": 12,
        "description": "Sender domains containing words like secure, verify, or billing may indicate impersonation."
    },
    {
        "name": "Suspicious sender top-level domain",
        "category": "Sender-based",
        "points": 15,
        "description": "A sender address using a suspicious TLD may be less trustworthy."
    },
    {
        "name": "Invalid sender email format",
        "category": "Sender-based",
        "points": 15,
        "description": "Malformed sender addresses may indicate spoofing or low-trust content."
    },
    {
        "name": "Credential request language",
        "category": "Content-based",
        "points": 12,
        "description": "Messages asking for passwords, logins, or account verification are common phishing indicators."
    },
    {
        "name": "Threat or urgency language",
        "category": "Content-based",
        "points": 12,
        "description": "Threatening or urgent language is frequently used to pressure users into acting quickly."
    },
    {
        "name": "Suspicious keyword match",
        "category": "Content-based",
        "points": 8,
        "description": "Manipulative or security-related keywords can indicate phishing intent."
    },
]

def is_ip_address(domain: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", domain))

def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""

def extract_sender_domain(sender_email: str) -> str:
    if "@" in sender_email:
        return sender_email.split("@", 1)[1].lower()
    return ""

def add_rule(rule_details, category_scores, name, category, points, description):
    rule_details.append({
        "name": name,
        "category": category,
        "points": points,
        "description": description
    })
    category_scores[category] += points

def build_explanation(risk_level, rule_details, category_scores):
    if not rule_details:
        return "No strong phishing indicators were detected in the submitted content."

    top_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
    main_categories = [c for c, score in top_categories if score > 0][:2]
    top_rules = [r["name"] for r in rule_details[:3]]

    category_text = ", ".join(main_categories) if main_categories else "multiple"
    rule_text = ", ".join(top_rules)

    return (
        f"This submission was classified as {risk_level} risk because the analysis detected "
        f"{category_text.lower()} indicators, including {rule_text}."
    )

def build_recommendations(risk_level):
    if risk_level == "High":
        return [
            "Do not click any links or download attachments.",
            "Verify the sender through an official channel.",
            "Report the message to your IT or security team.",
            "Access the organisation’s website manually instead of using the provided link."
        ]
    if risk_level == "Medium":
        return [
            "Treat the message with caution.",
            "Verify the sender and domain independently.",
            "Avoid entering passwords or payment information until confirmed."
        ]
    return [
        "No major warning signs were found, but continue to verify unfamiliar messages.",
        "Check the sender and destination before taking action."
    ]

def analyze_input(url: str = "", sender_email: str = "", subject: str = "", body: str = ""):
    rule_details = []
    category_scores = {
        "URL-based": 0,
        "Sender-based": 0,
        "Content-based": 0
    }

    text = f"{subject} {body} {sender_email}".lower()

    # URL-based rules
    if url:
        domain = extract_domain(url)

        if len(url) > 75:
            add_rule(
                rule_details, category_scores,
                "Very long URL", "URL-based", 15,
                "Long URLs can hide suspicious paths or misleading structures."
            )

        if domain.count(".") >= 3:
            add_rule(
                rule_details, category_scores,
                "Too many subdomains", "URL-based", 15,
                "Excessive subdomains can imitate legitimate brands."
            )

        if is_ip_address(domain.split(":")[0]):
            add_rule(
                rule_details, category_scores,
                "IP address used instead of domain", "URL-based", 30,
                "Raw IP addresses can indicate suspicious or deceptive links."
            )

        if any(shortener in domain for shortener in SHORTENERS):
            add_rule(
                rule_details, category_scores,
                "Shortened URL detected", "URL-based", 20,
                "Shortened URLs can hide their final destination."
            )

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            add_rule(
                rule_details, category_scores,
                "Suspicious top-level domain", "URL-based", 20,
                "The domain uses a TLD often associated with risky campaigns."
            )

        if "@" in url:
            add_rule(
                rule_details, category_scores,
                "@ symbol used in URL", "URL-based", 10,
                "The @ symbol can disguise the true destination of a link."
            )

        if "http://" in url.lower():
            add_rule(
                rule_details, category_scores,
                "Non-secure HTTP link", "URL-based", 10,
                "The link uses HTTP instead of HTTPS."
            )

    
    if sender_email:
        sender_domain = extract_sender_domain(sender_email)

        if not re.fullmatch(r"[^@]+@[^@]+\.[^@]+", sender_email):
            add_rule(
                rule_details, category_scores,
                "Invalid sender email format", "Sender-based", 15,
                "The sender email does not match a standard address pattern."
            )
        else:
            if any(keyword in sender_domain for keyword in SUSPICIOUS_SENDER_KEYWORDS):
                add_rule(
                    rule_details, category_scores,
                    "Suspicious sender-domain keyword", "Sender-based", 12,
                    "The sender domain contains words often used in impersonation attempts."
                )

            if any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                add_rule(
                    rule_details, category_scores,
                    "Suspicious sender top-level domain", "Sender-based", 15,
                    "The sender address uses a TLD often associated with risky domains."
                )

    
    if any(word in text for word in CREDENTIAL_WORDS):
        add_rule(
            rule_details, category_scores,
            "Credential request language", "Content-based", 12,
            "The message contains language asking for login details, passwords, or account verification."
        )

    if any(word in text for word in THREAT_URGENCY_WORDS):
        add_rule(
            rule_details, category_scores,
            "Threat or urgency language", "Content-based", 12,
            "The message uses urgency or pressure tactics commonly found in phishing."
        )

    matched_keywords = [word for word in SUSPICIOUS_WORDS if word in text]
    if matched_keywords:
        add_rule(
            rule_details, category_scores,
            "Suspicious keyword match", "Content-based", 8,
            f"The message contains suspicious terms such as: {', '.join(matched_keywords[:4])}."
        )

    score = sum(rule["points"] for rule in rule_details)

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    explanation = build_explanation(risk_level, rule_details, category_scores)
    recommendations = build_recommendations(risk_level)

    return {
        "score": score,
        "risk_level": risk_level,
        "triggered_rules": [rule["name"] for rule in rule_details],
        "rule_details": rule_details,
        "category_scores": category_scores,
        "explanation": explanation,
        "recommendations": recommendations
    }