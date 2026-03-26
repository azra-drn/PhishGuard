from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from collections import Counter

from .database import SessionLocal, engine, Base
from .schemas import AnalyzeRequest
from .rules import analyze_input, RULE_LIBRARY
from .crud import create_scan, get_scans

Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def calculate_metrics(results):
    tp = tn = fp = fn = 0

    for item in results:
        actual = item["actual_label"]
        predicted = item["predicted_label"]

        if actual == "phishing" and predicted == "phishing":
            tp += 1
        elif actual == "legitimate" and predicted == "legitimate":
            tn += 1
        elif actual == "legitimate" and predicted == "phishing":
            fp += 1
        elif actual == "phishing" and predicted == "legitimate":
            fn += 1

    total = len(results) if results else 1
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

    return {
        "accuracy": round(accuracy, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1_score, 3),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
    }


def get_demo_dataset():
    return [
        {
            "url": "http://192.168.1.1/login/verify",
            "sender_email": "security@fake-bank.click",
            "subject": "Urgent: Verify your password now",
            "body": "Your account has been suspended. Click here to confirm your login immediately.",
            "label": "phishing"
        },
        {
            "url": "http://bit.ly/abc123",
            "sender_email": "alerts@paypal-secure.work",
            "subject": "Confirm your PayPal details",
            "body": "We noticed unusual activity. Verify your details within 24 hours.",
            "label": "phishing"
        },
        {
            "url": "http://update.account.amazon.zip/verify",
            "sender_email": "verification@amazon-update.zip",
            "subject": "Account verification required",
            "body": "Please verify your account information immediately to restore access.",
            "label": "phishing"
        },
        {
            "url": "http://microsoft.com@malicious-server.click/login",
            "sender_email": "noreply@microsoft-security.click",
            "subject": "Security alert: confirm your sign in",
            "body": "We blocked your access temporarily. Confirm your sign in using the secure link below.",
            "label": "phishing"
        },
        {
            "url": "https://www.amazon.co.uk/orders/12345",
            "sender_email": "orders@amazon.co.uk",
            "subject": "Your Amazon order receipt",
            "body": "Thank you for your order. You can view your receipt and order details in your Amazon account.",
            "label": "legitimate"
        },
        {
            "url": "https://www.uwe.ac.uk/students/12345",
            "sender_email": "student.services@uwe.ac.uk",
            "subject": "Student services update",
            "body": "This is an informational update about your student portal. Visit the official website if you need more details.",
            "label": "legitimate"
        },
        {
            "url": "https://www.gov.uk/service/12345",
            "sender_email": "notifications@gov.uk",
            "subject": "Government service information",
            "body": "You have a new message about your service account. Please sign in through the official GOV.UK website if needed.",
            "label": "legitimate"
        },
        {
            "url": "https://outlook.office.com/mail/12345",
            "sender_email": "no-reply@microsoft.com",
            "subject": "Microsoft account activity summary",
            "body": "Here is your regular account activity summary. Review recent sign-ins from your Microsoft dashboard.",
            "label": "legitimate"
        },
    ] * 15


@app.get("/")
def root():
    return {"message": "PhishGuard backend is running"}


@app.post("/analyze")
def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    result = analyze_input(
        url=payload.url or "",
        sender_email=payload.sender_email or "",
        subject=payload.subject or "",
        body=payload.body or ""
    )

    saved_data = {
        "url": payload.url,
        "sender_email": payload.sender_email,
        "subject": payload.subject,
        "body": payload.body,
        "score": result["score"],
        "risk_level": result["risk_level"],
        "triggered_rules": result["triggered_rules"]
    }

    create_scan(db, saved_data)
    return result


@app.get("/history")
def history(db: Session = Depends(get_db)):
    return get_scans(db)


@app.get("/dashboard-summary")
def dashboard_summary(db: Session = Depends(get_db)):
    scans = get_scans(db)

    total = len(scans)
    high = len([s for s in scans if s.risk_level == "High"])
    medium = len([s for s in scans if s.risk_level == "Medium"])
    low = len([s for s in scans if s.risk_level == "Low"])
    avg_score = round(sum(s.score for s in scans) / total, 2) if total else 0

    rule_counter = Counter()
    for scan in scans:
        if scan.triggered_rules:
            rules = [r.strip() for r in scan.triggered_rules.split(",") if r.strip()]
            rule_counter.update(rules)

    most_common_rule = rule_counter.most_common(1)[0][0] if rule_counter else "None"

    return {
        "total_scans": total,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low,
        "average_score": avg_score,
        "most_common_rule": most_common_rule
    }


@app.get("/top-rules")
def top_rules(db: Session = Depends(get_db)):
    scans = get_scans(db)
    rule_counter = Counter()

    for scan in scans:
        if scan.triggered_rules:
            rules = [r.strip() for r in scan.triggered_rules.split(",") if r.strip()]
            rule_counter.update(rules)

    return [{"rule": rule, "count": count} for rule, count in rule_counter.most_common(10)]


@app.get("/rules")
def rules():
    return RULE_LIBRARY


@app.get("/evaluate-demo")
def evaluate_demo():
    dataset = get_demo_dataset()
    results = []
    rule_counter = Counter()

    for row in dataset:
        analysis = analyze_input(
            url=row["url"],
            sender_email=row["sender_email"],
            subject=row["subject"],
            body=row["body"]
        )

        predicted_label = "phishing" if analysis["score"] >= 30 else "legitimate"

        for rule in analysis.get("triggered_rules", []):
            rule_counter[rule] += 1

        results.append({
            "url": row["url"],
            "sender_email": row["sender_email"],
            "subject": row["subject"],
            "actual_label": row["label"],
            "predicted_label": predicted_label,
            "score": analysis["score"],
            "risk_level": analysis["risk_level"]
        })

    metrics = calculate_metrics(results)

    actual_counts = {
        "phishing": len([r for r in results if r["actual_label"] == "phishing"]),
        "legitimate": len([r for r in results if r["actual_label"] == "legitimate"]),
    }

    predicted_counts = {
        "phishing": len([r for r in results if r["predicted_label"] == "phishing"]),
        "legitimate": len([r for r in results if r["predicted_label"] == "legitimate"]),
    }

    top_demo_rules = [
        {"rule": rule, "count": count}
        for rule, count in rule_counter.most_common(10)
    ]

    return {
        "error": None,
        "total_samples": len(results),
        "detected_mapping": {
            "url": "built-in demo dataset",
            "sender_email": "built-in demo dataset",
            "subject": "built-in demo dataset",
            "body": "built-in demo dataset",
            "label": "built-in demo dataset",
        },
        "raw_headers": ["url", "sender_email", "subject", "body", "label"],
        "metrics": metrics,
        "actual_counts": actual_counts,
        "predicted_counts": predicted_counts,
        "top_demo_rules": top_demo_rules,
        "preview_results": results[:20],
        "full_results": results
    }