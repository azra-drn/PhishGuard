from sqlalchemy.orm import Session
from .models import ScanResult

def create_scan(db: Session, data: dict):
    scan = ScanResult(
        url=data.get("url"),
        sender_email=data.get("sender_email"),
        subject=data.get("subject"),
        body=data.get("body"),
        score=data["score"],
        risk_level=data["risk_level"],
        triggered_rules=", ".join(data["triggered_rules"])
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

def get_scans(db: Session):
    return db.query(ScanResult).order_by(ScanResult.id.desc()).all()