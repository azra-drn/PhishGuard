from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime
from .database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=True)
    sender_email = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    body = Column(Text, nullable=True)
    score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    triggered_rules = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)