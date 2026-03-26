from pydantic import BaseModel
from typing import Optional, List, Dict

class AnalyzeRequest(BaseModel):
    url: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None

class RuleDetail(BaseModel):
    name: str
    category: str
    points: int
    description: str

class AnalyzeResponse(BaseModel):
    score: int
    risk_level: str
    triggered_rules: List[str]
    rule_details: List[RuleDetail]
    category_scores: Dict[str, int]
    explanation: str
    recommendations: List[str]

class ScanHistoryItem(BaseModel):
    id: int
    url: Optional[str]
    sender_email: Optional[str]
    subject: Optional[str]
    body: Optional[str]
    score: int
    risk_level: str
    triggered_rules: str

    class Config:
        from_attributes = True

class DashboardSummary(BaseModel):
    total_scans: int
    high_risk: int
    medium_risk: int
    low_risk: int
    average_score: float
    most_common_rule: str

class TopRuleItem(BaseModel):
    rule: str
    count: int

class RuleLibraryItem(BaseModel):
    name: str
    category: str
    points: int
    description: str

class EvaluationMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int

class EvaluationResultItem(BaseModel):
    url: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    actual_label: str
    predicted_label: str
    score: int
    risk_level: str

class EvaluationResponse(BaseModel):
    metrics: EvaluationMetrics
    preview_results: List[EvaluationResultItem]