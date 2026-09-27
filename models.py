from datetime import datetime, timezone
from extensions import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="analyst")
    password_hash = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    cases = db.relationship("Case", backref="analyst", lazy=True)


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(500), nullable=False)
    sender = db.Column(db.String(255), nullable=False)
    recipient = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    headers = db.Column(db.Text, nullable=False, default="")
    source_ip = db.Column(db.String(64), nullable=False, default="Unknown")
    geo_country = db.Column(db.String(120), nullable=False, default="Unknown")
    geo_city = db.Column(db.String(120), nullable=False, default="Unknown")
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    verdict = db.Column(db.String(40), nullable=False, default="Pending")
    risk_level = db.Column(db.String(30), nullable=False, default="low")
    indicators = db.Column(db.Text, nullable=False, default="")
    evidence_hash = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(255), unique=True, nullable=False)
    subject = db.Column(db.String(500), nullable=False)
    sender = db.Column(db.String(255), nullable=False)
    recipient = db.Column(db.String(255), nullable=False)
    return_path = db.Column(db.String(255), default="")
    reply_to = db.Column(db.String(255), default="")
    body = db.Column(db.Text, nullable=False, default="")
    raw_headers = db.Column(db.Text, nullable=False, default="")
    received_chain = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    analysis = db.relationship("AnalysisResult", backref="email", uselist=False, cascade="all, delete-orphan")
    iocs = db.relationship("IOC", backref="email", lazy=True, cascade="all, delete-orphan")


class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("email.id"), nullable=False, unique=True)
    threat_score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(40), nullable=False)
    confidence = db.Column(db.Integer, nullable=False, default=0)
    category = db.Column(db.String(40), nullable=False, default="unknown")
    explanations = db.Column(db.JSON, default=list)
    mitre_techniques = db.Column(db.JSON, default=list)
    model_version = db.Column(db.String(80), nullable=False, default="hybrid-rules-v1")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("email.id"), nullable=False)
    kind = db.Column(db.String(30), nullable=False)
    value = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    source = db.Column(db.String(80), default="local-analyzer", nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class Investigation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="open")
    severity = db.Column(db.String(30), nullable=False, default="medium")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    email_id = db.Column(db.Integer, db.ForeignKey("email.id"), nullable=True)
    timeline = db.Column(db.JSON, default=list)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class ThreatIntel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(500), nullable=False, index=True)
    kind = db.Column(db.String(30), nullable=False)
    provider = db.Column(db.String(80), nullable=False, default="offline-fallback")
    verdict = db.Column(db.String(40), nullable=False, default="unknown")
    confidence = db.Column(db.Integer, nullable=False, default=0)
    raw_response = db.Column(db.JSON, default=dict)
    checked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(80), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    metadata_json = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
