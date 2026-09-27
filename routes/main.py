from functools import wraps
from flask import Blueprint, Response, jsonify, redirect, render_template, request, session, url_for
from uuid import uuid4
from extensions import db
from models import AnalysisResult, AuditLog, Case, Email, Investigation, IOC, ThreatIntel, User
from services.analyzer import analyze_email
from services.evidence import case_payload, evidence_hash, verify_case
from services.geo import locate_ip
from services.intelligence import analyze_message
from services.report import render_report

main_bp = Blueprint("main", __name__)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_user().role != "admin":
            return jsonify({"error": "Administrator role required."}), 403
        return view(*args, **kwargs)
    return wrapped


def current_user():
    return db.session.get(User, session.get("user_id"))


def audit(action, resource_type, resource_id=None, metadata=None):
    db.session.add(AuditLog(user_id=session.get("user_id"), action=action, resource_type=resource_type, resource_id=str(resource_id) if resource_id else None, ip_address=request.remote_addr, metadata_json=metadata or {}))


def case_map_points(cases):
    points = []
    for case in cases:
        location = locate_ip(case.source_ip)
        points.append({
            "city": case.geo_city,
            "country": case.geo_country,
            "ip": case.source_ip,
            "score": case.risk_score,
            "level": case.risk_level,
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
        })
    return points


@main_bp.route("/")
def index():
    return redirect(url_for("main.dashboard")) if session.get("user_id") else render_template("landing.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    stats = {"total": len(cases), "critical": sum(c.risk_level == "critical" for c in cases), "review": sum(c.risk_level in ("high", "medium") for c in cases), "verified": sum(verify_case(c) for c in cases)}
    map_points = case_map_points([case for case in cases if case.source_ip != "Unknown"])
    risk_series = {"critical": stats["critical"], "review": stats["review"], "safe": stats["total"] - stats["critical"] - stats["review"]}
    return render_template("dashboard_pro.html", cases=cases, stats=stats, user=current_user(), map_points=map_points, risk_series=risk_series)


@main_bp.route("/infrastructure")
@login_required
def infrastructure():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    map_points = case_map_points([case for case in cases if case.source_ip != "Unknown"])
    return render_template("infrastructure.html", user=current_user(), map_points=map_points)


@main_bp.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id):
    case = db.get_or_404(Case, case_id)
    return render_template("case_detail.html", case=case, verified=verify_case(case), user=current_user())


@main_bp.route("/cases/<int:case_id>/report")
@login_required
def case_report(case_id):
    case = db.get_or_404(Case, case_id)
    audit("report.download", "case", case.id)
    db.session.commit()
    return Response(render_report(case), mimetype="text/html", headers={"Content-Disposition": f"attachment; filename=sentinelmail-case-{case.id}.html"})


@main_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "sentinelmail", "mode": "offline-capable"})


@main_bp.route("/api/admin/audit")
@admin_required
def audit_events():
    events = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify({"events": [{"action": event.action, "resource": event.resource_type, "resource_id": event.resource_id, "ip": event.ip_address, "at": event.created_at.isoformat()} for event in events]})


@main_bp.route("/admin")
@admin_required
def admin_dashboard():
    events = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()
    return render_template("admin.html", events=events, user=current_user())


@main_bp.route("/threat-intelligence")
@login_required
def threat_intelligence():
    indicators = IOC.query.order_by(IOC.created_at.desc()).limit(100).all()
    intel = {item.indicator: item for item in ThreatIntel.query.order_by(ThreatIntel.checked_at.desc()).limit(100).all()}
    return render_template("threat_intelligence.html", indicators=indicators, intel=intel, user=current_user())


@main_bp.route("/api/analyze", methods=["POST"])
@login_required
def analyze():
    data = request.get_json(silent=True) or request.form
    subject, sender, recipient, body = [str(data.get(key, "")).strip() for key in ("subject", "sender", "recipient", "body")]
    headers, source_ip = str(data.get("headers", "")).strip(), str(data.get("source_ip", "")).strip()
    if not subject or not sender or not recipient or not body:
        return jsonify({"error": "Subject, sender, recipient, and body are required."}), 400
    location = locate_ip(source_ip)
    result = analyze_message(subject, sender, recipient, body, headers)
    case = Case(subject=subject, sender=sender, recipient=recipient, body=body, headers=headers, source_ip=location["ip"], geo_country=location["country"], geo_city=location["city"], risk_score=result["score"], verdict=result["verdict"], risk_level=result["level"], indicators="; ".join(result["indicators"]), user_id=session["user_id"])
    case.evidence_hash = evidence_hash(case_payload(case))
    db.session.add(case)
    email = Email(message_id=f"<sentinel-{uuid4()}@local>", subject=subject, sender=sender, recipient=recipient, body=body, raw_headers=headers, return_path=result["headers"]["return_path"], reply_to=result["headers"]["reply_to"], received_chain=result["headers"]["received_chain"])
    db.session.add(email)
    db.session.flush()
    db.session.add(AnalysisResult(email_id=email.id, threat_score=result["score"], verdict=result["verdict"], confidence=result["confidence"], category=result["category"], explanations=result["indicators"], mitre_techniques=result["mitre"], model_version=result["model"]))
    for kind, value in result["iocs"]:
        db.session.add(IOC(email_id=email.id, kind=kind, value=value, risk_score=result["score"]))
        db.session.add(ThreatIntel(indicator=value, kind=kind, provider="offline-fallback", verdict="unknown", confidence=15, raw_response={"note": "No external provider configured"}))
    db.session.add(Investigation(title=subject, status="open", severity=result["level"], owner_id=session["user_id"], email_id=email.id, timeline=[{"event": "captured", "at": email.created_at.isoformat(), "actor": current_user().email}, {"event": "analyzed", "at": email.created_at.isoformat(), "actor": result["model"]}]))
    audit("email.analyze", "email", email.id, {"verdict": result["verdict"], "score": result["score"]})
    db.session.commit()
    response = {
        "id": case.id,
        "email_id": email.id,
        "score": result["score"],
        "risk_score": result.get("risk_score", result["score"]),
        "verdict": result["verdict"],
        "level": result["level"],
        "category": result["category"],
        "classification": result.get("classification", result.get("verdict", "UNKNOWN").upper()),
        "confidence": result["confidence"],
        "indicators": result["indicators"],
        "evidence": result.get("evidence", result["indicators"]),
        "explanation": result.get("explanation", "; ".join(result["indicators"])),
        "mitre": result["mitre"],
        "iocs": result["iocs"],
        "headers": result["headers"],
        "location": location,
        "evidence_hash": case.evidence_hash,
        "model": result["model"],
    }
    return jsonify(response)
