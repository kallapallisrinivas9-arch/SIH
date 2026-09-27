import os
import logging
from flask import Flask
from werkzeug.security import generate_password_hash
from config import Config
from extensions import db
from models import User, Case


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    app.logger.setLevel(logging.INFO)
    os.makedirs(app.instance_path, exist_ok=True)
    db.init_app(app)
    from security import csrf_token, protect_csrf
    from services.rate_limit import install_rate_limit
    app.jinja_env.globals["csrf_token"] = csrf_token
    protect_csrf(app)
    install_rate_limit(app)

    from routes.auth import auth_bp
    from routes.main import main_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.errorhandler(400)
    def bad_request(error):
        if request_wants_json():
            return {"error": getattr(error, "description", "Bad request")}, 400
        return "Bad request", 400

    @app.errorhandler(404)
    def not_found(error):
        if request_wants_json():
            return {"error": "Resource not found"}, 404
        return "Resource not found", 404

    @app.errorhandler(429)
    def too_many_requests(error):
        return {"error": getattr(error, "description", "Too many requests")}, 429

    with app.app_context():
        db.create_all()
        seed_demo_user()
        seed_demo_cases()

    return app


def request_wants_json():
    from flask import request
    return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"


def seed_demo_user():
    user = User.query.filter_by(email="analyst@sih.local").first()
    if not user:
        db.session.add(User(email="analyst@sih.local", name="Aarav Analyst", role="analyst", password_hash=generate_password_hash("Demo@12345")))
        db.session.commit()
    elif not user.password_hash:
        user.password_hash = generate_password_hash("Demo@12345")
        db.session.commit()
    if not User.query.filter_by(email="admin@sih.local").first():
        db.session.add(User(email="admin@sih.local", name="Nisha Admin", role="admin", password_hash=generate_password_hash("Admin@12345")))
        db.session.commit()


def seed_demo_cases():
    if Case.query.count() > 0:
        return
    samples = [
        Case(subject="Urgent: Microsoft 365 password expiry", sender="security-alert@micr0soft-support.com", recipient="finance@acme.in", risk_score=92, verdict="Malicious", risk_level="critical", indicators="Lookalike domain; urgency language; credential link", source_ip="185.220.101.44", geo_country="Germany", geo_city="Frankfurt", evidence_hash="demo-hash-001"),
        Case(subject="Updated employee benefits policy", sender="hr@acme.in", recipient="all-staff@acme.in", risk_score=8, verdict="Likely Safe", risk_level="low", indicators="Trusted domain; normal language", source_ip="103.21.244.0", geo_country="India", geo_city="Mumbai", evidence_hash="demo-hash-002"),
        Case(subject="Invoice 4831 - action required", sender="billing@vendor-payments.net", recipient="accounts@acme.in", risk_score=68, verdict="Suspicious", risk_level="high", indicators="New sender; attachment lure; payment request", source_ip="45.146.164.12", geo_country="Netherlands", geo_city="Amsterdam", evidence_hash="demo-hash-003"),
    ]
    db.session.add_all(samples)
    db.session.commit()


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", use_reloader=False, host="127.0.0.1", port=int(os.getenv("PORT", "5001")))
