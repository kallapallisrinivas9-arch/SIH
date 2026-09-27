import secrets
from flask import abort, request, session


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def protect_csrf(app):
    @app.before_request
    def validate_csrf():
        if request.method != "POST" or request.endpoint in {"auth.login", "auth.register"}:
            return
        expected = session.get("csrf_token")
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if expected and not secrets.compare_digest(expected, supplied or ""):
            abort(400, description="Invalid CSRF token")
