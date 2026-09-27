from collections import defaultdict
from time import monotonic
from flask import abort, request

_hits = defaultdict(list)


def install_rate_limit(app, limit=30, window_seconds=60):
    @app.before_request
    def rate_limit_request():
        if not request.path.startswith("/api/"):
            return
        now = monotonic()
        key = request.remote_addr or "unknown"
        active = [stamp for stamp in _hits[key] if now - stamp < window_seconds]
        if len(active) >= limit:
            abort(429, description="Rate limit exceeded. Try again shortly.")
        active.append(now)
        _hits[key] = active
