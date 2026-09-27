from html import escape
from datetime import datetime, timezone


def render_report(case, analysis=None, headers=None, iocs=None):
    analysis = analysis or {}
    headers = headers or {}
    iocs = iocs or []
    indicators = analysis.get("indicators", case.indicators.split("; "))
    rows = "".join(f"<tr><td>{escape(kind)}</td><td>{escape(value)}</td></tr>" for kind, value in iocs)
    reasons = "".join(f"<li>{escape(item)}</li>" for item in indicators)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>SentinelMail Forensic Report #{case.id}</title><style>body{{font:14px Arial;color:#182a35;max-width:900px;margin:40px auto;line-height:1.5}}h1{{border-bottom:3px solid #1677ff;padding-bottom:14px}}.meta{{background:#f3f7f8;padding:18px}}.critical{{color:#c43f4b}}table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;border:1px solid #dce5e8;text-align:left}}small{{color:#61767d}}</style></head><body><h1>SentinelMail Forensic Report</h1><small>Generated {generated} | Report ID CASE-{case.id:04d}</small><div class='meta'><h2 class='{escape(case.risk_level)}'>{escape(case.verdict)} / {case.risk_score}/100</h2><p><b>Subject:</b> {escape(case.subject)}<br><b>Sender:</b> {escape(case.sender)}<br><b>Recipient:</b> {escape(case.recipient)}<br><b>Origin:</b> {escape(case.geo_city)}, {escape(case.geo_country)} ({escape(case.source_ip)})</p></div><h2>Executive finding</h2><ul>{reasons}</ul><h2>Header authentication</h2><pre>{escape(str(headers))}</pre><h2>Indicators of compromise</h2><table><tr><th>Type</th><th>Value</th></tr>{rows}</table><h2>Evidence integrity</h2><p>SHA-256 anchor: <code>{escape(case.evidence_hash)}</code></p><p><small>This report is an analyst aid. Geolocation and reputation results are provider-dependent and should be independently verified.</small></p></body></html>"""
