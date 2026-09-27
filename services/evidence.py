import hashlib
import json


def evidence_hash(payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def case_payload(case):
    return {"subject": case.subject, "sender": case.sender, "recipient": case.recipient, "body": case.body, "headers": case.headers, "source_ip": case.source_ip}


def verify_case(case):
    return evidence_hash(case_payload(case)) == case.evidence_hash
