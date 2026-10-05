"""
Optional DynamoDB history backend.

AWS is entirely optional. This module never imports boto3 or creates a client
at import time, so the application always starts without AWS credentials. When
AWS is not configured, ``save_audit`` becomes a no-op that returns ``None`` and
the SQLite store (src/core/store.py) remains the source of truth.
"""
import os
import uuid
from datetime import datetime


def aws_enabled() -> bool:
    """AWS history is used only when explicitly enabled AND credentials exist."""
    if os.getenv("DYNAMODB_ENABLED", "false").lower() not in ("1", "true", "yes"):
        return False
    return bool(os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"))


def _table():
    import boto3  # imported lazily; only reached when AWS is enabled
    dynamodb = boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION", "us-east-1"))
    return dynamodb.Table(os.getenv("DYNAMODB_TABLE", "CyberAuditHistory"))


def save_audit(
    ldap=None, ssh=None, ad=None, privilege=None, token=None, acl=None,
    potato=None, aws_iam=None, summary=None, modules_used=None,
    ai_recommendations=None, fix_logs=None,
):
    """Save an audit to DynamoDB when enabled; otherwise a safe no-op."""
    if not aws_enabled():
        return None
    try:
        audit_id = str(uuid.uuid4())
        item = {
            "audit_id": audit_id,
            "timestamp": int(datetime.utcnow().timestamp()),
            "summary": summary or {},
            "ldap": ldap or [], "ssh": ssh or [], "ad": ad or [],
            "privilege": privilege or [], "token": token or [], "acl": acl or [],
            "potato": potato or [], "aws_iam": aws_iam or [],
            "modules_used": modules_used or [],
            "ai_recommendations": ai_recommendations or "",
            "fix_logs": fix_logs or [],
        }
        _table().put_item(Item=item)
        return audit_id
    except Exception as e:  # AWS problems must never break an audit
        print(f"[dynamodb] save skipped: {e}")
        return None
