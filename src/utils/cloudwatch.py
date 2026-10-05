# src/integrations/cloudwatch.py
# NOTE: boto3 is imported lazily inside publish_audit_metrics so the platform
# starts and runs fully offline without AWS installed or configured.
import os
from datetime import datetime

# Publier les résultats de l'audit en tant que métriques personnalisées dans AWS CloudWatch
def cloudwatch_enabled() -> bool:
    if os.getenv("CLOUDWATCH_ENABLED", "false").lower() not in ("1", "true", "yes"):
        return False
    return bool(os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE"))


def publish_audit_metrics(summary: dict):
    """
    Send audit results as custom metrics to AWS CloudWatch.
    summary example: {"OK": 10, "WARN": 3, "CRIT": 2, "INFO": 1}

    AWS is optional: this is a no-op unless CloudWatch is explicitly enabled and
    credentials are present, and any failure is swallowed so audits never break.
    """
    if not summary or not cloudwatch_enabled():
        return
    import boto3  # lazy import — never touched unless AWS is enabled
    client = boto3.client('cloudwatch', region_name=os.environ.get("AWS_REGION"))

    # Calculate a simple security score: higher = better
    total_findings = sum(summary.values())
    risk_score = (summary.get("CRIT", 0) * 10) + (summary.get("WARN", 0) * 3)
    security_score = max(0, 100 - risk_score)  # 100 = perfect, 0 = disaster

    # Préparer les données des métriques
    metrics = [
        {
            'MetricName': 'CriticalFindings',
            'Dimensions': [{'Name': 'Project', 'Value': 'CyberAudit'}],
            'Value': summary.get("CRIT", 0),
            'Unit': 'Count',
            'Timestamp': datetime.utcnow()
        },
        {
            'MetricName': 'WarningFindings',
            'Dimensions': [{'Name': 'Project', 'Value': 'CyberAudit'}],
            'Value': summary.get("WARN", 0),
            'Unit': 'Count',
            'Timestamp': datetime.utcnow()
        },
        {
            'MetricName': 'TotalFindings',
            'Dimensions': [{'Name': 'Project', 'Value': 'CyberAudit'}],
            'Value': total_findings,
            'Unit': 'Count',
            'Timestamp': datetime.utcnow()
        },
        {
            'MetricName': 'SecurityScore',
            'Dimensions': [{'Name': 'Project', 'Value': 'CyberAudit'}],
            'Value': security_score,
            'Unit': 'None',
            'Timestamp': datetime.utcnow()
        }
    ]

    try:
        client.put_metric_data(
            Namespace='CyberAuditTool',
            MetricData=metrics
        )
        print(f"Published CloudWatch metrics: CRIT={summary.get('CRIT')}, Score={security_score}")
    except Exception as e:
        print(f"Failed to publish metrics: {e}")