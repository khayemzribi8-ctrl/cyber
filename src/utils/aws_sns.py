import os
# boto3 is imported lazily so the app runs fully offline without AWS installed.


def sns_enabled() -> bool:
    return (os.environ.get("SNS_ENABLED", "false").lower() == "true"
            and bool(os.environ.get("SNS_TOPIC_ARN")))


def _region_from_arn(arn: str) -> str:
    # arn:aws:sns:<region>:<account>:<topic>  -> use the topic's own region so a
    # mismatch with AWS_REGION can't silently break publishing.
    try:
        parts = arn.split(":")
        if len(parts) >= 4 and parts[3]:
            return parts[3]
    except Exception:
        pass
    return os.environ.get("AWS_REGION", "us-east-1")


def send_sns_alert(subject: str, message: str):
    """Publish to the configured SNS topic. Returns (ok, error_message)."""
    if os.environ.get("SNS_ENABLED", "false").lower() != "true":
        return (False, "SNS_ENABLED is not 'true'.")
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not topic_arn:
        return (False, "SNS_TOPIC_ARN is not set.")
    try:
        import boto3
        kwargs = {"region_name": _region_from_arn(topic_arn)}
        # only pass explicit keys if present, else let boto3 use the default chain
        if os.environ.get("AWS_ACCESS_KEY_ID"):
            kwargs["aws_access_key_id"] = os.environ.get("AWS_ACCESS_KEY_ID")
            kwargs["aws_secret_access_key"] = os.environ.get("AWS_SECRET_ACCESS_KEY")
        client = boto3.client("sns", **kwargs)
        resp = client.publish(TopicArn=topic_arn, Subject=subject[:100], Message=message)
        return (True, resp.get("MessageId", ""))
    except Exception as e:
        print("SNS Error:", e)
        return (False, str(e))
