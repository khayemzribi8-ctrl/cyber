"""
AWS IAM / account security collector (read-only).

Optional collector — only runs when boto3 is installed and AWS credentials are
configured. Every check is individually guarded so a missing IAM permission
skips that check instead of failing the whole audit.

Least-privilege IAM permissions used:
  sts:GetCallerIdentity, iam:ListUsers, iam:ListMFADevices,
  iam:ListAttachedUserPolicies, iam:ListAccessKeys,
  iam:GetAccountSummary, iam:GetAccountPasswordPolicy
(the AWS managed policy "SecurityAudit" or "ReadOnlyAccess" covers all of them).
"""
from typing import List, Dict, Any
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _f(check, result, severity, signature="", affected=None, rec=""):
    d = {"check": check, "result": result, "severity": severity, "recommendation": rec}
    if signature:
        d["signature"] = signature
    if affected:
        d["affected"] = affected
    return d


def run() -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

    try:
        iam = boto3.client("iam", region_name=region)
        sts = boto3.client("sts", region_name=region)

        # identify the account (also validates credentials early)
        account_id = sts.get_caller_identity().get("Account", "unknown")
        findings.append(_f("AWS account analysed", f"Account ID: {account_id}", "INFO",
                           rec="Review IAM regularly for this AWS account."))

        # enumerate users once
        users = []
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page.get("Users", []))

        # 1) Users without MFA
        try:
            no_mfa = [u["UserName"] for u in users
                      if len(iam.list_mfa_devices(UserName=u["UserName"]).get("MFADevices", [])) == 0]
            findings.append(_f("IAM users without MFA",
                               ", ".join(no_mfa) if no_mfa else "All users have MFA (or no users).",
                               "CRIT" if no_mfa else "OK", "AWS_NO_MFA", no_mfa,
                               "Enforce MFA for all human IAM users."))
        except (BotoCoreError, ClientError) as e:
            findings.append(_f("IAM MFA check skipped", str(e), "INFO", rec="Grant iam:ListMFADevices."))

        # 2) Users with AdministratorAccess
        try:
            admins = []
            for u in users:
                attached = iam.list_attached_user_policies(UserName=u["UserName"])
                if any("AdministratorAccess" in p["PolicyName"] for p in attached.get("AttachedPolicies", [])):
                    admins.append(u["UserName"])
            findings.append(_f("IAM users with AdministratorAccess",
                               ", ".join(admins) if admins else "None.",
                               "WARN" if admins else "OK", "AWS_ADMIN_USER", admins,
                               "Replace AdministratorAccess with least-privilege policies."))
        except (BotoCoreError, ClientError) as e:
            findings.append(_f("IAM admin-policy check skipped", str(e), "INFO",
                               rec="Grant iam:ListAttachedUserPolicies."))

        # 3) Long-lived access keys (> 90 days)
        try:
            old_keys = []
            now = datetime.now(timezone.utc)
            for u in users:
                for k in iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", []):
                    age = (now - k["CreateDate"]).days
                    if k.get("Status") == "Active" and age > 90:
                        old_keys.append(f"{u['UserName']} ({age}d)")
            if old_keys:
                findings.append(_f("Long-lived IAM access keys (> 90 days)",
                                   ", ".join(old_keys), "WARN", "AWS_KEY_AGE", old_keys,
                                   "Rotate access keys regularly and remove unused keys."))
            else:
                findings.append(_f("IAM access key age", "No active key older than 90 days.", "OK"))
        except (BotoCoreError, ClientError) as e:
            findings.append(_f("IAM access-key check skipped", str(e), "INFO", rec="Grant iam:ListAccessKeys."))

        # 4) Root account posture (account summary)
        try:
            summ = iam.get_account_summary().get("SummaryMap", {})
            if summ.get("AccountMFAEnabled", 0) != 1:
                findings.append(_f("Root account without MFA",
                                   "The AWS account root user has no MFA device.", "CRIT",
                                   "AWS_ROOT_MFA", rec="Enable MFA on the root user immediately."))
            else:
                findings.append(_f("Root account MFA", "Root MFA enabled.", "OK"))
            if summ.get("AccountAccessKeysPresent", 0) == 1:
                findings.append(_f("Root account has access keys",
                                   "The root user has active access keys (should be removed).", "CRIT",
                                   "AWS_ROOT_KEYS", rec="Delete root access keys; use IAM users/roles."))
        except (BotoCoreError, ClientError) as e:
            findings.append(_f("Account summary check skipped", str(e), "INFO",
                               rec="Grant iam:GetAccountSummary."))

        # 5) Account password policy
        try:
            pol = iam.get_account_password_policy().get("PasswordPolicy", {})
            weak = []
            if pol.get("MinimumPasswordLength", 0) < 14:
                weak.append(f"min length {pol.get('MinimumPasswordLength', '?')} (<14)")
            if not pol.get("RequireSymbols"):
                weak.append("no symbols")
            if not pol.get("RequireNumbers"):
                weak.append("no numbers")
            if not (pol.get("RequireUppercaseCharacters") and pol.get("RequireLowercaseCharacters")):
                weak.append("no mixed case")
            if weak:
                findings.append(_f("Weak IAM password policy", "; ".join(weak), "WARN",
                                   "AWS_PWD_POLICY", rec="Strengthen the IAM account password policy (>=14, complexity)."))
            else:
                findings.append(_f("IAM password policy", "Meets baseline complexity.", "OK"))
        except iam.exceptions.NoSuchEntityException:
            findings.append(_f("No IAM password policy set",
                               "The account has no password policy configured.", "WARN",
                               "AWS_PWD_POLICY", rec="Configure an IAM account password policy."))
        except (BotoCoreError, ClientError) as e:
            findings.append(_f("Password policy check skipped", str(e), "INFO",
                               rec="Grant iam:GetAccountPasswordPolicy."))

        # ---- broader posture checks (each self-contained) ---------------- #
        _check_s3(findings, region)
        _check_security_groups(findings, region)
        _check_cloudtrail(findings, region)
        _check_monitoring(findings, region)

    except (BotoCoreError, ClientError) as e:
        findings.append(_f("AWS IAM audit error", str(e), "CRIT",
                           rec="Check AWS credentials, region and IAM permissions "
                               "(sts:GetCallerIdentity, iam:ListUsers...)."))
    except Exception as e:
        findings.append(_f("AWS IAM audit unexpected error", repr(e), "CRIT",
                           rec="Enable debug logs and verify AWS/boto3 configuration."))

    return findings


# --------------------------------------------------------------------------- #
# Broader AWS posture checks (read-only). Each is fully guarded so a missing
# permission or service simply skips that check.
# --------------------------------------------------------------------------- #
def _check_s3(findings, region):
    try:
        s3 = boto3.client("s3", region_name=region)
        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            findings.append(_f("S3 buckets", "No S3 buckets in this account.", "OK"))
            return
        public, unencrypted = [], []
        for b in buckets:
            name = b["Name"]
            # account/bucket Block Public Access
            pab_all = False
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                pab_all = all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                   "BlockPublicPolicy", "RestrictPublicBuckets"))
            except (BotoCoreError, ClientError):
                pab_all = False
            policy_public = False
            try:
                policy_public = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
            except (BotoCoreError, ClientError):
                pass
            acl_public = False
            try:
                for g in s3.get_bucket_acl(Bucket=name).get("Grants", []):
                    uri = g.get("Grantee", {}).get("URI", "") or ""
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        acl_public = True
            except (BotoCoreError, ClientError):
                pass
            if (policy_public or acl_public) and not pab_all:
                public.append(name)
            try:
                s3.get_bucket_encryption(Bucket=name)
            except (BotoCoreError, ClientError):
                unencrypted.append(name)
        if public:
            findings.append(_f("Public S3 buckets", ", ".join(public), "CRIT",
                               "AWS_S3_PUBLIC", public,
                               "Enable S3 Block Public Access and remove public ACLs/policies."))
        else:
            findings.append(_f("S3 public access", "No publicly accessible buckets detected.", "OK"))
        if unencrypted:
            findings.append(_f("S3 buckets without default encryption", ", ".join(unencrypted),
                               "WARN", "AWS_S3_ENCRYPTION", unencrypted,
                               "Enable default encryption (SSE-S3/KMS) on these buckets."))
    except (BotoCoreError, ClientError) as e:
        findings.append(_f("S3 check skipped", str(e), "INFO", rec="Grant s3:ListAllMyBuckets and Get* on buckets."))


_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                    1433: "MSSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                    23: "Telnet", 21: "FTP"}


def _check_security_groups(findings, region):
    try:
        ec2 = boto3.client("ec2", region_name=region)
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        exposed = []
        for sg in sgs:
            gid = sg.get("GroupId", "?")
            for perm in sg.get("IpPermissions", []):
                world = (any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                         or any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])))
                if not world:
                    continue
                proto = perm.get("IpProtocol")
                if proto == "-1":
                    exposed.append(f"{gid} (ALL ports to world)")
                    continue
                fp, tp = perm.get("FromPort"), perm.get("ToPort")
                if fp is None:
                    continue
                for p, svc in _SENSITIVE_PORTS.items():
                    if fp <= p <= tp:
                        exposed.append(f"{gid} ({svc} {p} to world)")
        if exposed:
            crit = any(("SSH" in e or "RDP" in e or "ALL ports" in e) for e in exposed)
            findings.append(_f("Security groups open to the world",
                               "; ".join(sorted(set(exposed))[:20]),
                               "CRIT" if crit else "WARN", "AWS_SG_OPEN",
                               sorted(set(exposed)),
                               f"Restrict 0.0.0.0/0 ingress in region {region} to management ranges."))
        else:
            findings.append(_f("Security group exposure",
                               f"No sensitive port open to 0.0.0.0/0 in region {region}.", "OK"))
    except (BotoCoreError, ClientError) as e:
        findings.append(_f("Security group check skipped", str(e), "INFO", rec="Grant ec2:DescribeSecurityGroups."))


def _check_cloudtrail(findings, region):
    try:
        ct = boto3.client("cloudtrail", region_name=region)
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            findings.append(_f("CloudTrail not configured",
                               "No CloudTrail trail found — API activity is not logged.", "CRIT",
                               "AWS_CLOUDTRAIL", rec="Create a multi-region CloudTrail trail."))
            return
        multi = any(t.get("IsMultiRegionTrail") for t in trails)
        validation = any(t.get("LogFileValidationEnabled") for t in trails)
        logging_on = False
        for t in trails:
            try:
                if ct.get_trail_status(Name=t.get("TrailARN", t.get("Name"))).get("IsLogging"):
                    logging_on = True
            except (BotoCoreError, ClientError):
                pass
        issues = []
        if not multi:
            issues.append("no multi-region trail")
        if not logging_on:
            issues.append("logging disabled")
        if not validation:
            issues.append("log-file validation off")
        if issues:
            findings.append(_f("CloudTrail configuration weak", "; ".join(issues), "WARN",
                               "AWS_CLOUDTRAIL", rec="Enable multi-region logging and log-file validation."))
        else:
            findings.append(_f("CloudTrail", "Multi-region trail logging with validation.", "OK"))
    except (BotoCoreError, ClientError) as e:
        findings.append(_f("CloudTrail check skipped", str(e), "INFO", rec="Grant cloudtrail:DescribeTrails, GetTrailStatus."))


def _check_monitoring(findings, region):
    # GuardDuty
    try:
        gd = boto3.client("guardduty", region_name=region)
        if not gd.list_detectors().get("DetectorIds", []):
            findings.append(_f("GuardDuty not enabled",
                               f"No GuardDuty detector in region {region}.", "WARN",
                               "AWS_GUARDDUTY", rec="Enable Amazon GuardDuty threat detection."))
        else:
            findings.append(_f("GuardDuty", f"Enabled in region {region}.", "OK"))
    except (BotoCoreError, ClientError) as e:
        findings.append(_f("GuardDuty check skipped", str(e), "INFO", rec="Grant guardduty:ListDetectors."))
    # AWS Config
    try:
        cfg = boto3.client("config", region_name=region)
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not recs:
            findings.append(_f("AWS Config not enabled",
                               f"No configuration recorder in region {region}.", "WARN",
                               "AWS_CONFIG", rec="Enable AWS Config to record resource changes."))
        else:
            status = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            if not any(s.get("recording") for s in status):
                findings.append(_f("AWS Config recorder not recording",
                                   "Config recorder present but not recording.", "WARN",
                                   "AWS_CONFIG", rec="Start the AWS Config recorder."))
            else:
                findings.append(_f("AWS Config", f"Recording in region {region}.", "OK"))
    except (BotoCoreError, ClientError) as e:
        findings.append(_f("AWS Config check skipped", str(e), "INFO", rec="Grant config:DescribeConfigurationRecorders."))
