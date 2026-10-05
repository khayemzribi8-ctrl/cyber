"""
Module & navigation registry.

This is the single source of truth for:
  * the sidebar navigation groups,
  * the catalogue of security modules (the "30+ modules" of the platform),
  * how a raw finding is classified into a module,
  * which modules currently have a real collector wired in (``implemented``)
    versus those whose collector is not yet built (``planned``).

Nothing here fabricates results. A ``planned`` module renders an honest
"collector not yet implemented" state in the UI instead of inventing findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# --------------------------------------------------------------------------- #
# Sidebar navigation
# --------------------------------------------------------------------------- #
# (label, endpoint, icon-key, kind)  kind: "page" | "group-header"
NAV: List[Dict[str, str]] = [
    {"label": "Dashboard", "endpoint": "ui.dashboard", "icon": "grid"},
    {"label": "Security Assessment", "endpoint": "ui.assessment", "icon": "shield"},
    {"label": "Assets", "endpoint": "ui.assets", "icon": "server"},
    {"section": "Active Directory & Identity"},
    {"label": "Active Directory", "endpoint": "ui.module", "arg": "active_directory_audit", "icon": "sitemap"},
    {"label": "Identity Security", "endpoint": "ui.module", "arg": "user_account_security", "icon": "id"},
    {"label": "LDAP", "endpoint": "ui.module", "arg": "ldap_security_audit", "icon": "directory"},
    {"label": "Kerberos", "endpoint": "ui.module", "arg": "kerberos_security_audit", "icon": "ticket"},
    {"label": "SMB", "endpoint": "ui.module", "arg": "smb_security_audit", "icon": "share"},
    {"label": "Windows Security", "endpoint": "ui.module", "arg": "windows_security_audit", "icon": "windows"},
    {"label": "RDP", "endpoint": "ui.module", "arg": "rdp_security_audit", "icon": "desktop"},
    {"label": "WinRM", "endpoint": "ui.module", "arg": "winrm_security_audit", "icon": "terminal"},
    {"label": "ADCS", "endpoint": "ui.module", "arg": "adcs_security_audit", "icon": "certificate"},
    {"section": "Infrastructure"},
    {"label": "Linux / SSH", "endpoint": "ui.module", "arg": "ssh_security_audit", "icon": "linux"},
    {"label": "Network Exposure", "endpoint": "ui.network", "icon": "network"},
    {"label": "Vulnerability Management", "endpoint": "ui.module", "arg": "vulnerability_management", "icon": "bug"},
    {"label": "Attack Surface", "endpoint": "ui.attack_surface", "icon": "target"},
    {"section": "Analysis"},
    {"label": "Attack Paths", "endpoint": "ui.attack_paths", "icon": "route"},
    {"label": "MITRE ATT&CK", "endpoint": "ui.mitre", "icon": "matrix"},
    {"label": "Security Findings", "endpoint": "ui.findings", "icon": "flag"},
    {"label": "Evidence", "endpoint": "ui.evidence", "icon": "document"},
    {"label": "Remediation", "endpoint": "ui.remediation", "icon": "wrench"},
    {"label": "Compliance", "endpoint": "ui.compliance", "icon": "check"},
    {"section": "Operations"},
    {"label": "Reports", "endpoint": "ui.reports", "icon": "report"},
    {"label": "Audit History", "endpoint": "ui.history", "icon": "history"},
    {"label": "Automation", "endpoint": "ui.automation", "icon": "gear"},
    {"label": "AWS Security", "endpoint": "ui.module", "arg": "aws_iam_audit", "icon": "cloud"},
    {"label": "Settings", "endpoint": "ui.settings", "icon": "settings"},
]


# --------------------------------------------------------------------------- #
# Module definitions
# --------------------------------------------------------------------------- #
@dataclass
class Module:
    key: str
    name: str
    group: str                     # nav / category grouping
    description: str
    collector: Optional[str] = None   # collector key that feeds this module
    checks: List[str] = field(default_factory=list)
    match: List[str] = field(default_factory=list)  # keywords -> classify findings
    mitre: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "implemented" if self.collector else "planned"


# group order for the "Security Assessment" catalogue view
GROUPS = [
    "Active Directory", "Identity Security", "LDAP", "Kerberos", "SMB",
    "Windows Security", "RDP", "WinRM", "ADCS", "Linux", "Network",
    "Vulnerability Management", "Cloud", "Security Operations",
]


def _m(*a, **k) -> Module:
    return Module(*a, **k)


MODULES: List[Module] = [
    # ---- WINDOWS / ACTIVE DIRECTORY ------------------------------------- #
    _m("windows_security_audit", "Windows Security Audit", "Windows Security",
       "Baseline Windows hardening via WinRM (spooler, LSA/PPL) and privileges via SSH.",
       collector="windows_winrm",
       checks=["Impersonation privileges", "Print Spooler state", "Dangerous local privileges"],
       match=["windows security", "seimpersonate", "seassignprimarytoken", "spooler", "whoami"],
       mitre=["T1134.001", "T1068", "T1543.003"]),
    _m("active_directory_audit", "Active Directory Audit", "Active Directory",
       "Domain-wide AD hygiene: privileged groups, stale/expiring accounts, pre-auth.",
       collector="ad",
       checks=["Privileged group membership", "Disabled accounts", "Password never expires",
               "Accounts without expiration", "Kerberos pre-auth disabled", "Stale accounts"],
       match=["domain admins", "enterprise admins", "schema admins", "membership",
              "pre-auth", "preauth", "comptes", "expiration", "inactif", "backup operators",
              "account operators", "administrators membership"],
       mitre=["T1078.002", "T1558.004", "T1069.002"]),
    _m("domain_controller_security", "Domain Controller Security", "Active Directory",
       "DC-specific hardening, machine account quota, krbtgt age, functional level.",
       collector="policy",
       checks=["DC service exposure", "SMB/LDAP signing on DC", "Spooler on DC"],
       match=["domain controller", "dc0", "dc security"],
       mitre=["T1207", "T1557.001"]),
    _m("user_account_security", "User Account Security", "Identity Security",
       "User account state, control flags and hygiene.",
       collector="ldap",
       checks=["Total accounts", "Disabled accounts", "Password never expires"],
       match=["user account", "disabled account", "comptes désactivés", "password never expires",
              "n'expire jamais", "total user"],
       mitre=["T1078.002"]),
    _m("privileged_account_audit", "Privileged Account Audit", "Identity Security",
       "Enumerates privileged principals and AdminSDHolder-protected accounts.",
       collector="privilege",
       checks=["Domain Admins members", "adminCount=1 accounts", "Local Administrators"],
       match=["privilege", "adminsdholder", "admincount", "protégés"],
       mitre=["T1078.002"]),
    _m("group_membership_audit", "Group Membership Audit", "Identity Security",
       "Reviews sensitive group memberships against least privilege.",
       collector="ad",
       checks=["Sensitive group membership counts"],
       match=["group membership", "membership"],
       mitre=["T1069.002"]),
    _m("password_policy_audit", "Password Policy Audit", "Identity Security",
       "Domain password policy: length, complexity, history, age.",
       collector="policy",
       checks=["Min length", "Complexity", "Max age", "History"],
       match=["password policy", "minimum password", "complexity"],
       mitre=["T1110.003", "T1201"]),
    _m("account_lockout_audit", "Account Lockout Audit", "Identity Security",
       "Account lockout threshold / duration / reset window.",
       collector="policy",
       checks=["Lockout threshold", "Lockout duration"],
       match=["lockout", "account lockout"],
       mitre=["T1110"]),
    _m("kerberos_security_audit", "Kerberos Security Audit", "Kerberos",
       "Kerberoastable SPNs, AS-REP roasting exposure and delegation.",
       collector="kerberos",
       checks=["Kerberoastable accounts (SPN)", "Unconstrained delegation",
               "Constrained delegation / RBCD"],
       match=["kerberoast", "spn", "delegation", "délégation", "unconstrained", "rbcd", "token"],
       mitre=["T1558.003", "T1550.003"]),
    _m("ldap_security_audit", "LDAP Security Audit", "LDAP",
       "LDAP directory exposure, account/group enumeration and hygiene.",
       collector="ldap",
       checks=["User enumeration", "Group counts", "Password expiration policy"],
       match=["ldap", "total groups", "objectclass"],
       mitre=["T1087.002"]),
    _m("ldap_signing_audit", "LDAP Signing Audit", "LDAP",
       "Verifies LDAP signing and channel binding enforcement.",
       checks=["LDAP signing required", "Channel binding"],
       match=["ldap signing", "channel binding"],
       mitre=["T1557.001"]),
    _m("ntlm_security_audit", "NTLM Security Audit", "Windows Security",
       "NTLM usage / restriction and relay exposure.",
       checks=["NTLMv1 allowed", "LM hash storage", "NTLM restriction"],
       match=["ntlm", "lm hash"],
       mitre=["T1550.002"]),
    _m("smb_security_audit", "SMB Security Audit", "SMB",
       "SMB configuration hygiene.",
       checks=["SMB signing", "Guest access", "Null sessions"],
       match=["smb security", "smb signing", "null session"],
       mitre=["T1021.002", "T1557.001"]),
    _m("smb_signing_audit", "SMB Signing Audit", "SMB",
       "Whether SMB signing is required (anti-relay).",
       collector="windows_winrm",
       checks=["Server signing required", "Client signing required"],
       match=["smb signing"],
       mitre=["T1557.001"]),
    _m("smbv1_detection", "SMBv1 Detection", "SMB",
       "Detects the legacy SMBv1 protocol.",
       collector="windows_winrm",
       checks=["SMBv1 feature enabled"],
       match=["smbv1", "smb1", "smb v1"],
       mitre=["T1210", "T1021.002"]),
    _m("rdp_security_audit", "RDP Security Audit", "RDP",
       "RDP exposure, NLA and encryption level.",
       collector="network",
       checks=["RDP reachable (3389)", "NLA enforced", "Encryption level"],
       match=["rdp", "remote desktop", "3389"],
       mitre=["T1021.001"]),
    _m("winrm_security_audit", "WinRM Security Audit", "WinRM",
       "WinRM exposure and authentication configuration.",
       collector="network",
       checks=["WinRM reachable (5985/5986)", "Basic auth", "HTTPS listener"],
       match=["winrm", "5985", "5986", "wsman"],
       mitre=["T1021.006"]),
    _m("windows_firewall_audit", "Windows Firewall Audit", "Windows Security",
       "Host firewall profile state and rules.",
       collector="windows_winrm",
       checks=["Domain/Private/Public profile enabled"],
       match=["firewall"],
       mitre=["T1562.004"]),
    _m("windows_services_audit", "Windows Services Audit", "Windows Security",
       "Risky/unnecessary services and weak service configuration.",
       checks=["Unquoted service paths", "Risky services running"],
       match=["service", "unquoted"],
       mitre=["T1543.003"]),
    _m("windows_security_policy_audit", "Windows Security Policy Audit", "Windows Security",
       "Local security policy, Guest account, user rights.",
       collector="windows_winrm",
       checks=["User rights assignment", "Security options"],
       match=["security policy", "user rights", "secpol"],
       mitre=["T1078"]),
    _m("windows_event_logging_audit", "Windows Event Logging Audit", "Windows Security",
       "Audit policy and event log configuration.",
       collector="windows_winrm",
       checks=["Advanced audit policy", "Log sizes", "Command-line auditing"],
       match=["event log", "auditing", "audit policy", "logging"],
       mitre=["T1070.001"]),
    _m("powershell_security_audit", "PowerShell Security Audit", "Windows Security",
       "PowerShell hardening: v2 presence, logging, execution policy.",
       collector="windows_winrm",
       checks=["PowerShell v2 present", "Script block logging", "Execution policy"],
       match=["powershell", "execution policy", "scriptblock"],
       mitre=["T1059.001"]),
    _m("defender_controls_audit", "Windows Defender / Security Controls Audit", "Windows Security",
       "Endpoint protection state.",
       collector="windows_winrm",
       checks=["Real-time protection", "Tamper protection", "AV signatures"],
       match=["defender", "antivirus", "real-time protection", "tamper"],
       mitre=["T1562.001"]),
    _m("local_administrator_audit", "Local Administrator Audit", "Windows Security",
       "Local administrator group membership and LAPS usage.",
       collector="windows_winrm",
       checks=["Local admins", "LAPS deployed"],
       match=["local administrator", "local admin", "laps"],
       mitre=["T1078.001"]),
    _m("scheduled_tasks_audit", "Scheduled Tasks Security Audit", "Windows Security",
       "Scheduled tasks running as privileged principals.",
       checks=["Tasks as SYSTEM", "Writable task binaries"],
       match=["scheduled task"],
       mitre=["T1053.005"]),
    # ---- ADCS / PKI ------------------------------------------------------ #
    _m("adcs_security_audit", "ADCS Security Audit", "ADCS",
       "Active Directory Certificate Services misconfiguration (ESC1-ESC3 via LDAP).",
       collector="adcs",
       checks=["Vulnerable templates", "EDITF_ATTRIBUTESUBJECTALTNAME2", "Web enrollment / NTLM relay"],
       match=["adcs", "certificate services", "esc1", "esc2", "esc4", "esc8", "pkinit"],
       mitre=["T1649"]),
    _m("certificate_authority_audit", "Certificate Authority Audit", "ADCS",
       "CA inventory and configuration.",
       collector="adcs",
       checks=["CA flags", "Role separation", "Manager approval"],
       match=["certificate authority", "ca flags"],
       mitre=["T1649"]),
    _m("certificate_template_audit", "Certificate Template Audit", "ADCS",
       "Enrollable templates that allow SAN / client-auth abuse.",
       collector="adcs",
       checks=["Enrollee supplies subject", "Client authentication EKU", "Enroll rights"],
       match=["certificate template", "template"],
       mitre=["T1649"]),
    _m("certificate_permission_audit", "Certificate Permission Audit", "ADCS",
       "Dangerous enrollment / write permissions on templates & CA.",
       checks=["Enroll for low-priv principals", "Write on template"],
       match=["certificate permission", "enroll rights"],
       mitre=["T1649"]),
    _m("certificate_expiration_audit", "Certificate Expiration Audit", "ADCS",
       "Certificates nearing or past expiry.",
       checks=["Expiring certificates", "Expired certificates"],
       match=["certificate expiration", "certificate expiry", "expiring certificate"],
       mitre=[]),
    # ---- LINUX ----------------------------------------------------------- #
    _m("linux_security_audit", "Linux Security Audit", "Linux",
       "Baseline Linux host hardening.",
       checks=["Kernel hardening", "World-writable files", "SUID review"],
       match=["linux security", "suid", "world-writable"],
       mitre=["T1068"]),
    _m("ssh_security_audit", "SSH Security Audit", "Linux",
       "SSH daemon configuration hardening.",
       collector="ssh",
       checks=["PermitRootLogin", "PasswordAuthentication", "Protocol version", "Login banner"],
       match=["ssh", "permitrootlogin", "passwordauthentication", "sshd", "banner", "x11"],
       mitre=["T1021.004"]),
    _m("sudo_security_audit", "Sudo Security Audit", "Linux",
       "Sudoers policy weaknesses.",
       checks=["NOPASSWD rules", "Wildcards", "Dangerous binaries"],
       match=["sudo", "nopasswd", "sudoers"],
       mitre=["T1548"]),
    _m("linux_user_security", "Linux User Security", "Linux",
       "Linux account hygiene.",
       checks=["Empty passwords", "UID 0 accounts", "Stale accounts"],
       match=["linux user", "uid 0", "empty password"],
       mitre=["T1078"]),
    _m("linux_firewall_audit", "Linux Firewall Audit", "Linux",
       "iptables/nftables/ufw posture.",
       checks=["Default policy", "Open inbound"],
       match=["iptables", "nftables", "ufw", "linux firewall"],
       mitre=["T1562.004"]),
    _m("linux_service_audit", "Linux Service Audit", "Linux",
       "Exposed / unnecessary Linux services.",
       checks=["Listening services", "Legacy daemons"],
       match=["linux service", "systemd"],
       mitre=["T1543"]),
    # ---- NETWORK --------------------------------------------------------- #
    _m("network_exposure_scanner", "Network Exposure Scanner", "Network",
       "TCP connect scan of a target to enumerate reachable services.",
       collector="network",
       checks=["Port reachability", "Service identification", "Remote admin exposure"],
       match=["network exposure", "open port", "exposed service", "tcp/"],
       mitre=["T1046", "T1595.002"]),
    _m("open_port_audit", "Open Port Audit", "Network",
       "Enumerates open TCP ports on a target.",
       collector="network",
       checks=["Open TCP ports"],
       match=["open port", "port "],
       mitre=["T1046"]),
    _m("network_service_discovery", "Network Service Discovery", "Network",
       "Maps ports to well-known services.",
       collector="network",
       checks=["Service mapping"],
       match=["service discovery"],
       mitre=["T1046"]),
    _m("remote_admin_exposure", "Remote Administration Exposure", "Network",
       "Highlights exposed remote-admin services (RDP/WinRM/SSH/SMB).",
       collector="network",
       checks=["RDP/WinRM/SSH/SMB reachability"],
       match=["remote administration", "remote admin"],
       mitre=["T1021"]),
    _m("rdp_exposure", "RDP Exposure", "Network", "Internet/segment RDP exposure.",
       collector="network", checks=["3389 reachable"], match=["rdp exposure"], mitre=["T1021.001"]),
    _m("smb_exposure", "SMB Exposure", "Network", "SMB reachability.",
       collector="network", checks=["445 reachable"], match=["smb exposure"], mitre=["T1021.002"]),
    _m("winrm_exposure", "WinRM Exposure", "Network", "WinRM reachability.",
       collector="network", checks=["5985/5986 reachable"], match=["winrm exposure"], mitre=["T1021.006"]),
    _m("ssh_exposure", "SSH Exposure", "Network", "SSH reachability.",
       collector="network", checks=["22 reachable"], match=["ssh exposure"], mitre=["T1021.004"]),
    # ---- VULNERABILITY MANAGEMENT --------------------------------------- #
    _m("vulnerability_management", "Vulnerability Management", "Vulnerability Management",
       "Central register of configuration & known vulnerabilities (krbtgt age, quota, ...).",
       collector="policy",
       checks=["Config vulnerabilities", "Known CVE exposure"],
       match=["vulnerability", "cve-", "vulnerable"],
       mitre=["T1190"]),
    _m("config_vulnerability_detection", "Configuration Vulnerability Detection", "Vulnerability Management",
       "Detects insecure configuration primitives.",
       checks=["Insecure defaults", "Weak protocols"],
       match=["misconfiguration", "insecure default"],
       mitre=["T1190"]),
    _m("security_misconfiguration_detection", "Security Misconfiguration Detection", "Vulnerability Management",
       "Cross-module misconfiguration correlation.",
       checks=["Aggregated misconfigurations"],
       match=["misconfiguration"],
       mitre=["T1190"]),
    _m("risk_assessment", "Risk Assessment", "Vulnerability Management",
       "Risk scoring and prioritisation of findings.",
       checks=["Risk scoring", "Prioritisation"],
       match=["risk assessment"],
       mitre=[]),
    _m("attack_surface_management", "Attack Surface Management", "Vulnerability Management",
       "Aggregated external/internal attack surface.",
       collector="network",
       checks=["Exposed services", "Reachable admin planes"],
       match=["attack surface"],
       mitre=["T1046"]),
    _m("asset_discovery", "Asset Discovery", "Vulnerability Management",
       "Discovers assets from audit inputs and scans.",
       collector="network",
       checks=["Host discovery"],
       match=["asset discovery"],
       mitre=["T1018"]),
    # ---- CLOUD ----------------------------------------------------------- #
    _m("aws_iam_audit", "AWS Security", "Cloud",
       "AWS account & IAM security overview (aggregates all AWS checks): MFA, admin access, access keys, root posture, password policy.",
       collector="aws",
       checks=["Users without MFA", "AdministratorAccess users", "Access key age", "Root MFA / keys", "Password policy"],
       match=["aws", "iam", "mfa", "administratoraccess"],
       mitre=["T1078.004"]),
    _m("aws_account_security", "AWS Account Security", "Cloud",
       "Account-level baseline (root usage, account MFA).",
       collector="aws", checks=["Root usage", "Account MFA"], match=["aws account", "root account"],
       mitre=["T1078.004"]),
    _m("aws_access_key_audit", "AWS Access Key Audit", "Cloud",
       "Long-lived / unused IAM access keys.",
       collector="aws",
       checks=["Key age", "Unused keys"], match=["access key"], mitre=["T1552.001"]),
    _m("aws_mfa_audit", "AWS MFA Audit", "Cloud", "MFA coverage for IAM users.",
       collector="aws", checks=["MFA per user"], match=["mfa"], mitre=["T1078.004"]),
    _m("aws_iam_policy_audit", "AWS IAM Policy Audit", "Cloud",
       "Over-permissive IAM policies.",
       collector="aws",
       checks=["Wildcard actions", "Inline admin policies"], match=["iam policy", "wildcard"],
       mitre=["T1078.004"]),
    _m("aws_cloudtrail_audit", "AWS CloudTrail Audit", "Cloud",
       "CloudTrail logging coverage.",
       collector="aws",
       checks=["Trail enabled", "Multi-region", "Log validation"], match=["cloudtrail"],
       mitre=["T1562.001"]),
    _m("aws_security_monitoring", "AWS Security Monitoring", "Cloud",
       "GuardDuty / Config / monitoring posture.",
       collector="aws",
       checks=["GuardDuty enabled", "AWS Config recorder"], match=["guardduty", "aws config"],
       mitre=["T1562.001"]),
    _m("aws_s3_audit", "AWS S3 Bucket Security", "Cloud",
       "Public buckets, Block Public Access and default encryption.",
       collector="aws",
       checks=["Public buckets", "Block Public Access", "Default encryption"],
       match=["s3 bucket", "s3 public", "bucket"], mitre=["T1530"]),
    _m("aws_security_group_audit", "AWS Security Groups", "Cloud",
       "Security groups exposing sensitive ports to 0.0.0.0/0.",
       collector="aws",
       checks=["Ingress 0.0.0.0/0 on SSH/RDP/DB ports", "Allow-all rules"],
       match=["security group", "0.0.0.0/0", "open to the world"], mitre=["T1046", "T1190"]),
    # ---- SECURITY OPERATIONS (surfaced as dedicated pages) --------------- #
    _m("security_exceptions", "Security Exceptions", "Security Operations",
       "Accepted-risk register with owner and expiry.",
       checks=["Accepted risks", "Expiry tracking"], match=["exception"], mitre=[]),
    _m("collector_diagnostics", "Collector Diagnostics", "Security Operations",
       "Operational status of collectors: targets that could not be reached or "
       "integrations that are not configured. These are NOT security findings and "
       "do not affect the security score or ATT&CK coverage.",
       collector="engine",
       checks=["Collector reachability", "Integration configuration"],
       match=[], mitre=[]),
]


# --------------------------------------------------------------------------- #
# Indices & helpers
# --------------------------------------------------------------------------- #
MODULE_BY_KEY: Dict[str, Module] = {m.key: m for m in MODULES}


def get_module(key: str) -> Optional[Module]:
    return MODULE_BY_KEY.get(key)


def modules_by_group() -> Dict[str, List[Module]]:
    out: Dict[str, List[Module]] = {g: [] for g in GROUPS}
    for m in MODULES:
        out.setdefault(m.group, []).append(m)
    return out


# canonical signatures that map deterministically to a module (skip keyword logic)
SIGNATURE_TO_MODULE = {
    "NET_OPEN_PORTS": "open_port_audit",
    "NET_RDP_EXPOSED": "rdp_security_audit",
    "NET_SMB_EXPOSED": "smb_security_audit",
    "NET_WINRM_EXPOSED": "winrm_security_audit",
    "NET_SSH_EXPOSED": "ssh_security_audit",
    "NET_LDAP_EXPOSED": "ldap_security_audit",
    # ADCS collector
    "ADCS_ESC1": "adcs_security_audit",
    "ADCS_ESC2": "adcs_security_audit",
    "ADCS_ESC3": "adcs_security_audit",
    "ADCS_PRESENCE": "adcs_security_audit",
    "ADCS_TEMPLATES": "certificate_template_audit",
    "ADCS_CA_INVENTORY": "certificate_authority_audit",
    # policy / DC collector
    "PWD_POLICY_LENGTH": "password_policy_audit",
    "PWD_POLICY_COMPLEXITY": "password_policy_audit",
    "PWD_POLICY_MAXAGE": "password_policy_audit",
    "PWD_POLICY_HISTORY": "password_policy_audit",
    "ACCOUNT_LOCKOUT": "account_lockout_audit",
    "AD_MACHINE_ACCOUNT_QUOTA": "domain_controller_security",
    "AD_FUNCTIONAL_LEVEL": "domain_controller_security",
    "AD_KRBTGT_STALE": "vulnerability_management",
    # WinRM host collector
    "WIN_FIREWALL": "windows_firewall_audit",
    "WIN_DEFENDER": "defender_controls_audit",
    "SMBV1_ENABLED": "smbv1_detection",
    "SMB_SIGNING": "smb_signing_audit",
    "WIN_SPOOLER": "windows_security_audit",
    "PSV2": "powershell_security_audit",
    "RDP_NLA": "rdp_security_audit",
    "LOCAL_ADMINS": "local_administrator_audit",
    "GUEST_ENABLED": "windows_security_policy_audit",
    "CMDLINE_AUDIT": "windows_event_logging_audit",
    "LSA_PPL": "windows_security_audit",
    # AWS collector
    "AWS_NO_MFA": "aws_mfa_audit",
    "AWS_ADMIN_USER": "aws_iam_policy_audit",
    "AWS_KEY_AGE": "aws_access_key_audit",
    "AWS_ROOT_MFA": "aws_account_security",
    "AWS_ROOT_KEYS": "aws_account_security",
    "AWS_PWD_POLICY": "aws_account_security",
    "AWS_S3_PUBLIC": "aws_s3_audit",
    "AWS_S3_ENCRYPTION": "aws_s3_audit",
    "AWS_SG_OPEN": "aws_security_group_audit",
    "AWS_CLOUDTRAIL": "aws_cloudtrail_audit",
    "AWS_GUARDDUTY": "aws_security_monitoring",
    "AWS_CONFIG": "aws_security_monitoring",
}


def classify(finding_module: str, haystack: str, signature: str = "") -> str:
    """Pick the best module key for a finding.

    ``finding_module`` is the collector-supplied hint; ``haystack`` is
    lowercased title+signature+category text; ``signature`` is the canonical
    rule key. Returns a module key.
    """
    # 0) deterministic canonical signature
    if signature and signature.upper() in SIGNATURE_TO_MODULE:
        return SIGNATURE_TO_MODULE[signature.upper()]
    hay = (haystack or "").lower()
    # 1) direct key hit
    if finding_module in MODULE_BY_KEY:
        return finding_module
    # 2) keyword match, longest keyword wins (most specific)
    best_key, best_len = "", 0
    for m in MODULES:
        for kw in m.match:
            if kw and kw in hay and len(kw) > best_len:
                best_key, best_len = m.key, len(kw)
    if best_key:
        return best_key
    # 3) fall back to a sensible bucket by collector hint
    fallback = {
        "ad": "active_directory_audit", "ldap": "ldap_security_audit",
        "kerberos": "kerberos_security_audit", "ssh": "ssh_security_audit",
        "aws": "aws_iam_audit", "network": "network_exposure_scanner",
        "privilege": "privileged_account_audit", "acl": "active_directory_audit",
        "windows_privileges": "windows_security_audit",
    }
    return fallback.get(finding_module, "vulnerability_management")


def stats() -> Dict[str, int]:
    impl = sum(1 for m in MODULES if m.collector)
    return {
        "total": len(MODULES),
        "implemented": impl,
        "planned": len(MODULES) - impl,
    }
