"""
Network exposure collector — a real, dependency-free TCP connect scanner.

Unlike the Windows/AD collectors (which need a live domain), this collector
works entirely from the standard library and produces genuine findings against
any reachable target. It performs a concurrent TCP connect scan over a set of
security-relevant ports, maps them to services, and flags reachable
remote-administration planes with canonical signatures that the MITRE mapping
engine understands (NET_RDP_EXPOSED, NET_WINRM_EXPOSED, ...).

Nothing is fabricated: a port is only reported open if the TCP handshake
actually completes.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

# port -> (service, is_remote_admin, canonical signature for admin planes)
PORT_MAP: Dict[int, Dict[str, Any]] = {
    21: {"service": "FTP", "admin": False},
    22: {"service": "SSH", "admin": True, "sig": "NET_SSH_EXPOSED"},
    23: {"service": "Telnet", "admin": True, "sig": "NET_OPEN_PORTS"},
    25: {"service": "SMTP", "admin": False},
    53: {"service": "DNS", "admin": False},
    80: {"service": "HTTP", "admin": False},
    88: {"service": "Kerberos", "admin": False},
    110: {"service": "POP3", "admin": False},
    135: {"service": "MS-RPC (EPMAP)", "admin": False},
    139: {"service": "NetBIOS-SSN", "admin": False},
    389: {"service": "LDAP", "admin": False, "sig": "NET_LDAP_EXPOSED"},
    443: {"service": "HTTPS", "admin": False},
    445: {"service": "SMB", "admin": True, "sig": "NET_SMB_EXPOSED"},
    464: {"service": "Kerberos (kpasswd)", "admin": False},
    636: {"service": "LDAPS", "admin": False},
    993: {"service": "IMAPS", "admin": False},
    1433: {"service": "MSSQL", "admin": False},
    3306: {"service": "MySQL", "admin": False},
    3389: {"service": "RDP", "admin": True, "sig": "NET_RDP_EXPOSED"},
    5432: {"service": "PostgreSQL", "admin": False},
    5985: {"service": "WinRM (HTTP)", "admin": True, "sig": "NET_WINRM_EXPOSED"},
    5986: {"service": "WinRM (HTTPS)", "admin": True, "sig": "NET_WINRM_EXPOSED"},
    3268: {"service": "Global Catalog", "admin": False},
    9389: {"service": "AD Web Services", "admin": False},
    8080: {"service": "HTTP-alt", "admin": False},
}
DEFAULT_PORTS = sorted(PORT_MAP.keys())


def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def run(host: str, ports: List[int] = None, timeout: float = 1.0,
        max_workers: int = 40, **_ignored) -> List[Dict[str, Any]]:
    """Scan ``host`` and return legacy-shaped findings for the normalizer."""
    findings: List[Dict[str, Any]] = []
    if not host:
        return [{"check": "Network exposure scan",
                 "result": "No target host provided.",
                 "severity": "INFO",
                 "recommendation": "Provide a target host/IP to scan."}]

    ports = ports or DEFAULT_PORTS

    # resolve first so we fail cleanly on bad targets
    try:
        socket.gethostbyname(host)
    except OSError as e:
        return [{"check": "Network exposure scan",
                 "result": f"Could not resolve/reach target '{host}': {e}",
                 "severity": "INFO",
                 "recommendation": "Verify the target hostname/IP and connectivity."}]

    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            if fut.result():
                open_ports.append(futures[fut])
    open_ports.sort()

    if not open_ports:
        findings.append({
            "check": "Network exposure scan",
            "result": f"No scanned TCP ports reachable on {host}.",
            "severity": "OK",
            "recommendation": "Attack surface is minimal for the scanned port set."})
        return findings

    # summary finding (open ports)
    svc_list = ", ".join(f"{p}/{PORT_MAP.get(p, {}).get('service', 'unknown')}"
                         for p in open_ports)
    findings.append({
        "check": "Open TCP ports",
        "result": f"{len(open_ports)} reachable services on {host}: {svc_list}",
        "severity": "INFO",
        "signature": "NET_OPEN_PORTS",
        "affected": [str(p) for p in open_ports],
        "recommendation": "Reduce exposure: restrict to required ports via firewall/segmentation."})

    # one finding per reachable remote-admin plane
    for p in open_ports:
        meta = PORT_MAP.get(p, {"service": "unknown", "admin": False})
        if not meta.get("admin"):
            continue
        sig = meta.get("sig", "NET_OPEN_PORTS")
        findings.append({
            "check": f"{meta['service']} exposed (tcp/{p})",
            "result": f"{meta['service']} is reachable on {host}:{p}.",
            "severity": "HIGH" if sig in ("NET_RDP_EXPOSED", "NET_WINRM_EXPOSED") else "MEDIUM",
            "signature": sig,
            "affected": [f"{host}:{p}"],
            "recommendation": (
                f"Restrict {meta['service']} to management networks / VPN, enforce MFA "
                "and network-level authentication where applicable.")})

    return findings
