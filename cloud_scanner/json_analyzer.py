"""
Offline analysis of exported JSON (security groups, S3-style policies, ARM NSG snippets).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

from .models import CloudProvider, Finding, Severity


def analyze_json_file(path: str | Path) -> List[Finding]:
    """Detect misconfigurations in a JSON file (format auto-detected)."""
    p = Path(path)
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    findings: List[Finding] = []
    findings.extend(_maybe_security_groups(data, str(p)))
    findings.extend(_maybe_s3_policy(data, str(p)))
    findings.extend(_maybe_azure_nsg(data, str(p)))
    return findings


def _maybe_security_groups(data: Any, source: str) -> List[Finding]:
    out: List[Finding] = []
    groups: list = []
    if isinstance(data, dict):
        if "SecurityGroups" in data:
            groups = data["SecurityGroups"]
        elif data.get("GroupId") and "IpPermissions" in data:
            groups = [data]
    if not groups:
        return out

    risky = {22, 23, 25, 110, 135, 139, 1433, 1521, 3306, 3389, 5432, 6379, 27017}
    for sg in groups:
        gid = sg.get("GroupId", "unknown")
        vpc = sg.get("VpcId", "")
        name = next((t.get("Value") for t in sg.get("Tags", []) if t.get("Key") == "Name"), gid)
        for perm in sg.get("IpPermissions", []):
            proto = perm.get("IpProtocol", "-1")
            from_p = perm.get("FromPort")
            to_p = perm.get("ToPort")
            for r in perm.get("IpRanges", []):
                cidr = r.get("CidrIp", "")
                if cidr not in ("0.0.0.0/0", "::/0"):
                    continue
                port_desc = _port_desc(from_p, to_p, proto)
                if proto == "-1" or from_p is None:
                    sev = Severity.CRITICAL
                    code = "AWS_SG_OPEN_INTERNET"
                    title = f"Security group allows all traffic from the Internet ({name})"
                elif from_p is not None and int(from_p) in risky or (to_p and int(to_p) in risky):
                    sev = Severity.HIGH
                    code = "AWS_SG_RISKY_PORT_WORLD"
                    title = f"Security group exposes sensitive port(s) to the Internet ({name})"
                else:
                    sev = Severity.MEDIUM
                    code = "AWS_SG_OPEN_INTERNET"
                    title = f"Security group allows inbound from 0.0.0.0/0 ({name})"
                out.append(
                    Finding(
                        code=code,
                        title=title,
                        detail=f"{port_desc} — GroupId={gid}, VpcId={vpc}. Source file: {source}",
                        severity=sev,
                        provider=CloudProvider.STATIC,
                        resource_id=gid,
                        resource_type="ec2:security-group",
                        raw={"rule": perm, "cidr": cidr},
                    )
                )
    return out


def _port_desc(from_p: Any, to_p: Any, proto: str) -> str:
    if proto == "-1":
        return "All protocols/ports"
    if from_p is None:
        return f"protocol {proto}"
    if from_p == to_p:
        return f"port {from_p}/{proto}"
    return f"ports {from_p}-{to_p}/{proto}"


def _maybe_s3_policy(data: Any, source: str) -> List[Finding]:
    out: List[Finding] = []
    stmt = None
    if isinstance(data, dict):
        if "Statement" in data:
            stmt = data["Statement"]
        elif data.get("Version") and "Statement" in data:
            stmt = data["Statement"]
    if stmt is None:
        return out
    if not isinstance(stmt, list):
        stmt = [stmt]
    for s in stmt:
        principal = s.get("Principal", {})
        pub = principal == "*" or principal == {"AWS": "*"}
        if isinstance(principal, dict) and principal.get("AWS") == "*":
            pub = True
        if pub:
            actions = s.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if any("GetObject" in str(a) or "s3:" in str(a) for a in actions):
                out.append(
                    Finding(
                        code="STATIC_S3_POLICY_JSON",
                        title="Bucket policy may allow public access (Principal *)",
                        detail=f"Review Statement in {source}",
                        severity=Severity.HIGH,
                        provider=CloudProvider.STATIC,
                        resource_id=source,
                        resource_type="s3:bucket-policy",
                        raw=dict(s),
                    )
                )
    return out


def _maybe_azure_nsg(data: Any, source: str) -> List[Finding]:
    """Detect Azure NSG export shape (securityRules array)."""
    out: List[Finding] = []
    rules = None
    if isinstance(data, dict):
        rules = data.get("securityRules") or data.get("properties", {}).get("securityRules")
    if not rules:
        return out
    nsg_name = data.get("name", "nsg") if isinstance(data, dict) else "nsg"
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        props = rule.get("properties", rule)
        if props.get("direction") != "Inbound":
            continue
        access = props.get("access", "").lower()
        if access != "allow":
            continue
        src = props.get("sourceAddressPrefix") or props.get("sourceAddressPrefixes") or ""
        if isinstance(src, list):
            src = ",".join(src)
        if src not in ("*", "Internet", "0.0.0.0/0", "Any"):
            continue
        dest = props.get("destinationPortRange") or props.get("destinationPortRanges") or "*"
        out.append(
            Finding(
                code="AZURE_NSG_OPEN_INTERNET",
                title=f"NSG allows inbound from Internet ({nsg_name})",
                detail=f"Rule: {props.get('name', rule.get('name'))}, ports: {dest}. File: {source}",
                severity=Severity.HIGH,
                provider=CloudProvider.STATIC,
                resource_id=str(rule.get("id", nsg_name)),
                resource_type="network:nsg-rule",
                raw=dict(props),
            )
        )
    return out
