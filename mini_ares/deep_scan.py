"""
Nmap in-depth scan: service/version (-sV), optional OS (-O), and safe NSE scripts.
Requires nmap on PATH or standard install path (see tool_paths).
"""
from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from .tool_paths import resolve_nmap_executable

# Safe, read-only style scripts (no intrusive exploitation)
DEFAULT_NSE_SCRIPTS = (
    "http-title,http-server-header,http-headers,ssl-cert,ssh-hostkey,"
    "tls-nextprotoneg,tls-alpn"
)


@dataclass
class NmapScriptLine:
    script_id: str
    output: str


@dataclass
class NmapPortInfo:
    port: int
    protocol: str
    state: str
    service_name: str
    product: str
    version: str
    extrainfo: str
    cpe: list[str]
    scripts: list[NmapScriptLine] = field(default_factory=list)


@dataclass
class NmapHostScan:
    hostnames: list[str]
    addresses: list[dict[str, str]]  # addr, addrtype
    os_matches: list[dict[str, Any]]  # name, accuracy
    os_classes: list[dict[str, Any]]
    ports: list[NmapPortInfo]


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return str(el.text).strip()


def _parse_nmap_xml(xml_bytes: str) -> NmapHostScan | None:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None
    host_el = root.find("host")
    if host_el is None:
        return None

    hostnames: list[str] = []
    hn = host_el.find("hostnames")
    if hn is not None:
        for h in hn.findall("hostname"):
            n = h.get("name")
            if n:
                hostnames.append(n)

    addresses: list[dict[str, str]] = []
    for a in host_el.findall("address"):
        addr = a.get("addr")
        at = a.get("addrtype") or ""
        if addr:
            addresses.append({"addr": addr, "addrtype": at})

    os_matches: list[dict[str, Any]] = []
    os_classes: list[dict[str, Any]] = []
    os_el = host_el.find("os")
    if os_el is not None:
        for om in os_el.findall("osmatch"):
            os_matches.append(
                {
                    "name": om.get("name") or "",
                    "accuracy": om.get("accuracy") or "",
                }
            )
        for oc in os_el.findall("osclass"):
            os_classes.append(
                {
                    "type": oc.get("type") or "",
                    "vendor": oc.get("vendor") or "",
                    "osfamily": oc.get("osfamily") or "",
                    "osgen": oc.get("osgen") or "",
                    "accuracy": oc.get("accuracy") or "",
                }
            )

    ports_out: list[NmapPortInfo] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for pe in ports_el.findall("port"):
            pid = pe.get("portid")
            proto = pe.get("protocol") or "tcp"
            if not pid:
                continue
            try:
                port_num = int(pid)
            except ValueError:
                continue
            st_el = pe.find("state")
            state = st_el.get("state") if st_el is not None else ""
            svc_el = pe.find("service")
            name = product = version = extrainfo = ""
            cpe_list: list[str] = []
            if svc_el is not None:
                name = svc_el.get("name") or ""
                product = svc_el.get("product") or ""
                version = svc_el.get("version") or ""
                extrainfo = svc_el.get("extrainfo") or ""
                for cpe in svc_el.findall("cpe"):
                    if cpe.text:
                        cpe_list.append(cpe.text.strip())
            scripts: list[NmapScriptLine] = []
            for sc in pe.findall("script"):
                sid = sc.get("id") or "script"
                out = sc.get("output") or ""
                scripts.append(NmapScriptLine(script_id=sid, output=out[:4000]))

            ports_out.append(
                NmapPortInfo(
                    port=port_num,
                    protocol=proto,
                    state=state,
                    service_name=name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=cpe_list,
                    scripts=scripts,
                )
            )

    return NmapHostScan(
        hostnames=hostnames,
        addresses=addresses,
        os_matches=os_matches[:8],
        os_classes=os_classes[:8],
        ports=ports_out,
    )


def nmap_host_scan_to_dict(nh: NmapHostScan) -> dict[str, Any]:
    return {
        "hostnames": nh.hostnames,
        "addresses": nh.addresses,
        "os_matches": nh.os_matches,
        "os_classes": nh.os_classes,
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service_name,
                "product": p.product,
                "version": p.version,
                "extrainfo": p.extrainfo,
                "cpe": p.cpe,
                "scripts": [{"id": s.script_id, "output": s.output} for s in p.scripts],
            }
            for p in nh.ports
        ],
    }


def run_nmap_deep_scan(
    host: str,
    ports: list[int],
    *,
    timeout: int = 360,
    os_detection: bool = False,
    script_list: str | None = None,
) -> NmapHostScan | None:
    """
    Run nmap with -sV (version), optional -O (OS), and NSE scripts; return parsed XML.
    """
    nmap_exe = resolve_nmap_executable()
    if not nmap_exe:
        return None
    port_arg = ",".join(str(p) for p in ports)
    scripts = script_list or DEFAULT_NSE_SCRIPTS
    args: list[str] = [
        nmap_exe,
        "-Pn",
        "-sT",
        "-sV",
        "-T4",
        "--open",
        "-p",
        port_arg,
        "--script",
        scripts,
        "-oX",
        "-",
        host,
    ]
    if os_detection:
        # May require elevated privileges on some OSes; nmap will still return partial results
        args = [nmap_exe, "-Pn", "-sT", "-sV", "-T4", "--open", "-O", "--osscan-guess", "-p", port_arg, "--script", scripts, "-oX", "-", host]

    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None

    xml_out = (p.stdout or "").strip()
    if not xml_out.startswith("<?xml"):
        # Retry without OS if OS scan failed to produce XML
        if os_detection:
            return run_nmap_deep_scan(
                host, ports, timeout=timeout, os_detection=False, script_list=script_list
            )
        return None

    return _parse_nmap_xml(xml_out)


def format_port_detail(p: NmapPortInfo) -> str:
    bits = [f"{p.protocol.upper()}/{p.state}", p.service_name or "unknown"]
    if p.product:
        bits.append(p.product)
    if p.version:
        bits.append(p.version)
    if p.extrainfo:
        bits.append(f"({p.extrainfo})")
    line = " ".join(b for b in bits if b)
    if p.cpe:
        line += "\nCPE: " + ", ".join(p.cpe[:6])
    if p.scripts:
        line += "\n\nScripts:"
        for s in p.scripts[:12]:
            line += f"\n  [{s.script_id}] {s.output[:600]}"
    return line.strip()


def format_os_detail(nh: NmapHostScan) -> str:
    lines: list[str] = []
    for m in nh.os_matches[:5]:
        lines.append(f"  • {m.get('name', '')} (accuracy {m.get('accuracy', '')})")
    for c in nh.os_classes[:5]:
        lines.append(
            f"  • class: {c.get('vendor', '')} {c.get('osfamily', '')} {c.get('osgen', '')} "
            f"({c.get('type', '')}, acc {c.get('accuracy', '')})"
        )
    return "\n".join(lines) if lines else "(no OS fingerprint)"


def summarize_tech_stack(nh: NmapHostScan, http_fp: dict[str, Any] | None) -> str:
    """Human-readable stack summary from nmap services + optional HTTP fingerprint."""
    parts: list[str] = []
    for p in nh.ports:
        if p.product or p.version:
            parts.append(f"{p.port}/{p.service_name}: {p.product} {p.version}".strip())
        elif p.service_name:
            parts.append(f"{p.port}: {p.service_name}")
    if http_fp and not http_fp.get("error"):
        parts.append(
            f"HTTP {http_fp.get('status')}: Server={http_fp.get('server') or '—'}; "
            f"X-Powered-By={http_fp.get('x_powered_by') or '—'}"
        )
        if http_fp.get("framework_hints"):
            parts.append("Framework hints: " + ", ".join(http_fp["framework_hints"]))
    return "\n".join(parts) if parts else "No strong stack signals."
