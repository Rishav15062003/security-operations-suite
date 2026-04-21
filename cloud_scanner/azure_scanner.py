from __future__ import annotations

from typing import List

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

from .config_loader import ScanConfig
from .models import CloudProvider, Finding, Severity


def scan_azure(cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    sub = cfg.azure_subscription_id
    if not sub:
        return [
            Finding(
                code="AZURE_NSG_OPEN_INTERNET",
                title="Azure subscription ID not configured",
                detail="Set azure.subscription_id in config JSON or AZURE_SUBSCRIPTION_ID env var.",
                severity=Severity.INFO,
                provider=CloudProvider.AZURE,
                resource_id="subscription",
                resource_type="config",
                region=None,
            )
        ]

    cred = DefaultAzureCredential(exclude_interactive_browser_credential=False)
    out.extend(_scan_storage(cred, sub, cfg))
    out.extend(_scan_nsgs(cred, sub, cfg))
    out.extend(_scan_apim(cred, sub, cfg))
    return out


def _scan_storage(cred: DefaultAzureCredential, sub: str, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    client = StorageManagementClient(cred, sub)
    try:
        for sa in client.storage_accounts.list():
            rid = sa.id or ""
            name = sa.name
            allow_public = getattr(sa, "allow_blob_public_access", None)
            risky = allow_public is True
            if risky:
                out.append(
                    Finding(
                        code="AZURE_STORAGE_PUBLIC",
                        title=f"Storage account may allow public blob access: {name}",
                        detail="allow_blob_public_access=true — disable unless static hosting is intentional.",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        resource_id=rid,
                        resource_type="Microsoft.Storage/storageAccounts",
                        region=sa.location,
                    )
                )
    except HttpResponseError as e:
        out.append(
            Finding(
                code="AZURE_STORAGE_PUBLIC",
                title="Could not list storage accounts",
                detail=str(e),
                severity=Severity.INFO,
                provider=CloudProvider.AZURE,
                resource_id="storage",
                resource_type="Microsoft.Storage",
                region=None,
            )
        )
    return out


def _scan_nsgs(cred: DefaultAzureCredential, sub: str, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    client = NetworkManagementClient(cred, sub)
    risky_ports = {"22", "23", "3389", "1433", "3306", "5432", "6379", "27017", "*"}
    try:
        for nsg in client.network_security_groups.list_all():
            nsg_name = nsg.name or nsg.id
            loc = nsg.location
            for rule in nsg.security_rules or []:
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                src = rule.source_address_prefix or ""
                prefixes = getattr(rule, "source_address_prefixes", None) or []
                if src not in ("*", "Internet", "0.0.0.0/0", "Any") and not any(
                    x in ("*", "Internet", "0.0.0.0/0") for x in prefixes
                ):
                    continue
                dest = rule.destination_port_range or ""
                ranges = getattr(rule, "destination_port_ranges", None) or []
                ports = {dest} if dest else set(ranges)
                bad = bool(ports & risky_ports) or "*" in ports or any(
                    p in risky_ports for p in ports if p
                )
                if not ports and not ranges:
                    bad = True
                sev = Severity.HIGH if bad else Severity.MEDIUM
                out.append(
                    Finding(
                        code="AZURE_NSG_OPEN_INTERNET",
                        title=f"NSG allows inbound from Internet: {nsg_name}",
                        detail=f"Rule {rule.name}: ports {dest or ranges}, priority {rule.priority}",
                        severity=sev,
                        provider=CloudProvider.AZURE,
                        resource_id=nsg.id or nsg_name,
                        resource_type="network:nsg",
                        region=loc,
                        raw={"rule": rule.name},
                    )
                )
    except HttpResponseError as e:
        out.append(
            Finding(
                code="AZURE_NSG_OPEN_INTERNET",
                title="Could not list NSGs",
                detail=str(e),
                severity=Severity.INFO,
                provider=CloudProvider.AZURE,
                resource_id="nsg",
                resource_type="Microsoft.Network",
                region=None,
            )
        )
    return out


def _scan_apim(cred: DefaultAzureCredential, sub: str, cfg: ScanConfig) -> List[Finding]:
    """Flag API Management APIs that allow anonymous access (subscription not required)."""
    try:
        from azure.mgmt.apimanagement import ApiManagementClient
    except ImportError:
        return []

    out: List[Finding] = []
    client = ApiManagementClient(cred, sub)
    try:
        for svc in client.api_management_service.list():
            rg = svc.id.split("/")[4] if svc.id else ""
            name = svc.name
            try:
                for api in client.api.list_by_service(rg, name):
                    if getattr(api, "subscription_required", True) is False:
                        out.append(
                            Finding(
                                code="AZURE_API_EXPOSED",
                                title=f"APIM API does not require subscription: {api.name}",
                                detail=f"Service {name}, resource group {rg}",
                                severity=Severity.MEDIUM,
                                provider=CloudProvider.AZURE,
                                resource_id=api.id or "",
                                resource_type="Microsoft.ApiManagement/service/apis",
                                region=svc.location,
                            )
                        )
            except HttpResponseError:
                continue
    except HttpResponseError:
        pass
    return out
