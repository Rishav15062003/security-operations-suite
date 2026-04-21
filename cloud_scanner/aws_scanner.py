from __future__ import annotations

from typing import List, Set

import boto3
from botocore.exceptions import ClientError

from .models import CloudProvider, Finding, Severity
from .config_loader import ScanConfig


def _session(cfg: ScanConfig):
    return boto3.Session(profile_name=cfg.aws_profile, region_name=cfg.aws_regions[0])


def scan_aws(cfg: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    session = _session(cfg)
    findings.extend(_scan_s3(session, cfg))
    for region in cfg.aws_regions:
        findings.extend(_scan_security_groups(session, region))
        findings.extend(_scan_apigateway_http(session, region))
        findings.extend(_scan_lambda_urls(session, region))
    return findings


def _scan_s3(session: boto3.Session, cfg: ScanConfig) -> List[Finding]:
    out: List[Finding] = []
    s3 = session.client("s3")
    skip: Set[str] = set(cfg.aws_skip_buckets)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        return [
            Finding(
                code="AWS_S3_PUBLIC",
                title="Could not list S3 buckets",
                detail=str(e),
                severity=Severity.INFO,
                provider=CloudProvider.AWS,
                resource_id="s3",
                resource_type="s3:list-buckets",
                region="global",
            )
        ]

    for b in buckets:
        name = b["Name"]
        if name in skip:
            continue
        region = "us-east-1"
        try:
            loc = s3.get_bucket_location(Bucket=name)
            if loc.get("LocationConstraint"):
                region = loc["LocationConstraint"]
        except ClientError:
            pass

        risky = False
        detail_parts: List[str] = []

        try:
            pab = s3.get_public_access_block(Bucket=name)
            c = pab["PublicAccessBlockConfiguration"]
            if not all(
                c.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            ):
                risky = True
                detail_parts.append("Public access block not fully enabled")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                risky = True
                detail_parts.append("No public access block configuration (legacy bucket risk)")

        try:
            st = s3.get_bucket_policy_status(Bucket=name)
            if st.get("PolicyStatus", {}).get("IsPublic"):
                risky = True
                detail_parts.append("Bucket policy status reports public")
        except ClientError:
            pass

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                grantee = g.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    risky = True
                    detail_parts.append("ACL grants AllUsers or AuthenticatedUsers")
        except ClientError:
            pass

        if risky:
            out.append(
                Finding(
                    code="AWS_S3_PUBLIC",
                    title=f"Potentially public or overly permissive S3 bucket: {name}",
                    detail="; ".join(detail_parts) or "Review ACL, policy, and public access block.",
                    severity=Severity.HIGH,
                    provider=CloudProvider.AWS,
                    resource_id=name,
                    resource_type="s3:bucket",
                    region=region,
                )
            )
    return out


def _scan_security_groups(session: boto3.Session, region: str) -> List[Finding]:
    out: List[Finding] = []
    ec2 = session.client("ec2", region_name=region)
    risky_ports = {22, 23, 25, 135, 139, 1433, 1521, 3306, 3389, 5432, 6379, 27017}
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                gid = sg["GroupId"]
                name = next((t["Value"] for t in sg.get("Tags", []) if t["Key"] == "Name"), gid)
                vpc = sg.get("VpcId", "")
                for perm in sg.get("IpPermissions", []):
                    proto = perm.get("IpProtocol", "tcp")
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")
                    for r in perm.get("IpRanges", []):
                        cidr = r.get("CidrIp", "")
                        if cidr not in ("0.0.0.0/0", "::/0"):
                            continue
                        if proto == "-1" or from_p is None:
                            out.append(
                                Finding(
                                    code="AWS_SG_OPEN_INTERNET",
                                    title=f"Security group allows all protocols from Internet ({name})",
                                    detail=f"{gid} in {region}, VpcId={vpc}",
                                    severity=Severity.CRITICAL,
                                    provider=CloudProvider.AWS,
                                    resource_id=gid,
                                    resource_type="ec2:security-group",
                                    region=region,
                                    raw={"rule": perm},
                                )
                            )
                        elif from_p is not None and to_p is not None:
                            fp, tp = int(from_p), int(to_p)
                            if tp - fp > 256:
                                bad = True
                            else:
                                bad = any(p in risky_ports for p in range(fp, tp + 1))
                            code = "AWS_SG_RISKY_PORT_WORLD" if bad else "AWS_SG_OPEN_INTERNET"
                            sev = Severity.HIGH if bad else Severity.MEDIUM
                            out.append(
                                Finding(
                                    code=code,
                                    title=f"Security group inbound from 0.0.0.0/0 ({name}) ports {from_p}-{to_p}",
                                    detail=f"{gid} {region} protocol={proto}",
                                    severity=sev,
                                    provider=CloudProvider.AWS,
                                    resource_id=gid,
                                    resource_type="ec2:security-group",
                                    region=region,
                                    raw={"rule": perm},
                                )
                            )
    except ClientError as e:
        out.append(
            Finding(
                code="AWS_SG_OPEN_INTERNET",
                title=f"Could not describe security groups in {region}",
                detail=str(e),
                severity=Severity.INFO,
                provider=CloudProvider.AWS,
                resource_id=region,
                resource_type="ec2:describe-security-groups",
                region=region,
            )
        )
    return out


def _scan_apigateway_http(session: boto3.Session, region: str) -> List[Finding]:
    """API Gateway HTTP APIs (v2) with routes that use no authorizer."""
    out: List[Finding] = []
    client = session.client("apigatewayv2", region_name=region)
    try:
        apis = client.get_apis().get("Items", [])
    except ClientError:
        return out
    for api in apis:
        api_id = api["ApiId"]
        name = api.get("Name", api_id)
        endpoint = api.get("ApiEndpoint", "")
        try:
            routes = client.get_routes(ApiId=api_id).get("Items", [])
        except ClientError:
            continue
        for route in routes:
            rk = route.get("RouteKey", "")
            if rk.upper().startswith("OPTIONS"):
                continue
            auth = route.get("AuthorizationType", "NONE")
            if auth == "NONE":
                out.append(
                    Finding(
                        code="AWS_API_GW_ANONYMOUS",
                        title=f"HTTP API route without authorizer: {name}",
                        detail=f"Route {rk} — {endpoint} ({region})",
                        severity=Severity.MEDIUM,
                        provider=CloudProvider.AWS,
                        resource_id=api_id,
                        resource_type="apigatewayv2:api",
                        region=region,
                        raw={"route": route},
                    )
                )
    return out


def _scan_lambda_urls(session: boto3.Session, region: str) -> List[Finding]:
    out: List[Finding] = []
    lam = session.client("lambda", region_name=region)
    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                arn = fn["FunctionArn"]
                name = fn["FunctionName"]
                try:
                    cfg = lam.get_function_url_config(FunctionName=name)
                    if cfg.get("AuthType") == "NONE":
                        out.append(
                            Finding(
                                code="AWS_LAMBDA_URL_PUBLIC",
                                title=f"Lambda function URL allows unauthenticated access: {name}",
                                detail=f"{cfg.get('FunctionUrl')} ({region})",
                                severity=Severity.HIGH,
                                provider=CloudProvider.AWS,
                                resource_id=name,
                                resource_type="lambda:function-url",
                                region=region,
                            )
                        )
                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceNotFoundException":
                        pass
    except ClientError:
        pass
    return out
