from __future__ import annotations

from typing import List

# Maps finding `code` to human-readable remediation steps (AWS CLI / Azure CLI / console hints).

REMEDIATION: dict[str, List[str]] = {
    "AWS_S3_PUBLIC": [
        "Enable S3 Block Public Access at account or bucket level (AWS Console → S3 → bucket → Permissions).",
        "AWS CLI: aws s3api put-public-access-block --bucket NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "Review bucket policy and ACLs; remove Principal: \"*\" or public grants unless intentionally public (static website with controls).",
    ],
    "AWS_SG_OPEN_INTERNET": [
        "Edit the security group: replace 0.0.0.0/0 with a VPN CIDR, bastion host SG, or specific office IPs.",
        "AWS CLI: aws ec2 revoke-security-group-ingress --group-id sg-xxx --ip-permissions '...'",
        "For web traffic use an ALB + WAF instead of opening SSH/RDP to the world.",
    ],
    "AWS_SG_RISKY_PORT_WORLD": [
        "Restrict inbound rules to known CIDRs; use SSM Session Manager instead of SSH from 0.0.0.0/0 where possible.",
        "For RDP/SSH, require VPN or AWS Client VPN / bastion with MFA.",
    ],
    "AWS_API_GW_ANONYMOUS": [
        "Add an authorizer (Cognito, Lambda, IAM) or API keys + usage plans on sensitive routes.",
        "Restrict resource policies so execute-api:Invoke is not granted to \"*\" without business justification.",
        "Consider AWS WAF on API Gateway stage if the API must be public.",
    ],
    "AWS_LAMBDA_URL_PUBLIC": [
        "Disable the function URL or attach auth (Lambda response headers + JWT validation in function).",
        "Prefer API Gateway / ALB with proper authorizers in front of Lambda.",
    ],
    "AZURE_STORAGE_PUBLIC": [
        "Set allowBlobPublicAccess to false on the storage account (Azure Portal → Storage account → Configuration).",
        "Azure CLI: az storage account update --name NAME --resource-group RG --allow-blob-public-access false",
        "Disable anonymous access on containers unless required for static hosting with a CDN in front.",
    ],
    "AZURE_NSG_OPEN_INTERNET": [
        "Narrow NSG rules: replace * / Internet with specific IPs, service tags, or Application Security Groups.",
        "Azure CLI: az network nsg rule update ... or delete overly permissive rules.",
        "Place jump boxes behind Azure Bastion instead of exposing RDP/SSH broadly.",
    ],
    "AZURE_API_EXPOSED": [
        "Enable subscription keys, OAuth, or Azure AD auth on APIM APIs; remove anonymous products if unintended.",
        "Use Application Gateway WAF in front of public APIs when appropriate.",
    ],
    "STATIC_SG_JSON": [
        "Treat this as offline analysis; apply the same remediation as live security group findings after verifying in AWS.",
    ],
    "STATIC_S3_POLICY_JSON": [
        "Remove s3:GetObject (or other actions) for Principal \"*\" unless using CloudFront OAC/OAI with a locked bucket.",
    ],
}


def suggestions_for_code(code: str) -> List[str]:
    return list(REMEDIATION.get(code, [
        "Review the finding in your cloud console and align with your organization’s security baseline.",
        "Document exceptions and apply compensating controls (monitoring, WAF, least privilege).",
    ]))


def format_remediation_block(code: str) -> str:
    lines = suggestions_for_code(code)
    return "\n".join(f"  • {line}" for line in lines)
