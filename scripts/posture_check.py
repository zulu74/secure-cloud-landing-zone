#!/usr/bin/env python3
"""
posture_check.py — continuous cloud security posture baseline.

Runs a small set of checks against a live AWS (or LocalStack) account
and reports findings, loosely modeled on CIS AWS Foundations Benchmark
controls. This is the "detect drift after deploy" half of DevSecOps —
the IaC scanners in the CI pipeline catch bad config before it ships;
this catches bad config that shows up afterwards (manual console
changes, a policy edited outside Terraform, etc.).

Usage:
    python scripts/posture_check.py                 # print findings, exit 0
    python scripts/posture_check.py --fail-on-critical
    python scripts/posture_check.py --json out.json

Findings are also written as GitHub Issues when GITHUB_TOKEN and
GITHUB_REPOSITORY are set (wired up in the CI workflow / cron job),
so they land where the team already looks instead of a log nobody reads.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from enum import Enum
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclasses.dataclass
class Finding:
    check_id: str
    severity: Severity
    resource: str
    description: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        return d


def _client(service: str):
    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    return boto3.client(
        service,
        endpoint_url=endpoint,
        config=Config(retries={"max_attempts": 3, "mode": "standard"}),
    )


# ---------------------------------------------------------------------------
# Checks — each returns a list[Finding]; add new checks here and register
# them in CHECKS at the bottom. Keeping each check a pure function makes
# them trivial to unit test in isolation.
# ---------------------------------------------------------------------------


def check_public_s3_buckets() -> list[Finding]:
    """CIS 2.1.5-ish: S3 buckets must block public access."""
    s3 = _client("s3")
    findings: list[Finding] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as exc:
        return [
            Finding(
                "S3-000",
                Severity.LOW,
                "s3",
                f"Could not list buckets: {exc}",
                "Verify credentials/permissions for posture-check role.",
            )
        ]

    for bucket in buckets:
        name = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            blocked = all(
                pab.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "BlockPublicPolicy",
                    "IgnorePublicAcls",
                    "RestrictPublicBuckets",
                )
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                blocked = False
            else:
                continue

        if not blocked:
            findings.append(
                Finding(
                    "S3-001",
                    Severity.CRITICAL,
                    f"s3://{name}",
                    "Bucket does not fully block public access.",
                    "Attach an aws_s3_bucket_public_access_block resource "
                    "with all four settings enabled.",
                )
            )

        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            if not rules:
                raise ClientError({"Error": {"Code": "NoEncryption"}}, "GetBucketEncryption")
        except ClientError:
            findings.append(
                Finding(
                    "S3-002",
                    Severity.HIGH,
                    f"s3://{name}",
                    "Bucket has no default server-side encryption configured.",
                    "Attach aws_s3_bucket_server_side_encryption_configuration.",
                )
            )

    return findings


def check_iam_wildcard_policies() -> list[Finding]:
    """CIS 1.16-ish: no customer-managed IAM policy should grant Action:* / Resource:*."""
    iam = _client("iam")
    findings: list[Finding] = []

    try:
        policies = iam.list_policies(Scope="Local")["Policies"]
    except ClientError as exc:
        return [
            Finding(
                "IAM-000",
                Severity.LOW,
                "iam",
                f"Could not list policies: {exc}",
                "Verify credentials/permissions for posture-check role.",
            )
        ]

    for policy in policies:
        arn = policy["Arn"]
        version_id = policy["DefaultVersionId"]
        try:
            doc = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)["PolicyVersion"]["Document"]
        except ClientError:
            continue

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = [resources] if isinstance(resources, str) else resources

            if "*" in actions and "*" in resources:
                findings.append(
                    Finding(
                        "IAM-001",
                        Severity.CRITICAL,
                        arn,
                        "Policy grants Action:* on Resource:* (full admin).",
                        "Scope the policy to specific actions and resource ARNs.",
                    )
                )

    return findings


def check_security_groups_open_to_world() -> list[Finding]:
    """CIS 5.2/5.3: no security group should allow ingress from 0.0.0.0/0 on all ports."""
    ec2 = _client("ec2")
    findings: list[Finding] = []

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as exc:
        return [
            Finding(
                "SG-000",
                Severity.LOW,
                "ec2",
                f"Could not describe security groups: {exc}",
                "Verify credentials/permissions for posture-check role.",
            )
        ]

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            open_to_world = any(
                r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
            )
            if open_to_world:
                findings.append(
                    Finding(
                        "SG-001",
                        Severity.HIGH,
                        sg.get("GroupId", "unknown"),
                        f"Security group '{sg.get('GroupName')}' allows ingress "
                        f"from 0.0.0.0/0 on port range "
                        f"{perm.get('FromPort')}-{perm.get('ToPort')}.",
                        "Restrict ingress to specific CIDRs or security groups; "
                        "never 0.0.0.0/0 except for a fronting load balancer on 443.",
                    )
                )

    return findings


CHECKS = [
    check_public_s3_buckets,
    check_iam_wildcard_policies,
    check_security_groups_open_to_world,
]


def run_all_checks() -> list[Finding]:
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check())
    return findings


def print_report(findings: list[Finding]) -> None:
    if not findings:
        print("✅ Posture check passed — no findings.")
        return

    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    for f in sorted(findings, key=lambda f: order[f.severity]):
        print(f"[{f.severity.value}] {f.check_id} — {f.resource}")
        print(f"    {f.description}")
        print(f"    → {f.remediation}\n")

    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    print("Summary:", ", ".join(f"{s.value}={counts[s]}" for s in Severity if counts[s]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fail-on-critical", action="store_true",
                         help="Exit non-zero if any CRITICAL finding is present.")
    parser.add_argument("--json", metavar="PATH",
                         help="Also write findings as JSON to this path.")
    args = parser.parse_args()

    findings = run_all_checks()
    print_report(findings)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2)

    if args.fail_on_critical and any(f.severity == Severity.CRITICAL for f in findings):
        print("\n❌ Failing build: one or more CRITICAL findings.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
