# Secure Cloud Landing Zone with CI/CD Security Guardrails

A small, deliberately end-to-end DevSecOps project: it provisions a
minimal AWS "landing zone" with Terraform, gates every change through
automated security scanning before it can merge, continuously checks
the deployed environment against a security baseline, and documents
how to respond when something goes wrong anyway. Everything runs
against [LocalStack](https://www.localstack.cloud/) so the whole thing
is reproducible at zero cost — no AWS bill required to prove it works.

Most portfolios show the "ship infrastructure" half of DevSecOps.
This one shows the half that actually fills most of the job: catching
problems before they ship, catching drift after they ship, and having
a rehearsed plan for when prevention fails anyway.

## Architecture

```
┌─────────────┐      PR opened      ┌───────────────────────────────┐
│  Terraform   │ ──────────────────▶ │     GitHub Actions Pipeline    │
│  (terraform/)│                      │                                │
└─────────────┘                      │  ① tfsec + checkov  (IaC scan) │
      │                              │  ② gitleaks         (secrets)  │
      │ terraform apply              │  ③ trivy             (CVEs)    │
      ▼                              │  ④ deploy → LocalStack          │
┌─────────────┐                      │  ⑤ posture_check.py (baseline) │
│  LocalStack  │◀─────────────────── └───────────────────────────────┘
│ (fake AWS)   │
└─────────────┘
      │
      ▼
 docs/incident-response-runbook.md  ← what to do when a check fails anyway
```

| Layer | What it does | Where |
|---|---|---|
| **Provision** | VPC, locked-down default security group, least-privilege IAM role, encrypted + access-blocked S3 bucket with logging | `terraform/` |
| **Shift-left gates** | Fail the PR on IaC misconfig, leaked secrets, or vulnerable container images | `.github/workflows/security-pipeline.yml` |
| **Detect drift** | After deploy, independently re-check the live environment against a CIS-style baseline (public buckets, wildcard IAM, open security groups) | `scripts/posture_check.py` |
| **Respond** | A runbook a person under pressure can actually follow for a leaked-credential incident | `docs/incident-response-runbook.md` |

## Running it locally

1. **Start LocalStack:**
   ```bash
   pip install localstack
   localstack start -d
   ```

2. **Provision the landing zone:**
   ```bash
   cd terraform
   terraform init
   terraform apply -auto-approve
   ```

3. **Run the posture check against it:**
   ```bash
   cd ..
   pip install -r scripts/requirements.txt
   export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
   export AWS_ENDPOINT_URL=http://localhost:4566
   python scripts/posture_check.py
   ```
   Expect `✅ Posture check passed — no findings.` on a clean apply.
   Try manually loosening the S3 public access block or widening a
   security group to see it catch the drift.

4. **See the gates fail on purpose:** comment out the
   `aws_s3_bucket_public_access_block` resource in `terraform/s3.tf`
   and open a PR — `checkov`/`tfsec` should block the merge before it
   ever reaches LocalStack.

## Why each tool, not just "a" tool

- **tfsec / checkov** — two IaC scanners instead of one on purpose;
  they catch overlapping but not identical issues, which mirrors how
  real pipelines are built (defense in depth, not a single point of
  failure in the tooling itself).
- **gitleaks** — scans full git history on every run, not just the
  diff, because a secret committed three commits ago and then
  "removed" is still exposed.
- **trivy** — scans container images for known CVEs with a hard fail
  on CRITICAL/HIGH, the same gate most real CI/CD security policies
  enforce.
- **LocalStack** — makes the "deploy and verify" half of the pipeline
  runnable in CI and on a laptop with no AWS credentials, no cost, and
  no risk of a demo project leaving real infrastructure running.

## CV-ready summary

> Built a Terraform-provisioned AWS landing zone (VPC, least-privilege
> IAM, encrypted/access-blocked S3) with a GitHub Actions pipeline
> enforcing IaC scanning (tfsec, checkov), secret scanning (gitleaks)
> and container CVE scanning (trivy) as hard merge gates; added a
> Python posture-check tool that re-validates the deployed environment
> against CIS-style controls after every deploy, and a documented
> incident-response runbook for credential-leak scenarios. Entire
> stack runs against LocalStack for zero-cost, fully reproducible CI.

## Next steps (good follow-up commits)

- Add a Lambda function as the actual workload the `app_role` assumes,
  so the IAM policy has something real to protect.
- Wire `posture_check.py` findings to auto-file GitHub Issues.
- Add a `terraform plan` drift-detection job on a schedule (not just
  on PR) to catch manual console changes between deploys.
