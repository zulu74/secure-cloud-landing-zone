# Incident Response Runbook: Leaked AWS Access Key

**Scenario:** An AWS access key (`AKIA...`) for this project has been
committed to a public repository, pasted into a public forum/Slack, or
otherwise exposed. This runbook assumes the key belongs to either the
`${project_name}-app-role` application role's associated credentials
or a human IAM user with programmatic access.

This is written to be run by one person under time pressure — each
step says exactly what to type or click, not just what to achieve.

---

## Severity & triage (first 5 minutes)

1. **Confirm the key is real and live.**
   ```bash
   aws sts get-caller-identity --profile <suspect-profile>
   ```
   If this returns an identity, the key is active. Treat as live until
   proven otherwise — don't wait for confirmation of misuse.

2. **Classify blast radius** using the IAM policy attached to the key
   (see `terraform/iam.tf` for what this project's role *should* have —
   confirm the live policy matches; a manual console change is itself
   a finding `posture_check.py` should have caught).
   - Scoped to one S3 bucket → contained, but still rotate.
   - Broad / admin-equivalent → treat as full account compromise.

## Containment (next 10–15 minutes)

3. **Disable the credential immediately — don't delete yet** (deleting
   first can remove evidence needed for the post-mortem):
   ```bash
   aws iam update-access-key \
     --access-key-id AKIA... \
     --status Inactive \
     --user-name <iam-user-name>
   ```
   If the key belongs to a role (not a long-lived IAM user key), instead
   revoke active sessions:
   ```bash
   aws iam put-role-policy \
     --role-name secure-landing-zone-app-role \
     --policy-name DenyAllPending \
     --policy-document file://docs/deny-all.json
   ```

4. **Rotate:** issue a new key/role trust and update it everywhere the
   old one was used (CI secrets, `.env` files, deployed Lambda config).
   Never re-activate a compromised key.

5. **If this repo is where the key leaked:** purge it from git history,
   not just the latest commit (`git log -p | grep AKIA` to confirm
   scope first):
   ```bash
   # BFG Repo-Cleaner is faster and safer than filter-branch for this.
   bfg --replace-text passwords.txt
   git push --force
   ```
   Then invalidate the key regardless — a force-push does not undo an
   exposure that's already been scraped by a bot (this typically
   happens within minutes on GitHub).

## Eradication & verification (next 30 minutes)

6. **Check CloudTrail for activity on the key** between its creation
   and deactivation:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
     --start-time <exposure-window-start>
   ```
   Look specifically for: new IAM users/roles created, policy changes,
   EC2 instances launched (common for crypto-mining abuse), and any
   `GetObject`/`PutObject` outside expected buckets.

7. **Run `scripts/posture_check.py --fail-on-critical`** against the
   account to confirm no new public buckets, wildcard policies, or
   open security groups were created during the exposure window.

8. **Check for persistence mechanisms** the attacker may have left
   behind even after the key is dead: new IAM users, new access keys
   on *other* users, new Lambda functions, new EC2 key pairs.

## Recovery

9. Redeploy from known-good Terraform state (`terraform plan` should
   show zero unexpected drift once posture check and CloudTrail are
   clean).
10. Re-enable normal operations once the new credential is confirmed
    working end-to-end in CI.

## Post-incident (within 48 hours)

11. Write up: how the key leaked, time-to-detect, time-to-contain,
    what CloudTrail/posture-check showed, and one concrete pipeline
    change that would have caught this sooner (e.g., this is exactly
    what the `gitleaks` job in `security-pipeline.yml` is meant to
    prevent — if it fired late or not at all, that's the finding).
12. Update this runbook with anything that didn't go as scripted.

---

### Why this runbook exists in the repo (not just in someone's head)

A security control nobody can execute under pressure isn't a control.
Keeping this versioned alongside the Terraform and CI config that it
references means the runbook never silently drifts out of date when
the infrastructure changes — a PR that renames the app role is a PR
that should also touch this file.
