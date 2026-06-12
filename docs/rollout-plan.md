# Rollout Plan -- 5 SWAT teams, zero Lead-Time regression

The hard part of this challenge isn't the scanners -- it's getting them
adopted by 5 teams that are already shipping in < 1 h without losing that
velocity or trust. Strategy: **graduated gates**, **opt-in to opt-out**,
**security owns the toil, not the squads**.

## Adoption pattern: 3 phases per scanner

| Phase | Duration | Behaviour | Exit criterion |
|---|---|---|---|
| 1. Shadow | 2 weeks | Scanner runs; findings posted as PR comments; **never** blocks. | False-positive rate < 10% on sampled PRs. |
| 2. Warn | 2 weeks | Scanner runs; findings annotated as warnings; merge allowed; weekly digest to squad lead. | < 3 unaddressed CRITICAL findings per squad. |
| 3. Block | ongoing | Build fails on any CRITICAL/HIGH. | n/a -- steady state. |

Each scanner moves through these phases *independently*. We don't ship
all five layers at "block" on day one.

## Squad-by-squad sequence

| Week | Payments-SWAT | KYC-SWAT | FX-SWAT | Treasury-SWAT | Platform-SWAT |
|---|---|---|---|---|---|
| 1-2 | Shadow all 5 | - | - | - | Block all 5 (eats own dogfood) |
| 3-4 | Warn all 5 | Shadow all 5 | - | - | Block |
| 5-6 | Block all 5 | Warn | Shadow | - | Block |
| 7-8 | Block | Block | Warn | Shadow | Block |
| 9+ | Block | Block | Block | Warn -> Block | Block |

Platform-SWAT (the team owning this pipeline) ships in block mode from
week 1 -- credibility comes from running the gate against ourselves first.

## Exception handling

There is no in-repo exception path. A CRITICAL or HIGH finding that the
squad believes is a false positive or genuinely needs to ship before
remediation goes through the security-platform team out-of-band:

- **False positive in a tool ruleset** -- security-platform tunes the
  rule (e.g., add an allowlist anchor in `.gitleaks.toml`, narrow a
  Semgrep pattern). PR back through this repo with the rule change so
  the suppression is itself reviewable evidence, not an opaque ID.
- **Genuine "ship before fix"** -- escalate to the security-platform
  lead. If approved, the unblock is a temporary scope narrowing in
  `factory/pipeline/config.yaml` (e.g., drop the layer to `severity:
  MEDIUM`) with a tracking issue and a calendar reversion date. We
  prefer a visible config change over a silent exemption table.

## DevEx commitments (what the squads can hold us to)

1. **One pipeline, one place.** All findings land in GitHub code-scanning.
   No "go check the Snyk dashboard" or "log into Trivy SaaS."
2. **Findings ship with fix hints.** Each custom policy includes a
   `remediation` field linking to an internal runbook (v2).
3. **No surprise blocks.** A gate change that moves a scanner from Warn to
   Block requires 1 week's notice in #plat-security + a heads-up to squad
   leads.
4. **Pre-commit hook offered.** v2 ships a `pre-commit` config so devs see
   findings locally in seconds, not after CI runs.
5. **Security-team SLA on triage.** New CRITICAL findings get a security-team
   response within 1 business day; if we miss it, the gate fails open for
   that finding for 24 h. (We hold ourselves accountable to the same gate.)

## Failure modes we expect and how we handle them

- **Trivy false positive blocks a release.** Squad files an issue
  against the security-platform team; security-platform tightens the
  Trivy invocation (severity floor, ignore list against a specific
  CVE+package) via PR to `factory/pipeline/scanners/trivy-fs.sh` so the
  suppression is reviewable. Real fix tracked in the squad backlog.
- **A scanner goes down (SaaS or Action outage).** The gate fails closed:
  it reads the expected scanner list from `config.yaml` and errors on any
  missing SARIF (a crashed scanner is never a silent pass). The unblock
  path during an outage is a temporary entry removal from `config.yaml`
  with a tracking ticket -- the absence is visible in git history.
  Outage > 4 h triggers an incident.
- **An auditor asks "show me proof".** SARIF + SBOM artifacts retained 90 d
  on GH; older runs archived to S3 with Object Lock (v2).
