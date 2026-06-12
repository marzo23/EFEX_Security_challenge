# EFEX Secure Software Factory

A DevSecOps pipeline + quality gate + custom policy-as-code wrapped
around a deliberately vulnerable FastAPI/Terraform seed, designed to be
runnable by a Mexican fintech under IFPE authorisation and readable by
a SOC 2 auditor. Long version: [`README.md`](./README.md). AI
disclosure + prompt log: [`LLM_README.md`](./LLM_README.md).

## Tool selection

OSS-first, SARIF native, custom-rule capable, no per-seat SaaS, runs on
a developer laptop:

| Layer | Tool | Custom rule |
|---|---|---|
| Secrets | gitleaks | `efex-hardcoded-signing-secret` (low-entropy JWT keys the defaults miss) |
| SAST | Semgrep + p/python + p/owasp-top-ten + p/fastapi | `efex-py-001-fstring-sql-execute` (two-step f-string SQLi taint) |
| SCA | Trivy fs | -- |
| IaC defaults | Checkov (1k+ rules) | -- |
| IaC custom | OPA / Conftest | `EFEX-OPA-001` (no IAM `*:*`), `EFEX-OPA-002` (SSE on payment-data S3) |
| Container | Trivy image + Checkov dockerfile | `EFEX_DOCKER_001` (fires on missing USER, not just `USER root`) |
| SBOM | Syft -> CycloneDX | -- |
| Signing | cosign keyless + SLSA L2 + SBOM attestation (Sigstore Fulcio/Rekor) | -- |
| DAST | OWASP ZAP baseline (PR, warn-mode) | -- |
| Evidence | S3 + Object Lock (COMPLIANCE, 7y) on push to main | -- |

Rejected: Snyk (SaaS, per-developer at 25 engineers), SonarQube
(heavier infra), GHAS/CodeQL (per-seat license + lock-in).

## AI / LLM use

Built with Claude as a working partner throughout, openly. Where it
helped: scaffolds, cross-framework regulatory lookups, two independent
audit passes that caught defects (Rego v1 syntax, gate CVSS hole,
missing `__init__.py`, plan-time-unknown false positive). Where I
overrode: regulatory overclaims (signing -> PCI 6.4.2 is wrong; that's
WAF), `curl|sh` install snippets that contradicted my own threat
model, subtle Rego defects that passed fixtures but failed real plans.
Every tool-behaviour claim was reproduced locally before being
believed. Full prompt log + reflection: [`LLM_README.md`](./LLM_README.md).

## How to run

Easiest path -- Docker only:

```bash
mkdir -p evidence
docker compose run --rm gitleaks            # one scanner
docker compose run --rm conftest-verify     # OPA policy self-tests (9/9 fixtures)
docker compose run --rm gate                # evaluate the gate
docker compose run --rm report              # render compliance report
docker compose up seed-service              # vulnerable FastAPI for manual DAST
```

Other tiers (Python-only gate, single-scanner CLI, GitHub Actions) in
the long README.

## Failing / passing demo

`main` ships the failing state -- gate blocks on 36 findings across 4
layers including the custom checks. Round trip:

```bash
demo/passing/apply.sh    # flip to passing
demo/failing/apply.sh    # flip back (hash-identical to main)
```

Pre-rendered reports for both states at
`demo/{failing,passing}/sample-compliance-report.md`.

## Test cases

Twelve seeded vulnerabilities (`VULN-001..013`, 009 unused), each with
an explicit detector. The matrix lives in the long README; the headline
ones:

- SQL injection via f-string -> caught by custom Semgrep taint rule
- Hardcoded JWT secret -> caught by custom gitleaks rule
- IAM `Action="*" Resource="*"` -> caught by `EFEX-OPA-001`
- S3 bucket holding SPEI data without SSE -> caught by `EFEX-OPA-002`
- Container with no `USER` -> caught by `EFEX_DOCKER_001`

Plus regression tests for the gate itself: CVSS normalization,
missing-scanner fail-closed, empty SARIF passes. All verified locally
with the actual tools.

## Out of scope

Live AWS deployment, runtime CSPM/EDR, application authn/authz on the
seed, production secrets-manager wiring, network/VPC design,
TLS-in-transit OPA rule (v3), SLSA L3 hermetic builder (currently L2),
Spanish-localised compliance report, SIEM ingestion beyond the webhook
stub.

## Deeper docs

- [`docs/threat-model.md`](./docs/threat-model.md) -- STRIDE on app +
  pipeline (TM-SUP-01..06: compromised Action, typosquat, post-build
  tamper, gate insider edit, runner reuse, evidence tampering).
- [`docs/regulatory-mapping.md`](./docs/regulatory-mapping.md) --
  ISO 27001 / PCI DSS / SOC 2 / CNBV CUIFPE control coverage.
- [`docs/rollout-plan.md`](./docs/rollout-plan.md) -- shadow -> warn ->
  block, dogfood-first, exception handling, DevEx SLAs.
- [`LLM_README.md`](./LLM_README.md) -- the prompts that drove
  development + verification discipline.
