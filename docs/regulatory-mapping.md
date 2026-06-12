# Regulatory Mapping

For each control we owe an auditor, point to the **automated pipeline
evidence** that satisfies it. If a row says "manual" or "v3", that's debt
-- it should become automated by the next major iteration.

The machine-readable source of truth lives under `factory/controls/` --
one YAML per framework. This Markdown is the human-facing summary.

## Frameworks covered

| File | Framework | Audit driver |
|---|---|---|
| `factory/controls/iso27001.yaml` | ISO/IEC 27001:2022 Annex A | Org-wide ISMS certification |
| `factory/controls/pci-dss.yaml`  | PCI DSS v4.0 | When card/PAN scope expands |
| `factory/controls/soc2.yaml`     | SOC 2 (TSC 2017 r2022) | Customer trust + enterprise sales |
| `factory/controls/cnbv-cub.yaml` | CNBV/IFPE CUIFPE + Banxico 4/2017 | IFPE authorization |

## Quick view: every custom policy -> all four frameworks

| Policy | ISO 27001 | PCI DSS | SOC 2 | CNBV/IFPE |
|---|---|---|---|---|
| **EFEX-OPA-001** (no wildcard IAM) | A.5.15, A.8.2, A.8.3 | 7.2.1, 7.2.5 | CC6.1, CC6.3 | Art. 48-II |
| **EFEX-OPA-002** (SSE on payment storage) | A.8.24 | 3.5.1, 3.5.1.1 | CC6.7 | Art. 48-I; Banxico 4/2017 6.4 |
| **EFEX_DOCKER_001** (non-root containers) | A.8.27, A.8.28 | 2.2.1, 2.2.6, 6.4.1 | CC6.6 | Art. 48-II |

This table is auto-generatable from `factory/policies/catalog.yaml` -- v3
will ship the renderer.

## ISO/IEC 27001:2022 -- Annex A (subset enforced by this pipeline)

| Control | Title | Pipeline evidence |
|---|---|---|
| A.5.15 | Access control | EFEX-OPA-001 |
| A.8.2 | Privileged access rights | EFEX-OPA-001 |
| A.8.3 | Information access restriction | EFEX-OPA-001 + Checkov SG/NACL |
| A.8.8 | Management of technical vulnerabilities | Trivy fs + Trivy image; remediation tracked per finding in the squad backlog |
| A.8.9 | Configuration management | Checkov + EFEX_DOCKER_001 |
| A.8.15 | Logging | Evidence mirrored to S3 + Object Lock COMPLIANCE (push to main) |
| A.8.24 | Use of cryptography | EFEX-OPA-002 |
| A.8.25 | Secure development lifecycle | Multi-layer pipeline + gate |
| A.8.26 | Application security requirements | Semgrep OWASP + FastAPI rule packs |
| A.8.27 | Secure system architecture | EFEX_DOCKER_001 + threat model |
| A.8.28 | Secure coding | Semgrep + Gitleaks |
| A.8.29 | Security testing in dev and acceptance | Pipeline gates every PR |
| A.8.30 | Outsourced development | cosign keyless signing + SLSA provenance (push to main) |
| A.8.31 | Separation of environments | Promotion gated on green pipeline |
| A.8.32 | Change management | PR-only changes; CODEOWNERS routes sensitive paths to security-platform |

## PCI DSS v4.0 (subset)

| Req | Title | Pipeline evidence |
|---|---|---|
| 2.2.1 | Configuration standards developed and applied | Checkov + EFEX_DOCKER_001 |
| 2.2.6 | System security parameters configured | EFEX_DOCKER_001 |
| 3.5.1 | PAN rendered unreadable | EFEX-OPA-002 |
| 3.5.1.1 | Encryption keys managed per docs | EFEX-OPA-002 (KMS-source validation v3) |
| 4.2.1 | Strong cryptography in transit | Roadmap EFEX-OPA-003 |
| 6.2.1 | Bespoke software developed securely | Semgrep |
| 6.2.4 | Engineering techniques prevent injection/XSS | Semgrep `python.lang.security.audit.*` |
| 6.3.1 | Vulnerabilities identified | Trivy fs + Trivy image |
| 6.3.2 | Inventory of software maintained | Syft (CycloneDX SBOM per build) |
| 6.4.1 | Public-facing apps reviewed | SAST + roadmap ZAP DAST |
| 7.2.1 / 7.2.5 | Access model + least privilege | EFEX-OPA-001 |
| 10.3.4 | Audit logs protected | Evidence bucket: S3 Object Lock COMPLIANCE, 7y, write-only OIDC role |
| 10.5.1 | Audit log history retained >=12 months | 7y WORM retention + 90d GH artifacts |
| 11.3.1 | Internal vulnerability scans quarterly | Pipeline runs on every PR/push (exceeds the cadence); not claimed as formal scan-cadence evidence |

## SOC 2 -- Trust Services Criteria (subset)

| TSC | Title | Pipeline evidence |
|---|---|---|
| CC6.1 | Logical access controls | EFEX-OPA-001 |
| CC6.3 | Authorization aligned with role | EFEX-OPA-001 |
| CC6.6 | Encryption for external user access | EFEX_DOCKER_001 + roadmap TLS policy |
| CC6.7 | Data protected in transit and at rest | EFEX-OPA-002 + roadmap TLS policy |
| CC7.1 | Detection of security events | SARIF -> code-scanning; SIEM webhook forwarder (report job, main) |
| CC7.2 | Anomalies detected/acted upon | Gate blocks anomalies pre-merge |
| CC8.1 | Changes authorized/documented/tested | PR-only changes; CODEOWNERS on pipeline/policy paths; gate failures visible in PR checks |

## CNBV/IFPE (subset)

| Art. | Title | Pipeline evidence |
|---|---|---|
| 48-I | Confidentiality/integrity in transit and at rest | EFEX-OPA-002 |
| 48-II | Access control based on least privilege | EFEX-OPA-001 + EFEX_DOCKER_001 |
| 168 | Inalterable logs of critical operations | S3 + Object Lock COMPLIANCE evidence mirror (push to main); GH Actions audit log + SARIF artifacts as short-term ledger |
| 169 | Vulnerability management with documented remediation | Trivy + per-finding squad backlog tickets; compliance report mirrored to S3+Object Lock for the audit trail |
| 170 | Pre-production security testing | SAST + SCA + IaC + Container layers |
| Banxico 4/2017 6.4 | Encryption of sensitive information | EFEX-OPA-002 + Checkov defaults |

## v2 -> v2.1 closed gaps

1. [OK] **Provenance attestations** (ISO A.8.30/A.8.31, SOC2 CC8.1, CNBV 170):
   cosign keyless image signing + GitHub-native SLSA L2 build provenance +
   SBOM attestation, on every push to main.
2. [OK] **Evidence retention** (SOC2 CC7.1, CNBV Art. 168, PCI 10.3.4, ISO
   A.8.15): S3 + Object Lock COMPLIANCE mode (7y) in
   `factory/infra/aws/platform/evidence_bucket.tf`.
3. [OK] **DAST** (PCI 6.4.1): ZAP baseline in `.github/workflows/dast.yml`
   (non-blocking warn-mode on PRs touching `factory/service/`).
4. [OK] **Compliance report generator**: `factory/pipeline/report/compliance_report.py`
   emits per-build Markdown + JSON; sample at `demo/{red,green}/sample-compliance-report.md`.
5. [OK] **Dependabot** for `pip` + `github-actions` ecosystems
   (`.github/dependabot.yml`); pre-commit hooks
   (`.pre-commit-config.yaml`) covering secrets/format/Rego.

## Remaining v3 roadmap

1. **TLS-in-transit policy** (PCI 4.2.1, ISO A.8.24, SOC2 CC6.7): OPA rule
   EFEX-OPA-003 -- enforce TLS 1.2+ on ALB/NLB listeners.
2. **Real-time SIEM forwarding** (SOC2 CC7.1 incremental): SARIF webhook to
   the SOC's SIEM in addition to the WORM bucket already in place.
3. **SLSA L3** (hermetic builder + runtime verify via Kyverno / Connaisseur
   admission control).
4. **CNBV/IFPE compliance report Spanish localisation** (`compliance_report.py
   --lang es`).
5. **`pip install --require-hashes` + `pip-audit`** as additional supply-chain
   defence (TM-SUP-02 follow-through).
