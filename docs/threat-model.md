# Threat Model -- EFEX Payments Service + Secure Factory Pipeline

**Scope:** v1 vulnerable seed (`service/`, `infra/terraform/`) plus the CI/CD
pipeline that builds and ships it (`.github/workflows/secure-pipeline.yml`).
Framework: lightweight STRIDE. Detailed quantitative scoring deferred to v2.

## Trust boundaries

```
[Developer laptop]  git push  [GitHub PR]
                                     
                                     
                         [GH Actions runner (ephemeral)]
                                     
              
                                                              
         [Container         [Terraform plan            [Artifact registry
          registry]          + apply (manual)]          (SBOM, SARIF)]
                                    
                                    
        [Kubernetes prod]      [AWS account: payments]
              
              
         [SPEI / Banxico]   trust boundary EFEX/external
```

## STRIDE -- application service (`service/`)

| ID | Threat | STRIDE | Vuln tag | Mitigation in pipeline |
|---|---|---|---|---|
| TM-APP-01 | Hardcoded JWT/API secret leaks via repo or logs | I | VULN-001 | gitleaks (Layer 1) |
| TM-APP-02 | SQL injection on `/clients/search` exfiltrates CLABEs | I, T | VULN-002 | Custom Semgrep rule `efex-py-001-fstring-sql-execute` (Layer 2 -- the OSS packs miss the two-step f-string pattern) |
| TM-APP-03 | Command injection on `/diag/ping` gives RCE on the pod | E, T | VULN-003 | Semgrep `subprocess-shell-true` (Layer 2) |
| TM-APP-04 | Dep with known CVE (pyyaml 5.3.1, requests 2.25.1) used in prod | E, I | VULN-004/005 | Trivy fs (Layer 3) + Dependabot (PLUS) |

## STRIDE -- container & infra (`service/Dockerfile`, `infra/`)

| ID | Threat | STRIDE | Vuln tag | Mitigation |
|---|---|---|---|---|
| TM-CONT-01 | Container runs as root -> host escape gives access to other tenants on the node | E | VULN-007 | Custom Checkov check `EFEX_DOCKER_001` (Layer 4) |
| TM-CONT-02 | Floating base image tag re-pulls to a different (possibly compromised) layer | T | VULN-006 | Trivy image scan; SBOM (Layer 5) |
| TM-IAM-01 | IAM policy with `Action="*" Resource="*"` is the blast radius for any one compromised credential | E | VULN-012 | Custom OPA `EFEX-OPA-001` (Layer 4) |
| TM-S3-01 | S3 bucket holding SPEI archive is public and unencrypted at rest | I | VULN-010/011 | Custom OPA `EFEX-OPA-002` + Checkov defaults (Layer 4) |
| TM-NET-01 | SG `0.0.0.0/0:22` is the front door for credential stuffing & 0-day SSH bugs | E | VULN-013 | Checkov `CKV_AWS_24` (Layer 4) |

## STRIDE -- supply chain & pipeline itself

These are the threats that distinguish Staff-level from Senior -- securing the
factory floor, not just the product coming off it.

| ID | Threat | Mitigation today | Gap (v2) |
|---|---|---|---|
| TM-SUP-01 | Compromised third-party Action steals `GITHUB_TOKEN` or injects code | `permissions:` minimum in workflow; Dependabot weekly auto-PRs for actions versions | Pin all `uses:` by SHA, not tag |
| TM-SUP-02 | Typosquatted PyPI package shipped via `requirements.txt` | Trivy fs flags known-bad; Dependabot daily auto-PRs surface drift; no positive identity check | Add `pip install --require-hashes` + `pip-audit` |
| TM-SUP-03 | Built image is swapped between build and deploy ("post-build tamper") | Image signed with cosign keyless on push; SLSA L2 build provenance + SBOM attested via actions/attest-* (Sigstore Fulcio/Rekor) | Move to SLSA L3 (hermetic builder); add admission-control verify in cluster |
| TM-SUP-04 | Insider modifies the gate to soft-fail without review | `evaluate_gate.py` and `config.yaml` live in the same repo (PR review required); CODEOWNERS routes `factory/policies/`, `factory/pipeline/`, `.github/` to `@efex/security-platform`; gate has no in-repo exception path so any "let it through" change is a visible config edit, not a silent exemption | Signed-commit enforcement on gate/config edits; branch protection blocking direct push |
| TM-SUP-05 | Self-hosted runner reuse leaks artifacts across jobs | Using GitHub-hosted runners (ephemeral) | If we move to self-hosted: per-job ephemeral runners |
| TM-SUP-06 | Evidence/audit artefacts deleted or modified after the fact to hide a breach | **v2.1: compliance evidence mirrored to S3 with Object Lock COMPLIANCE mode (7y retention); writer role limited to PutObject; no root override possible** | Cross-region replication for DR |

## Out of scope for v1

- Quantitative likelihood/impact scoring.
- Network-level threat model for the prod cluster.
- DAST (runtime exploit attempts) -- planned for v2 with ZAP baseline.
- Threats against Banxico-side endpoints (out of EFEX's blast radius).
