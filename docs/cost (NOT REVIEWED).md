# Cost — Secure Software Factory @ ~25 engineers

Stack baseline cost (2026 list prices) for a ~25-engineer fintech with
5 SWAT teams pushing ~30 PRs/day. All numbers MXN-neutral (USD list);
budgets assume a single AWS account for the demo.

## Per-month cost (steady state)

| Item | List | Realised at our scale | Notes |
|---|---:|---:|---|
| **OSS scanners** — gitleaks, Semgrep CE, Trivy, Checkov, OPA/Conftest, Syft, cosign | $0 | $0 | All Apache-2.0/MPL-2.0 OSS. |
| **GitHub Actions minutes** (free org) | $0 | ~$0–$300 | Free 50K min/mo on Team; we expect ~25K min/mo (≈4 min × 6 layers × 30 PRs × 22d). |
| **GHCR storage** | $0 first 50 GB | ~$0 | Image SHA-tagged + a `latest`; ≈300 MB × 90-day retention ≈ 10 GB. |
| **Dependabot** | $0 | $0 | Free on all GitHub plans, public + private. |
| **Sigstore Fulcio/Rekor** (cosign keyless) | $0 | $0 | Public good service; SLA matters for prod (see below). |
| **AWS — evidence bucket** (S3 + KMS + Object Lock) | usage | **~$5–$30** | ≈5 GB SARIF/SBOM/reports per month, tiering to Glacier IR at 90d, Deep Archive at 365d. KMS request volume dominates; bucket-key reduces by ~99%. |
| **AWS — KMS CMK** | $1/mo per key | **$1** | One CMK for payments + evidence (separate aliases). |
| **AWS — CloudWatch alarms** for bucket policy drift (v3) | $0.10/alarm | **<$1** | 3 alarms. |
| **Total (OSS-only)** | | **~$10–$35/mo** | |

## Costed alternatives we deliberately did NOT pick (and why)

| Option | List | Realised | Why not (today) |
|---|---:|---:|---|
| **Snyk Team** (SCA + container) | $25/dev/mo published | **~$1,500/mo** (25 × ~$60 effective) | Better UX than Trivy; SaaS data-egress concerns for SPEI metadata. Hold as fallback if Trivy FP-rate > 15%. |
| **GitHub Advanced Security — Code Security** | $30/committer/mo | **$750/mo** | CodeQL is excellent but per-seat scales painfully + lock-in. Semgrep covers the same SAST need at $0 up to 10 contributors. |
| **GitHub Advanced Security — Secret Protection** | $19/committer/mo | **$475/mo** | gitleaks at $0 covers the gate; push-protection is the nice-to-have that pushes us toward this in v3. |
| **Snyk Code** (SAST) | bundled with Snyk plans | included above | Same logic as SCA. |
| **Wiz / Lacework / CrowdStrike** runtime CSPM | $80–$250/host/mo | **$2,000–$10,000/mo** | Out of pipeline scope; planned for separate CSPM workstream once IFPE approved. |
| **HashiCorp Vault Enterprise** | seat-based | **$2,000+/mo** | AWS Secrets Manager covers the immediate need at ~$0.40/secret/mo. |
| **Self-hosted Sigstore stack** | infra cost | **$300–$500/mo** | Only worth it if public Sigstore SLA is insufficient for production verification path. |

## Cost vs. industry benchmark

IANS Research's 2025 financial-services security report puts cybersecurity
spend at **8–14% of IT budget** for fintechs in our band; for a 25-engineer
shop at ~$500K–$1M/mo all-in IT, security budget is **~$40K–$140K/mo**.

The OSS-first stack consumes **< 0.1%** of that envelope, leaving budget
headroom for:

1. A paid SCA (Snyk or GHAS) if we hit the FP threshold in §ADR-001.
2. Runtime CSPM (Wiz/Lacework/CrowdStrike) which an IFPE will almost
   certainly need before the first Banxico inspection.
3. A 24/7 MSSP (~$5K–$15K/mo for fintech tier) to backstop on-call.

## Operational baseline

| Resource | Quantity | Notes |
|---|---:|---|
| Security-platform team | 1 Staff + 1 Senior | Owns this factory; on-call for gate breakage SLA. |
| Squad security-champions | 5 (1/SWAT) | Triage waivers, push remediations into squad backlog. |
| Auditor face-time | 1× annual SOC 2 + 1× CNBV | Compliance report + SARIF artifacts ship the bulk of the evidence. |
| Toolchain lifecycle review | quarterly | Snyk-vs-Trivy FP-rate check; cost re-baseline. |

## Watch-items

- **CI minutes growth.** Above ~50K min/mo we cross from free → $0.008/min on Team. Profile the slowest matrix cells before that point.
- **GHCR egress.** Free up to 100 GB/mo of pulls; if downstream environments pull on every node-boot, we may need a registry mirror.
- **AWS data-transfer.** Evidence bucket is in-region; cross-region replication for DR doubles storage cost.
- **Sigstore Rekor.** Public-good infra; for prod verification consider mirroring critical attestations.

## Citations

- [Semgrep pricing](https://semgrep.dev/pricing/)
- [Snyk plans](https://snyk.io/plans/)
- [GitHub pricing — Advanced Security](https://github.com/pricing)
- [GitHub Actions minutes](https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions)
- [AWS S3 + KMS pricing](https://aws.amazon.com/s3/pricing/)
- [IANS Financial-Services Security Staffing 2025](https://www.iansresearch.com/resources/all-blogs/post/security-blog/2025/03/06/key-financial-services-security-staffing-impacts-in-2025)
