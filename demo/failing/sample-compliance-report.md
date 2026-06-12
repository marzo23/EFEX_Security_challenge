# Compliance Report

- Build SHA: `red-demo`
- Generated: 2026-06-08T18:30:58+00:00
- Severity floor: HIGH

## Summary

| Framework | Total | [OK] Passing | [X] Failing | [!] Partial |  Uncovered |
|---|---:|---:|---:|---:|---:|
| ISO/IEC 27001:2022 | 15 | 0 | 9 | 3 | 3 |
| PCI DSS v4.0 | 17 | 1 | 12 | 3 | 1 |
| SOC 2 Trust Services Criteria (2017, rev 2022) | 7 | 0 | 5 | 2 | 0 |
| CNBV/IFPE CUIFPE + Banxico Circular 4/2017 | 6 | 0 | 3 | 2 | 1 |

## ISO/IEC 27001:2022

| Control | Title | Status | Covered by |
|---|---|---|---|
| `A.5.15` | Access control | [X] FAILING | `EFEX-OPA-001`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `A.8.2` | Privileged access rights | [X] FAILING | `EFEX-OPA-001` |
| `A.8.3` | Information access restriction | [X] FAILING | `EFEX-OPA-001` |
| `A.8.8` | Management of technical vulnerabilities | [X] FAILING | `SCANNER:sca-python`, `SCANNER:container-image` |
| `A.8.9` | Configuration management | [X] FAILING | `SCANNER:iac-defaults-aws` |
| `A.8.15` | Logging | [!] PARTIAL | `SCANNER:evidence-retention` |
| `A.8.24` | Use of cryptography | [X] FAILING | `EFEX-OPA-002`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `A.8.25` | Secure development lifecycle |  UNCOVERED | -- |
| `A.8.26` | Application security requirements | [X] FAILING | `SCANNER:sast-python` |
| `A.8.27` | Secure system architecture and engineering principles | [X] FAILING | `EFEX_DOCKER_001`, `SCANNER:iac-defaults-aws`, `SCANNER:container-image` |
| `A.8.28` | Secure coding | [X] FAILING | `EFEX_DOCKER_001`, `SCANNER:secrets`, `SCANNER:sast-python` |
| `A.8.29` | Security testing in development and acceptance |  UNCOVERED | -- |
| `A.8.30` | Outsourced development | [!] PARTIAL | `SCANNER:supply-chain-signing` |
| `A.8.31` | Separation of development, test and production environments | [!] PARTIAL | `SCANNER:supply-chain-signing` |
| `A.8.32` | Change management |  UNCOVERED | -- |

## PCI DSS v4.0

| Control | Title | Status | Covered by |
|---|---|---|---|
| `2.2.1` | Configuration standards developed and applied | [X] FAILING | `EFEX_DOCKER_001`, `SCANNER:iac-defaults-aws`, `SCANNER:container-image` |
| `2.2.6` | System security parameters configured to prevent misuse | [X] FAILING | `EFEX_DOCKER_001`, `SCANNER:iac-defaults-aws` |
| `3.5.1` | PAN stored is rendered unreadable (encryption at rest) | [X] FAILING | `EFEX-OPA-002`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `3.5.1.1` | Encryption keys managed in accordance with documented procedures | [X] FAILING | `EFEX-OPA-002` |
| `4.2.1` | Strong cryptography during transmission over open networks |  UNCOVERED | -- |
| `6.2.1` | Bespoke software developed securely | [X] FAILING | `SCANNER:secrets`, `SCANNER:sast-python` |
| `6.2.4` | Engineering techniques to prevent common attacks (injection, XSS, etc.) | [X] FAILING | `SCANNER:sast-python` |
| `6.3.1` | Security vulnerabilities are identified | [X] FAILING | `SCANNER:sca-python`, `SCANNER:container-image` |
| `6.3.2` | Inventory of bespoke + third-party software maintained | [OK] PASSING | `SCANNER:sbom` |
| `6.3.3` | System components protected from known vulnerabilities via patches | [X] FAILING | `SCANNER:sca-python` |
| `6.4.1` | Public-facing apps protected against attacks (review/automated tools) | [X] FAILING | `EFEX_DOCKER_001`, `SCANNER:sast-python` |
| `6.4.2` | Public-facing apps have automated technical solution (WAF or equivalent) | [!] PARTIAL | `SCANNER:supply-chain-signing` |
| `7.2.1` | Access control model defined | [X] FAILING | `EFEX-OPA-001`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `7.2.4` | User account/access reviews at least every six months | [X] FAILING | `EFEX-OPA-001` |
| `7.2.5` | Application/system accounts have minimum privileges | [X] FAILING | `EFEX-OPA-001` |
| `10.3.4` | Audit logs protected from modification | [!] PARTIAL | `SCANNER:evidence-retention` |
| `11.3.1` | Internal vulnerability scans every 3 months | [!] PARTIAL | `SCANNER:evidence-retention` |

## SOC 2 Trust Services Criteria (2017, rev 2022)

| Control | Title | Status | Covered by |
|---|---|---|---|
| `CC6.1` | Logical/physical access controls restrict access | [X] FAILING | `EFEX-OPA-001`, `SCANNER:secrets`, `SCANNER:iac-defaults-aws`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `CC6.3` | Authorization aligned with role/responsibility | [X] FAILING | `EFEX-OPA-001` |
| `CC6.6` | Logical access for external users protected by encryption | [X] FAILING | `EFEX_DOCKER_001`, `SCANNER:sast-python`, `SCANNER:container-image` |
| `CC6.7` | Data in transit and at rest protected | [X] FAILING | `EFEX-OPA-002`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `CC7.1` | Detection of security events | [!] PARTIAL | `SCANNER:sbom`, `SCANNER:evidence-retention` |
| `CC7.2` | Anomalies are detected and acted upon | [X] FAILING | `SCANNER:sca-python`, `SCANNER:container-image` |
| `CC8.1` | Changes to systems are authorized, documented, tested, approved | [!] PARTIAL | `SCANNER:supply-chain-signing` |

## CNBV/IFPE CUIFPE + Banxico Circular 4/2017

| Control | Title | Status | Covered by |
|---|---|---|---|
| `48-I` | Confidentiality and integrity of data in transit and at rest | [X] FAILING | `EFEX-OPA-002`, `SCANNER:secrets`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `48-II` | Access control based on least privilege | [X] FAILING | `EFEX-OPA-001`, `EFEX_DOCKER_001`, `SCANNER:iac-custom-aws`, `SCANNER:iac-platform-aws` |
| `168` | Inalterable logs of critical operations | [!] PARTIAL | `SCANNER:evidence-retention` |
| `169` | Vulnerability management with documented remediation | [X] FAILING | `SCANNER:sca-python` |
| `170` | Pre-production security testing | [!] PARTIAL | `SCANNER:supply-chain-signing` |
| `Banxico 4/2017 6.4` | Encryption of sensitive information |  UNCOVERED | -- |

## Policy / Scanner statuses

| ID | Kind | Status | Failing findings |
|---|---|---|---:|
| `EFEX-OPA-001` | policy | FAILING | 1 |
| `EFEX-OPA-002` | policy | FAILING | 1 |
| `EFEX_DOCKER_001` | policy | FAILING | 1 |
| `SCANNER:secrets` | scanner | FAILING | 1 |
| `SCANNER:sast-python` | scanner | FAILING | 1 |
| `SCANNER:sca-python` | scanner | FAILING | 1 |
| `SCANNER:iac-defaults-aws` | scanner | FAILING | 2 |
| `SCANNER:iac-custom-aws` | scanner | FAILING | 2 |
| `SCANNER:container-image` | scanner | FAILING | 1 |
| `SCANNER:sbom` | scanner | PASSING | 0 |
| `SCANNER:iac-platform-aws` | scanner | PASSING | 0 |
| `SCANNER:supply-chain-signing` | scanner | UNRUN | 0 |
| `SCANNER:evidence-retention` | scanner | UNRUN | 0 |
