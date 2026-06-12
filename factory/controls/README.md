# Controls catalog

Machine-readable mapping of certification controls to the pipeline evidence
this factory produces. One file per framework:

| File | Framework | Scope |
|---|---|---|
| `iso27001.yaml` | ISO/IEC 27001:2022 Annex A | Subset relevant to the SDLC + pipeline |
| `pci-dss.yaml`  | PCI DSS v4.0 | Subset the pipeline can attest to |
| `soc2.yaml`     | SOC 2 Trust Services Criteria | Common Criteria CC6/CC7/CC8 |
| `cnbv-cub.yaml` | CNBV/IFPE CUIFPE + Banxico 4/2017 | Subset enforced by pipeline |

## Why YAML, not just prose

- The gate (v3) will read these to emit a per-build compliance report.
- Auditors get a single source of truth instead of three Markdown tabs that
  drift apart.
- Renaming a policy in `factory/policies/catalog.yaml` propagates -- the
  policy ID is the foreign key.

## Schema

```yaml
controls:                       # or `requirements:` or `criteria:` or `articles:`
  - id: <control id>
    title: <human title>
    pipeline_evidence:          # what the pipeline produces that satisfies this
      - "<one-line description, ideally pointing at a policy id>"
    related_policies: [...]     # IDs from policies/catalog.yaml (optional)
    gaps: [...]                 # acknowledged gaps the auditor needs to see
```

## Out of scope here

These catalogs cover only what the **Secure Software Factory** can attest
to. Organization-wide controls (HR, physical security, BCP, supplier
diligence) live in the company-wide ISMS.
