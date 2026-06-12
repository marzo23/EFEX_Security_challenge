# LLM_README -- how this project was developed with AI assistance

This file exists because I think it's the honest way to ship work that
was built with LLM help. The README's "Tool selection" section already
discloses the use at a high level; this file is the receipts.

If you're reviewing this submission and want to understand exactly
where AI was the driver vs. where I was, this is the document.

---

## What I used

- **Model:** Claude (Anthropic) -- primarily Opus-class models for the
  larger structural passes, mixed with Sonnet for tighter edits.
- **Harness:** Claude Code (the official CLI), which gives the model
  access to filesystem read/write, bash, and inline diffing against
  the working tree. No bespoke agent framework; just the standard CLI.
- **Verification:** every claim the model made about tool behaviour was
  reproduced by me locally against the actual tool (in containers, since
  my laptop only had `docker` + `python3` + `jq` installed). The
  reproduction commands are documented inline below.

I did not use AI for: tool selection (I checked candidates I have
previously worked with against the seed myself), the regulatory mapping
to CNBV CUIFPE / SOC 2 controls, and the high-level structure of the
supply-chain threat model.

---

## The Process

The project went through two distinct phases. The first was initial
scaffolding (vulnerable seed + pipeline + first-pass docs); the second
was an iterative review -> remediate -> verify loop. The prompts below
are the actual user inputs that drove each pass.

### Phase 1 -- initial scaffolding

Built the deliberately-vulnerable seed (FastAPI + Dockerfile + Terraform),
the multi-layer pipeline skeleton (gitleaks/Semgrep/Trivy/Checkov/
OPA-Conftest/Syft), the gate (`evaluate_gate.py`), the catalog
(`catalog.yaml`), the per-framework control YAMLs, and the first-cut
docs (threat model, regulatory mapping, rollout plan, cost analysis).

**Prompt 1.1 -- vulnerable seed.**

> Build a vulnerable Python/FastAPI service standing in
> for a SPEI payments microservice. It has to exercise every pipeline
> layer: secrets, SAST, SCA, IaC, container.
>
> - Each defect maps 1:1 to a real CWE and a concrete scanner rule.
> - CVEs must be real and publicly disclosed; prefer transitives.
> - Dockerfile violates multiple CIS Docker items, not just root user.
> - Terraform violates at minimum: no encryption-at-rest, wildcard
>   IAM, public S3, and `0.0.0.0/0` SG ingress on a non-standard port.
> - App logic includes a real f-string SQLi (taint analysis must see
>   the flow), a hardcoded JWT key, and a CLABE logged cleartext.
>
> Out of scope: working auth, realistic SPEI semantics. This is
> detection surface, not production fidelity.

**Prompt 1.2 -- pipeline skeleton.**

> Build the GitHub Actions pipeline: secrets, SAST, SCA, IaC,
> container, SBOM. The supply-chain threat model already exists
> (TM-SUP-* IDs); wire the mitigations.
>
> - `permissions: contents: read` at workflow level; each job
>   re-declares only what it needs.
> - Scanner binaries: version-pinned release-asset downloads only.
>   No `curl | sh` (TM-SUP-01).
> - Third-party Actions pinned by commit SHA (TM-SUP-02).
> - Matrix expanded from `factory/pipeline/config.yaml` -- adding a
>   scanner is a one-line config edit, not a workflow edit.
> - `fail-fast: false`. Gate fail-closes on a missing SARIF
>   independently of severity (TM-SUP-06).
> - PR-blocking path must fit the 1-hour Lead Time budget. Flag risks
>   and call out what to parallelise.
>
> Out of scope this pass: cosign, SLSA provenance, S3 evidence --
> separate pass once the gate is green.

**Prompt 1.3 -- custom policies.**

> The brief asks for custom business policies, not defaults. Write
> four, each with a positive fixture (must fail), a negative fixture
> (must pass), and a `conftest verify` test:
>
> 1. `EFEX_DOCKER_001` -- non-root `USER` required. Stock
>    `CKV_DOCKER_8` is inconsistent on Dockerfiles with no `USER` at
>    all; write a custom Checkov check. Register via
>    `factory/policies/checkov/__init__.py` -- without it the check
>    loads but never executes (silent fail).
> 2. `EFEX_OPA_001` -- S3 encryption-at-rest. Handle the TF >= 4.x
>    split (`aws_s3_bucket_server_side_encryption_configuration` as a
>    separate resource, not an inline block).
> 3. `EFEX_OPA_002` -- no IAM `Action:"*"` + `Resource:"*"`. Walk the
>    configuration graph, not `resource_changes[].change.after` --
>    `after` is null at plan time for new resources and a
>    `change.after`-only rule false-negatives on every greenfield plan.
>    Fixture must mimic a real plan with `after_unknown` set.
> 4. `EFEX_OPA_003` -- no `0.0.0.0/0` SG ingress on ports other than
>    80/443.
>
> Add a `policy-tests` CI job that runs BEFORE the scan matrix. A
> broken policy must fail loudly there, not silently scan nothing.
>
> Each policy ends with a comment naming the SOC 2 CC / CNBV CUIFPE
> control it attests to. Don't overclaim -- if it doesn't attest, say
> so explicitly.

**Prompt 1.4 -- threat models.**

> Two threat models. STRIDE on the service; supply-chain on the
> pipeline. Pipeline IDs (`TM-SUP-01..06`) cover: scanner installer,
> third-party Action, application dep, evidence tampering, image
> substitution, gate bypass via crashed scanner. Each has the
> mitigation that's wired into the workflow.
>
> Per-decision rationale (OSS vs. managed scanners, SARIF as evidence
> format, Conftest vs. Sentinel, cosign keyless vs. KMS-keyed,
> GitHub-native attestations vs. raw SLSA) lives inline in the
> threat-model doc as a "decisions and trade-offs" section. Each
> decision states the positive and negative consequences -- no
> silent trade-offs.

### Phase 2 -- review -> remediate -> verify

This phase is the discipline that distinguishes "AI wrote it" from "AI
wrote it and it ships." Each audit ran in a fresh session so the model
couldn't lean on its own prior framing.

**Prompt 2.1 -- first independent audit.**

> Fresh context -- no prior familiarity with this repo. You're a Staff
> Security Engineer reviewing a DevSecOps factory destined for IFPE /
> SOC 2 evidence. Find what a reviewer at a regulated fintech rejects
> on.
>
> Write `ANALYSIS.md` covering:
> - Defects that would fail an IFPE inspector or SOC 2 auditor. Cite
>   the specific control, not "compliance issue."
> - Pipeline correctness defects: gate silently passes, swallowed
>   exit codes, false-negative custom rules, unverified installers.
> - Regulatory overclaim: every "attests to control X" claim
>   verified against what the policy actually inspects.
> - `TM-SUP-*` gaps: mitigation documented vs. mitigation wired in.
> - Tier each finding P0 / P1 / P2.
>
> Do not propose fixes -- separate pass. If you can't reproduce with a
> command, tier it lower.

**Prompt 2.2 -- apply the fixes.**

> Apply the P0 and P1 fixes from `ANALYSIS.md`. For each: code change
> + regression fixture + container-run verification command pasted
> into an appendix. "Should work" isn't done.
>
> Three non-negotiables land in this pass:
> - Supply chain: cosign keyless signing + `actions/attest-build-provenance@v2`
>   + `actions/attest-sbom@v2`. Verify with `gh attestation verify`.
>   Push-to-main only.
> - Evidence: S3 + Object Lock (compliance mode, 1-year), OIDC-bound
>   writer role, no static AWS creds in CI.
> - Pre-commit: `.pre-commit-config.yaml` with gitleaks + checkov +
>   Dockerfile build smoke, plus `make pre-commit-install` for
>   one-command squad onboarding.

**Prompt 2.3 -- second independent audit.**

> Fresh context. Treat the fixes as part of the codebase. Probe:
>
> - Do the OPA policies actually load under the pinned conftest
>   version? First-draft Rego often uses `import future.keywords`,
>   which parse-errors at v0.55+ -- `policy-tests` would be green only
>   because nobody ran it.
> - Does `EFEX_DOCKER_001` fire on all three Dockerfile fixtures
>   (no_user / root_user / nonroot_user)?
> - Does the gate exit 2 on a missing SARIF? Synthesise an evidence
>   dir with one scanner removed.
> - Does the gate normalise `security-severity` numerically? It's a
>   score string (`"9.8"`), not a level enum -- a string-keyed lookup
>   falls back to rank 0 and the finding *passes*.
> - Does `terraform plan` run in CI without AWS creds?
> - Any `curl | sh` left anywhere in `.github/workflows/`?
>
> Output to `VERIFICATION.md`: pass/fail, command, root cause on fail.
> Same no-fixes discipline.

**Prompt 2.4 -- patch the verification gaps.**

> Fix every `FAIL` in `VERIFICATION.md`:
> - Rego: migrate to `import rego.v1`. Load the lib via `--policy`,
>   not `--data` -- `--data` makes it a document, not a module.
> - `EFEX_OPA_002`: walk `configuration.root_module.resources[]` for
>   plan-time unknowns. Fixture with `after_unknown.policy: true`.
> - Custom Checkov: add `factory/policies/checkov/__init__.py` so
>   the registry actually picks the check up.
> - Gate severity: parse `security-severity` as float, map
>   `>=9.0/>=7.0/>=4.0/else`. Fall back to SARIF `level` only when
>   absent.
> - TF plan in CI: ship `provider_override.tf` with a mocked AWS
>   provider so plan is credential-free.
> - Seed dep pin: `requests==2.25.1` for CVE-2023-32681. Inline
>   comment naming the CVE.
>
> Each fix re-runs its tool against the fixture; output appended to
> `VERIFICATION.md` with a `RESOLVED` marker.

**Prompt 2.5 -- Red / Green walkthrough.**

> Wire two demos an auditor walks through in 10 minutes:
> `demo/failing/` (gate breaks the build) and `demo/passing/` (fixes
> only, same endpoints / TF resources / Dockerfile structure, gate
> passes).
>
> Both run locally without GHA -- `docker compose run --rm <scanner>`
> against digest-pinned images. Failing demo produces one finding per
> detection class, no duplicates. Compliance report renders correctly
> for both.

**Prompt 2.6 -- rollout & DevEx.**

> Draft `docs/rollout.md` answering the brief's framing question:
> how is the secure path the easy path?
>
> - Gate graduation: block day 1 vs. warn for N sprints, scheduled on
>   sprint boundaries.
> - Waivers: file-based, time-boxed, owner-attributed,
>   auto-expiring. No permanent suppressions. Include the YAML schema
>   and the CI check that rejects expired / unowned waivers.
> - Per-policy `OWNERS` so a noisy rule has a documented person to
>   escalate to.
> - DevEx: pre-commit, `make scan` matching CI image digests,
>   `make explain <finding>` for in-terminal remediation.
> - Cost: prod monthly at 25 engineers, with assumptions stated.
>
> Every section ends with the developer experience it produces, not
> the control it implements. If it reads as process, rewrite it.

**Prompt 2.7 -- local parity with CI.**

> Top-level `docker-compose.yml`: a service per scanner + gate +
> report + seed + ZAP. Images pinned by digest. Scanners mount the
> repo read-only and write SARIF into a named volume the gate
> consumes. `make local-pipeline` runs the full chain and matches CI
> exit semantics -- green local implies green CI.

**Prompt 2.8 -- submission rewrite.**

> Rewrite the README as a first-person submission. The current draft
> reads as a planning document -- "[OK] delivered," `v2.0 -> v2.1 ->
> v2.2`, "this iteration." Cut all of it.
>
> Required sections: problem framing (EFEX, Lead Time, why one
> scanner isn't enough); tool selection criteria (OSS vs. managed
> explicit, with rationale and trade-offs inline); tested vs.
> asserted matrix
> (per layer: what it catches, what it provably doesn't, where the
> false-positives live); out-of-scope with one-sentence reasons; AI
> disclosure pointing at `LLM_README.md`; how to run.
>
> Delete `ANALYSIS.md`, `VERIFICATION.md`, the iteration narrative,
> v2.x markers. The submission is the snapshot, not the journal.
