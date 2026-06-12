"""Custom Checkov check -- EFEX_DOCKER_001.

Requires every production Dockerfile to declare a non-root USER explicitly.
Stricter than the default CKV_DOCKER_3 because we also forbid
``USER root`` / ``USER 0`` (some teams "satisfy" the default by setting
USER root explicitly).

Wire-up:
  checkov -d service/ --external-checks-dir policies/checkov --framework dockerfile

Reasoning: EFEX containers run alongside SPEI batch jobs; a root container
that escapes namespace boundaries gets host-level access to other tenants.
See docs/threat-model.md Container.
"""
from __future__ import annotations

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck


class DockerfileNonRootUser(BaseDockerfileCheck):
    def __init__(self) -> None:
        # "*" (not "USER"): an instruction-scoped check only runs when that
        # instruction EXISTS, so it could never flag a Dockerfile with no
        # USER at all -- the exact case this check is for.
        super().__init__(
            name="EFEX: Dockerfile must declare a non-root USER",
            id="EFEX_DOCKER_001",
            categories=(CheckCategories.GENERAL_SECURITY,),
            supported_instructions=["*"],
        )

    def scan_resource_conf(self, conf: dict[str, list[dict]]) -> tuple[CheckResult, list[dict] | None]:
        user_instructions = conf.get("USER")
        if not user_instructions:
            return CheckResult.FAILED, None

        last = user_instructions[-1]["value"].strip().lower()
        if last in {"root", "0", "0:0"}:
            return CheckResult.FAILED, user_instructions
        return CheckResult.PASSED, user_instructions


check = DockerfileNonRootUser()
