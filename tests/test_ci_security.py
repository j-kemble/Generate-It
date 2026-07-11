"""Test CI security: immutable action pins, locked dependencies, platform constraints.

Phase 1 tests covering Tasks 1-4:
- All external action pins in tracked workflows must be 40-char hex SHAs
- CI installs consume hash-locked constraints and build with --no-isolation
- Runtime dependencies meet minimum versions (cryptography >= 44.0.0)
- Pre-commit hooks are pinned to commit SHAs, not tags
"""

import re
import subprocess
import sys
from pathlib import Path

try:
    from importlib import metadata
except ImportError:
    import importlib_metadata as metadata  # type: ignore[no-redef]

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"


def _tracked_workflows():
    """Return Paths to all tracked .github/workflows/*.yml files."""
    result = subprocess.run(
        ["git", "ls-files", "--", ".github/workflows/"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"git ls-files failed: {result.stderr}"
    paths = [REPO_ROOT / p.strip() for p in result.stdout.splitlines() if p.strip().endswith(".yml")]
    return [p for p in paths if p.exists()]


def _load_yaml(path: Path) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def _extract_external_uses(data: dict, current_path: str = "root") -> list[tuple[str, str]]:
    """Recursively extract (action_ref, context_path) for all external uses: entries."""
    results = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "uses" and isinstance(value, str):
                # Skip local actions (./path or just a filename)
                if not value.startswith("./") and "/" in value:
                    results.append((value, current_path))
            else:
                results.extend(_extract_external_uses(value, f"{current_path}.{key}"))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.extend(_extract_external_uses(item, f"{current_path}[{i}]"))
    return results


class TestImmutableActionPins:
    """All external action references in tracked workflows must be 40-char hex SHAs."""

    HEX_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

    def test_all_tracked_workflow_uses_are_40_hex(self):
        """Every external uses: value in tracked workflows must be exactly 40 lowercase hex chars."""
        failures = []
        for wf_path in _tracked_workflows():
            data = _load_yaml(wf_path)
            for action_ref, ctx in _extract_external_uses(data):
                sha = action_ref.split("@")[-1]
                if not self.HEX_SHA_RE.match(sha):
                    failures.append(f"{wf_path.name}:{ctx} uses={action_ref} (SHA={sha}, len={len(sha)})")
        if failures:
            msg = "\n  ".join(failures)
            raise AssertionError(f"Non-40-hex-SHA action pins found:\n  {msg}")

    def test_publish_workflow_setup_python_pin(self):
        """publish.yml must pin actions/setup-python to the verified v5.2.0 commit SHA."""
        path = WORKFLOW_DIR / "publish.yml"
        if not path.exists():
            return  # ok if file doesn't exist
        data = _load_yaml(path)
        uses_entries = [ref for ref, _ in _extract_external_uses(data)]
        setup_python_refs = [u for u in uses_entries if "actions/setup-python" in u]
        assert setup_python_refs, "No actions/setup-python reference in publish.yml"
        expected_sha = "f677139bbe7f9c59b41e40162b753c062f5d49a3"
        for ref in setup_python_refs:
            sha = ref.split("@")[-1]
            assert sha == expected_sha, (
                f"publish.yml actions/setup-python sha={sha}, expected={expected_sha} (v5.2.0)"
            )

    def test_publish_workflow_pypi_publish_pin(self):
        """publish.yml must pin pypa/gh-action-pypi-publish to the verified v1.9.0 commit SHA."""
        path = WORKFLOW_DIR / "publish.yml"
        if not path.exists():
            return
        data = _load_yaml(path)
        uses_entries = [ref for ref, _ in _extract_external_uses(data)]
        pypi_refs = [u for u in uses_entries if "pypa/gh-action-pypi-publish" in u]
        assert pypi_refs, "No pypa/gh-action-pypi-publish reference in publish.yml"
        expected_sha = "ec4db0b4ddc65acdf4bff5fa45ac92d78b56bdf0"
        for ref in pypi_refs:
            sha = ref.split("@")[-1]
            assert sha == expected_sha, (
                f"publish.yml pypa/gh-action-pypi-publish sha={sha}, expected={expected_sha} (v1.9.0)"
            )

    def test_security_workflow_checkout_pin(self):
        """security.yml must pin actions/checkout to the verified v5 commit SHA."""
        path = WORKFLOW_DIR / "security.yml"
        if not path.exists():
            return
        data = _load_yaml(path)
        uses_entries = [ref for ref, _ in _extract_external_uses(data)]
        checkout_refs = [u for u in uses_entries if "actions/checkout" in u]
        assert checkout_refs, "No actions/checkout reference in security.yml"
        expected_sha = "93cb6efe18208431cddfb8368fd83d5badbf9bfd"
        for ref in checkout_refs:
            sha = ref.split("@")[-1]
            assert sha == expected_sha, (
                f"security.yml actions/checkout sha={sha}, expected={expected_sha} (v5)"
            )

    def test_security_workflow_setup_python_pin(self):
        """security.yml must pin actions/setup-python to the verified v6.3.0 commit SHA."""
        path = WORKFLOW_DIR / "security.yml"
        if not path.exists():
            return
        data = _load_yaml(path)
        uses_entries = [ref for ref, _ in _extract_external_uses(data)]
        setup_python_refs = [u for u in uses_entries if "actions/setup-python" in u]
        assert setup_python_refs, "No actions/setup-python reference in security.yml"
        expected_sha = "ece7cb06caefa5fff74198d8649806c4678c61a1"
        for ref in setup_python_refs:
            sha = ref.split("@")[-1]
            assert sha == expected_sha, (
                f"security.yml actions/setup-python sha={sha}, expected={expected_sha} (v6.3.0)"
            )


class TestLockedCIDependencies:
    """CI jobs must install from hash-locked constraint files."""

    def test_security_yml_uses_require_hashes(self):
        """security.yml install steps must use --require-hashes with constraints files."""
        path = WORKFLOW_DIR / "security.yml"
        if not path.exists():
            return
        content = path.read_text()
        # Check that install steps use constraint files with --require-hashes
        assert "--require-hashes" in content, (
            "security.yml must use --require-hashes for hash-verified installs"
        )
        assert "constraints/ci.txt" in content, (
            "security.yml must install from constraints/ci.txt"
        )
        assert "--no-deps" in content, (
            "security.yml editable install must use --no-deps after locked install"
        )

    def test_publish_yml_uses_require_hashes(self):
        """publish.yml build job must install from hash-locked constraints/release.txt."""
        path = WORKFLOW_DIR / "publish.yml"
        if not path.exists():
            return
        content = path.read_text()
        assert "--require-hashes" in content, (
            "publish.yml must use --require-hashes for hash-verified installs"
        )
        assert "constraints/release.txt" in content, (
            "publish.yml must install from constraints/release.txt"
        )
        assert "--no-isolation" in content, (
            "publish.yml build must use --no-isolation after hash-verified backend install"
        )

    def test_no_unconstrained_pip_upgrade(self):
        """Workflows must not run 'pip install --upgrade pip' without constraints."""
        for wf_path in _tracked_workflows():
            content = wf_path.read_text()
            # Allow upgrade pip if constrained, but bare "pip install --upgrade pip" is a smell
            # We now use python -m pip install --require-hashes -r constraints/...
            # So we should not see bare "pip install --upgrade pip" lines
            if re.search(r"\binstall --upgrade pip\b", content):
                # Check it's used in conjunction with constraints
                if "--require-hashes" not in content:
                    raise AssertionError(
                        f"{wf_path.name}: found 'install --upgrade pip' without --require-hashes"
                    )


class TestRuntimeDependencyVersions:
    """Runtime dependencies must meet minimum security versions."""

    def test_cryptography_ge_44(self):
        """cryptography must be >= 44.0.0 (first release with Argon2id support)."""
        pyproject = REPO_ROOT / "pyproject.toml"
        content = pyproject.read_text()
        # Find the cryptography>= line
        match = re.search(r'"cryptography\s*>=\s*([^"]+)"', content)
        assert match, "cryptography dependency not found in pyproject.toml"
        version_str = match.group(1)
        version = tuple(int(x) for x in version_str.split("."))
        assert version >= (44, 0, 0), (
            f"cryptography>={version_str} found, expected >=44.0.0"
        )

    def test_windows_curses_in_windows_input(self):
        """constraints/ci-windows.in must include windows-curses for Windows platform coverage."""
        ci_win_in = REPO_ROOT / "constraints" / "ci-windows.in"
        assert ci_win_in.exists(), (
            "constraints/ci-windows.in must exist for Windows platform lock generation"
        )
        content = ci_win_in.read_text()
        assert "windows-curses" in content, (
            "constraints/ci-windows.in must include windows-curses for Windows platform lock generation"
        )

    def test_installed_cryptography_ge_44(self):
        """The installed cryptography package must satisfy >=44.0.0 (metadata check)."""
        try:
            dist = metadata.distribution("cryptography")
            version_str = dist.version
        except metadata.PackageNotFoundError:
            return  # Not installed; skip
        version = tuple(int(x) for x in version_str.split("."))
        assert version >= (44, 0, 0), (
            f"Installed cryptography=={version_str}, expected >=44.0.0"
        )


class TestPreCommitImmutablePins:
    """All pre-commit hook revisions must be 40-char commit SHAs, not tags."""

    HEX_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

    def test_all_precommit_revs_are_shas(self):
        """Every rev: entry in .pre-commit-config.yaml must be a 40-char hex SHA."""
        path = REPO_ROOT / ".pre-commit-config.yaml"
        if not path.exists():
            return
        data = _load_yaml(path)
        failures = []
        for repo in data.get("repos", []):
            rev = repo.get("rev", "")
            repo_name = repo.get("repo", "unknown")
            if not self.HEX_SHA_RE.match(rev):
                failures.append(f"  {repo_name}: rev={rev!r} (not a 40-char hex SHA)")
        if failures:
            msg = "\n".join(failures)
            raise AssertionError(f"Tag-based pre-commit revisions found:\n{msg}")
