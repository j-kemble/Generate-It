from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _step(job: str, name: str) -> dict:
    for step in _workflow()["jobs"][job]["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"missing {job}/{name}")


def test_changed_range_check_fetches_history_and_handles_initial_push() -> None:
    data = _workflow()
    checkout = next(step for step in data["jobs"]["typecheck"]["steps"] if "checkout" in step["uses"])
    assert checkout["with"]["fetch-depth"] == 0
    run = _step("typecheck", "Check for trailing whitespace violations")["run"]
    assert 'github.event.pull_request.base.sha' in run
    assert 'github.event.before' in run
    assert '0000000000000000000000000000000000000000' in run
    assert "git diff --check" in run


def test_wheel_smoke_runs_from_outside_source_checkout() -> None:
    run = _step("build", "Smoke-test built wheel")["run"]
    assert "python -m venv" in run
    assert "pip install --require-hashes -r constraints/ci.txt" in run
    assert "pip install --no-deps dist/*.whl" in run
    assert "cd /tmp" in run or "working-directory" in run
    assert "generate_it.__file__" in run
    assert "site-packages" in run
    assert "generate_it.storage" in run
    assert "generate_it.tui" in run


def test_wheel_smoke_checks_packaged_resource_and_entry_point() -> None:
    run = _step("build", "Smoke-test built wheel")["run"]
    assert "generate_it.__main__" in run
    assert "wordlist.txt" in run
    assert "generate_it.storage" in run
    assert "generate_it.tui" in run


def test_first_push_diff_command_uses_empty_tree_range() -> None:
    run = _step("typecheck", "Check for trailing whitespace violations")["run"]
    assert "git hash-object -t tree /dev/null" in run
    assert "github.event.before" in run
    assert "github.sha" in run


def test_workflow_has_locked_installs_per_step() -> None:
    for job_name, job in _workflow()["jobs"].items():
        for step in job.get("steps", []):
            command = step.get("run", "")
            if "pip install" in command and "--no-deps -e ." not in command:
                assert "--require-hashes" in command, f"unlocked install in {job_name}/{step.get('name')}"
                assert "pip install --upgrade" not in command
