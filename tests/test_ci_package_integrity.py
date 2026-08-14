from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_security_workflow_checks_changed_commit_range() -> None:
    content = (REPO_ROOT / ".github" / "workflows" / "security.yml").read_text()
    assert "github.event.pull_request.base.sha" in content
    assert 'git diff --check "${{ github.event.before }}...${{ github.sha }}"' in content


def test_security_workflow_smoke_tests_built_wheel_imports() -> None:
    content = (REPO_ROOT / ".github" / "workflows" / "security.yml").read_text()
    assert "Smoke-test built wheel" in content
    assert "import generate_it.storage, generate_it.tui" in content
