# Publishing Generate-It to PyPI

This guide walks through the process of publishing Generate-It to PyPI (Python Package Index) so users can install it with `pip install generate-it`.

## One-time Setup

### 1. Create PyPI Account

1. Go to https://pypi.org/account/register/
2. Create a new account with your username and password
3. Verify your email address

### 2. Set Up OIDC Trusted Publishing

This project uses PyPI OIDC trusted publishing instead of long-lived API tokens.
Trusted publishing allows PyPI to verify the GitHub Actions workflow identity directly,
without needing a secret token.

1. Log in to https://pypi.org
2. Go to your project → Settings → Publishing
3. Click "Add a new publisher"
4. Fill in:
   - **Owner:** `j-kemble`
   - **Repository:** `Generate-It`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`
5. Click "Add"

No API token is needed — PyPI verifies the OIDC identity of the GitHub Actions workflow
at upload time. The `publish.yml` workflow uses the `pypi` GitHub Environment, which can
be configured to require manual approval before releases.

> **Important:** The tag pushed must match the version in `pyproject.toml` (e.g., tag `v0.2.2`
> requires `version = "0.2.2"` in `pyproject.toml`). The `validate` job enforces this.

### 3. Install Build Tools

```bash
pip install --upgrade build twine
```

## Publishing a Release

### 1. Update Version

Edit `pyproject.toml` and bump the version:

```toml
[project]
version = "0.2.2"  # Change this
```

### 2. Commit and Tag

```bash
git add pyproject.toml
git commit -m "Bump version to 0.2.2 for release

Co-Authored-By: Oz <oz-agent@warp.dev>"

git tag v0.2.2
git push origin main
git push origin v0.2.2
```

### 3. Build Distribution Files

```bash
python -m build
```

This creates:
- `dist/generate_it-0.2.2.tar.gz` (source distribution)
- `dist/generate_it-0.2.2-py3-none-any.whl` (wheel distribution)

### 4. Push the Tag to Trigger Publishing

Pushing a version tag (e.g., `v0.2.2`) triggers the `publish.yml` workflow automatically.
No manual upload is needed — the workflow validates the tag, runs tests and security scans,
builds the distribution, and publishes to PyPI via OIDC trusted publishing.

> **Note:** The publish workflow requires approval via the `pypi` GitHub Environment if
> you have configured it with required reviewers. Check the "Actions" tab on GitHub for
> pending approvals.

### 5. Verify

Check that your package appears on PyPI:
https://pypi.org/project/generate-it/

Test installation on another machine (or in a fresh venv):

```bash
pip install generate-it
generate-it
```

## Notes

- This project uses PyPI OIDC trusted publishing — no API token is needed or stored
- Test in a fresh virtual environment before tagging a release to ensure all dependencies are correct
- Review the **Known Limitations** section in `README.md` (process-local brute-force lockout, indefinitely retained migration backups, and partial metadata sanitization) before preparing release notes.
- For TestPyPI trusted publishing, add the `testpypi` environment with `twine upload --repository testpypi dist/*`
- The publish workflow verifies that the git tag matches `pyproject.toml` version before proceeding
- The `pypi` GitHub Environment can be configured with required reviewers for manual release approval

## GitHub Actions (Already Set Up)

Automated workflows are configured in `.github/workflows/`:

**security.yml**: Runs cross-platform tests on Python 3.10/3.12/3.13 across Linux, macOS, and Windows; includes mypy, Bandit, pip-audit, actionlint, zizmor, TruffleHog, and dependency hash verification on pushes and pull requests.

**publish.yml**: Three-stage pipeline when a version tag is pushed (e.g., `v0.2.2`): (1) `validate` — confirms the tag matches `pyproject.toml`; (2) `test` — installs hash-locked dependencies, runs full test suite, Bandit, and pip-audit; (3) `build-and-publish` — builds via `python -m build --no-isolation`, validates with `twine check`, and publishes to PyPI via OIDC trusted publishing under the protected `pypi` environment.

### Setting Up Automated Publishing

1. Set up PyPI OIDC trusted publishing on your PyPI project (see "One-time Setup" above)
2. In your GitHub repository, go to Settings → Environments
3. Create an environment named `pypi`
4. Optionally, add required reviewers to the `pypi` environment for manual release approval
5. No API token or GitHub secret is needed — OIDC handles authentication automatically

### Usage

```bash
# Update version in pyproject.toml
# e.g., change version = "0.2.1" to version = "0.2.2"

git add pyproject.toml
git commit -m "Bump version to 0.2.2 for release

Co-Authored-By: Oz <oz-agent@warp.dev>"

git tag v0.2.2
git push origin main
git push origin v0.2.2
```

The GitHub Actions workflow will automatically:
1. Validate the tag matches the version in `pyproject.toml`
2. Run test suite and security scan (`bandit`)
3. Build the distribution packages
4. Validate the package with `twine check`
5. Publish to PyPI via OIDC trusted publishing

You can monitor progress in the "Actions" tab on GitHub.
