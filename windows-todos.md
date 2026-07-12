# Windows CI Lockfile Setup — TODO

**Status:** The Windows implementation is complete locally. The hashed Windows lockfile has been generated from the lowest CI Python version, Windows has been restored to the CI matrix, and the Windows dependency path has been verified in an isolated Python 3.10 environment. The remaining steps are to commit/push the compatibility correction and confirm the hosted GitHub Actions matrix.

**Context:** Finding F-023 — the Windows CI lockfile could not be generated on macOS/Linux because `windows-curses` only resolves on Windows. The placeholder `ci-windows.txt` caused `pip install --require-hashes` to fail because it contained no packages.

---

## Completed

- Generated `constraints/ci-windows.txt` on this Windows machine with Python 3.10, the lowest version in the CI matrix. Resolving from the lowest supported Python prevents newer releases such as `stevedore==5.9.0` (Python >=3.11) from breaking the Python 3.10 job:

  ```powershell
  uv run --no-project --python 3.10 --with "pip-tools==7.5.3" pip-compile --generate-hashes `
    --output-file=constraints/ci-windows.txt constraints/ci-windows.in
  ```

- Verified the lockfile contains `windows-curses==2.4.2` and its hashes. It contains 51 pinned packages and 791 package-hash entries.
- Restored `windows-latest` to the test matrix for Python 3.10, 3.12, and 3.13.
- Added shell-neutral conditional install steps in `.github/workflows/security.yml`:
  - Unix runners install `constraints/ci.txt`.
  - Windows runners install `constraints/ci-windows.txt`.
  - All runners install the package with `--no-deps -e .`.
- Fixed a Windows export failure where `os.fsync()` was called on a read-only descriptor. The export now flushes and syncs while the file is still open for writing.
- Made POSIX permission enforcement and permission-bit assertions explicitly POSIX-only.
- Made symlink security tests skip cleanly when the Windows runner lacks symlink privilege; they still run when symlinks are available.

## Verification completed

In a clean Windows Python 3.10 virtual environment, the following succeeded:

- `pip install --require-hashes -r constraints/ci-windows.txt`
- `pip install --no-deps -e .`
- `pip check` — no broken requirements
- `pytest tests/ -q` — **372 passed, 11 skipped**
- Workflow YAML parsing succeeded locally. `actionlint` was not installed, so GitHub-hosted Actions remains the final workflow-level check.

## Remaining steps

1. Review the working-tree diff.
2. Commit the changes, for example:

   ```powershell
   git add .github/workflows/security.yml constraints/ci-windows.txt `
     generate_it/logging.py generate_it/storage.py `
     tests/test_crypto_v2.py tests/test_logging.py tests/test_security_storage.py `
     windows-todos.md
   git commit -m "ci: restore Windows test matrix with hashed lockfile"
   ```

3. Push the branch or open a PR and confirm all three `windows-latest` jobs pass.
4. If a hosted Windows job reports a platform-specific dependency or test issue, reproduce it with the same Python version and update the lockfile or platform guard as appropriate.

## Reproduction notes

`constraints/ci-windows.in` extends `ci.in` with `windows-curses`. Regenerate the lockfile on Windows whenever either input file changes:

```powershell
py -3.10 -m pip install pip-tools
py -3.10 -m piptools compile --generate-hashes `
  --output-file=constraints/ci-windows.txt constraints/ci-windows.in
```

Do not generate this lockfile on macOS/Linux: `windows-curses` has Windows-only wheels and the resolver may not produce a usable Windows lock.
