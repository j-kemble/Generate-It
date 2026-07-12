# Windows CI Lockfile Setup — TODO

**Status:** Complete. The hashed Windows lockfile was generated from the lowest CI Python version, Windows was restored to the CI matrix, the compatibility correction was committed and pushed, and hosted GitHub Actions passed for all Windows matrix versions.

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
- Hosted GitHub Actions run `29204957899` passed all jobs, including `windows-latest` on Python 3.10, 3.12, and 3.13.
- GitHub reported non-blocking runner annotations about Node.js 20 action deprecation and the future `macos-latest` image migration.

## Finalization completed

- Commit `17c0bdf` restored the Windows matrix and added the initial hashed lockfile.
- Follow-up commit `11e14b7` regenerated the lockfile from Python 3.10, fixing the Python 3.10 compatibility issue caused by `stevedore==5.9.0`.
- Both commits were pushed to `development`.
- Hosted run `29204957899` passed all checks.

## Reproduction notes

`constraints/ci-windows.in` extends `ci.in` with `windows-curses`. Regenerate the lockfile on Windows whenever either input file changes:

```powershell
py -3.10 -m pip install pip-tools
py -3.10 -m piptools compile --generate-hashes `
  --output-file=constraints/ci-windows.txt constraints/ci-windows.in
```

Do not generate this lockfile on macOS/Linux: `windows-curses` has Windows-only wheels and the resolver may not produce a usable Windows lock.
