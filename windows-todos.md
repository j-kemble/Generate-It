# Windows CI Lockfile Setup — TODO

**Status:** `constraints/ci-windows.txt` is a placeholder (comments only, no packages listed). Windows has been **temporarily removed** from the CI matrix in `.github/workflows/security.yml` until the real lockfile is generated on a Windows machine.

**Date:** 2026-07-11
**Context:** Finding F-023 — the Windows CI lockfile could not be generated on macOS/Linux because `windows-curses` only resolves on Windows. The placeholder `ci-windows.txt` causes `pip install --require-hashes` to fail (no packages + `--require-hashes` = error).

---

## Current State

- `constraints/ci-windows.in` exists and extends `ci.in` with `windows-curses`.
- `constraints/ci-windows.txt` is a **placeholder** — it contains only explanatory comments and no package pins or hashes.
- The GitHub Actions matrix in `.github/workflows/security.yml` runs only on `ubuntu-latest` and `macos-latest`. `windows-latest` has been removed.
- The Windows-specific conditional `pip install` block that referenced `ci-windows.txt` has been removed from the workflow.

## Steps to Generate the Real Lockfile and Re-enable Windows CI

These steps must be performed on a **real Windows machine**. The user's Pip machine (AMD 9060 XT, Windows 11) is suitable.

### 1. Install pip-tools

```powershell
python -m pip install pip-tools
```

### 2. Generate the lockfile with hashes

From the repository root on the Windows machine:

```powershell
pip-compile --generate-hashes --output-file=constraints/ci-windows.txt constraints/ci-windows.in
```

This resolves `ci-windows.in` (which includes `ci.in` + `windows-curses`) and produces a fully pinned, hashed lockfile.

### 3. Verify windows-curses resolved

Check that `windows-curses` appears in the generated file:

```powershell
Select-String -Path constraints/ci-windows.txt -Pattern "windows-curses"
```

You should see a `windows-curses==X.Y.Z` line with its hash entries.

### 4. Commit the lockfile

```powershell
git add constraints/ci-windows.txt
git commit -m "ci: add Windows lockfile with hashes (generated on Win11)"
```

Push to the `development` branch (or open a PR).

### 5. Re-add `windows-latest` to the CI matrix

In `.github/workflows/security.yml`, update the matrix:

```yaml
      matrix:
        # Windows temporarily removed — see windows-todos.md
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.10", "3.12", "3.13"]
```

(Remove the "Windows temporarily removed" comment once re-enabled.)

### 6. Re-add the Windows-specific pip install block

In the "Install dependencies" step of the `test` job, restore the conditional:

```yaml
      - name: Install dependencies
        run: |
          if [ "${{ matrix.os }}" = "windows-latest" ]; then
            python -m pip install --require-hashes -r constraints/ci-windows.txt
          else
            python -m pip install --require-hashes -r constraints/ci.txt
          fi
          python -m pip install --no-deps -e .
```

> **Note:** This uses bash `if` syntax, which works because GitHub Actions Windows runners default to Git Bash. If the workflow is changed to use PowerShell, adjust the conditional accordingly.

### 7. Run CI to verify it passes

Push the changes and monitor the GitHub Actions run. Confirm the `windows-latest` jobs (all three Python versions) pass the test suite.

If the Windows job fails due to a missing hash or resolution error, re-run `pip-compile` on the Windows machine and re-commit.

---

## Machine Reference

- **Target machine:** AMD 9060 XT, Windows 11
- **Why Windows is required:** `pip-compile` resolves platform-specific wheels. `windows-curses` only has Windows wheels, so resolution fails on macOS/Linux.
