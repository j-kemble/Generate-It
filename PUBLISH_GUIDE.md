# Publishing Generate-It to PyPI

This guide walks through the process of publishing Generate-It to PyPI (Python Package Index) so users can install it with `pip install generate-it`.

## One-time Setup

### 1. Create PyPI Account

1. Go to https://pypi.org/account/register/
2. Create a new account with your username and password
3. Verify your email address

### 2. Create API Token (recommended over password)

This is more secure than using your password directly.

1. Log in to https://pypi.org
2. Go to Account Settings → API tokens
3. Click "Add API token"
4. Name it something like "Generate-It Release Token"
5. Scope: "Entire account"
6. Copy the token (starts with `pypi-`)

### 3. Install Build Tools

```bash
pip install --upgrade build twine
```

## Publishing a Release

### 1. Update Version

Edit `pyproject.toml` and bump the version:

```toml
[project]
version = "0.1.1"  # Change this
```

### 2. Commit and Tag

```bash
git add pyproject.toml
git commit -m "Bump version to 0.1.1

Co-Authored-By: Warp <agent@warp.dev>"

git tag v0.1.1
git push origin main
git push origin v0.1.1
```

### 3. Build Distribution Files

```bash
python -m build
```

This creates:
- `dist/generate_it-0.1.1.tar.gz` (source distribution)
- `dist/generate_it-0.1.1-py3-none-any.whl` (wheel distribution)

### 4. Upload to PyPI

Using your API token (replace `YOUR_TOKEN_HERE`):

```bash
python -m twine upload dist/generate_it-0.1.1.tar.gz dist/generate_it-0.1.1-py3-none-any.whl \
  --username __token__ \
  --password YOUR_TOKEN_HERE
```

Or create a `~/.pypirc` file for easier uploads:

```ini
[distutils]
index-servers =
    pypi

[pypi]
username = __token__
password = pypi-YOUR_TOKEN_HERE
```

Then simply:

```bash
twine upload dist/*
```

### 5. Verify

Check that your package appears on PyPI:
https://pypi.org/project/generate-it/

Test installation on another machine (or in a fresh venv):

```bash
pip install generate-it
generate-it
```

## Notes

- Keep your API token private—never commit it to git
- Test in a fresh virtual environment before publishing to ensure all dependencies are correct
- You can also publish to TestPyPI first to test the workflow: https://test.pypi.org
- To use TestPyPI, add the extra index in setup: `twine upload --repository testpypi dist/*`

## GitHub Actions (Optional)

To automate releases, you can set up GitHub Actions to build and publish when you create a tag:

1. Create `.github/workflows/publish.yml`
2. Add your PyPI API token as a GitHub secret named `PYPI_API_TOKEN`
3. Workflow will trigger on new version tags and publish automatically

Let me know if you'd like help setting this up!
