# Releasing Bulwark

Bulwark is a monorepo of five independently-published packages. This is the release checklist.

## Packages (publish order)

Publish **bulwark-core first** (the others depend on it), then the tools, then the meta-CLI:

1. `bulwark-core`
2. `airlock`
3. `warden`
4. `manifest`
5. `bulwark`

## One-time PyPI setup (Trusted Publishing)

For each of the five PyPI project names, configure **Trusted Publishing (OIDC)** so no tokens are
stored:

1. Create the project on PyPI (or reserve the name with a first manual upload).
2. In the project's *Publishing* settings, add a trusted publisher:
   - Owner: `mk12002`, Repository: `Bulwark`, Workflow: `release.yml`, Environment: `pypi`.
3. Create a GitHub Environment named `pypi` on the repo (Settings → Environments).

## Cutting a release

1. Ensure the tree is green:
   ```bash
   python check.py
   ```
2. Update `CHANGELOG.md`: move items from **Unreleased** into a new `## [X.Y.Z]` section with the date.
3. Bump `version` in each package's `pyproject.toml` (keep them in lockstep for a suite release).
4. Commit, then tag and push:
   ```bash
   git commit -am "Release vX.Y.Z"
   git tag vX.Y.Z
   git push && git push --tags
   ```
5. The `Release` workflow builds every package (`python -m build packages/<pkg>`), runs
   `twine check`, and publishes each to PyPI via OIDC. Watch the Actions run.

## Verifying a build locally (no upload)

```bash
python -m pip install --upgrade build twine
python -m build packages/bulwark-core --outdir /tmp/dist
python -m build packages/airlock      --outdir /tmp/dist
twine check /tmp/dist/*
```

## After release

- Confirm `pip install bulwark-suite` pulls in `bulwark-airlock`, `bulwark-warden`,
  `bulwark-manifest`, and `bulwark-core`.
- Update the GitHub release notes from the `CHANGELOG.md` section.
- Update the README badges / demo if anything user-facing changed.

## Versioning

Semantic Versioning. For v0.x, minor bumps may include additive detectors/rules; a new *category* of
finding or a breaking CLI change warrants a minor bump and a clear CHANGELOG entry.
