<!-- Thanks for contributing to Bulwark! -->

## What this changes

<!-- A short description of the change and why. Link any issue: Closes #123 -->

## Type

- [ ] New detector / rule
- [ ] New importer / format
- [ ] Bug fix
- [ ] Docs
- [ ] Refactor / infra

## Checklist

- [ ] `python check.py` is green (ruff + mypy + pytest across affected packages)
- [ ] New detector? Ships with a **YAML rule**, a **benign fixture**, and a **test** asserting on
      `category` + `severity`
- [ ] No target code is executed/deserialized/imported (inspection only)
- [ ] Any "malicious" fixture uses **benign, inert** markers (no real malware, secrets, or exfil)
- [ ] Docs updated if behavior/flags changed (README / USAGE / PROJECT_REFERENCE_*)
- [ ] `CHANGELOG.md` updated under **Unreleased**

## Notes for reviewers

<!-- Anything non-obvious: tradeoffs, follow-ups, why an approach was chosen -->
