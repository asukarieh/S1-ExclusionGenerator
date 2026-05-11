<!--
Thanks for the PR! Fill in the relevant sections and delete the rest.
-->

## What this PR does

One or two sentences describing the change.

## Type of change

- [ ] KB addition (new product entry)
- [ ] KB fix (correcting an existing entry)
- [ ] Bug fix (matcher / parser / output formatting)
- [ ] New feature
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] Commits are signed (`git config --global commit.gpgsign true` if SSH-signing) -- `main` is protected and rejects unsigned commits.
- [ ] CI is green (PSScriptAnalyzer + shellcheck both pass).
- [ ] If this changes the KB, the rationale in `Notes` is one clear sentence and the `Risk` level is honest.
- [ ] If this changes script behaviour, `CHANGELOG.md` has a matching entry under an `Unreleased` heading.
- [ ] If this changes the README's scope (new platform, new requirements, new flag), the README and the `.NOTES` block in the script header are both updated.
- [ ] No new runtime dependencies. The scripts must stay self-contained.

## KB addition specifics (skip if not applicable)

- [ ] Tested on a real running instance of the product -- not theoretical.
- [ ] No path exclusion looks like `C:\` or `/` rooted in a way that's broader than the product's own directories.
- [ ] No extension exclusion matches user-writable binaries (`.exe`, `.dll`, `.so`, `.bin`, `.cmd`, `.bat`, `.msi`, ...).
- [ ] If a process name needs a wildcard, the pattern is tight (`tomcat*.exe`, not `*.exe`).

## Notes for the reviewer

Anything that's not obvious from the diff -- design trade-offs, why a
seemingly simpler approach didn't work, related issues.
