#!/usr/bin/env bash
#
# push-to-github.sh
#
# One-shot helper that initialises this folder as a git repo, makes the
# initial commit, and pushes to GitHub. Run it ONCE from a Terminal on
# your Mac (not from the sandbox).
#
# Usage:
#   1. Create an empty repo on github.com (no README, no .gitignore --
#      this script provides them). Copy the repo URL.
#   2. cd to this folder and run:
#        bash push-to-github.sh <repo-url>
#      e.g.
#        bash push-to-github.sh git@github.com:asukarieh/S1-ExclusionGenerator.git
#      or
#        bash push-to-github.sh https://github.com/asukarieh/S1-ExclusionGenerator.git
#
# Requirements:
#   - git installed (`brew install git` or Xcode CLI tools)
#   - You are signed in to GitHub: either an SSH key registered with
#     your account, or `gh auth login`, or a Personal Access Token
#     cached by git-credential-osxkeychain.
#
set -euo pipefail

REPO_URL="${1:-}"
if [[ -z "$REPO_URL" ]]; then
    echo "Usage: bash push-to-github.sh <repo-url>" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  bash push-to-github.sh git@github.com:asukarieh/S1-ExclusionGenerator.git" >&2
    exit 1
fi

# Always work from the directory this script lives in.
cd "$(dirname "$0")"

# Confirm we are where we expect to be.
if [[ ! -f S1-ExclusionGenerator.ps1 ]]; then
    echo "Error: S1-ExclusionGenerator.ps1 not found in $(pwd)" >&2
    exit 2
fi

# A stale half-formed .git directory may exist from a previous failed
# attempt. If the repo has no commits yet, wipe it and re-init so we
# start clean.
if [[ -d .git ]] && ! git rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "==> wiping stale .git (no commits found)"
    rm -rf .git
fi

# Initialise if needed; otherwise reuse the existing repo.
if [[ ! -d .git ]]; then
    echo "==> git init"
    git init -q -b main
fi

# Local identity for this repo (does not touch your global config).
git config user.name  "Alaa G. Sukarieh"
git config user.email "alaa@sukarieh.com"

# Add everything except files matched by .gitignore (old report files,
# editor noise, etc.).
echo "==> git add ."
git add -A

# Skip the commit if there is nothing staged.
if git diff --cached --quiet; then
    echo "==> nothing to commit (working tree matches HEAD)"
else
    echo "==> git commit"
    git commit -q -m "Initial release of S1-ExclusionGenerator v2.2

SentinelOne exclusion-recommendation generator for Windows endpoints.
Inventories installed software (registry), running services (WMI), and
running processes (WMI) on the local host, matches against a curated
knowledge base of enterprise / Telco / Mobile Money / fintech products,
and emits S1-ready exclusion lists in HTML, CSV, JSON, and TXT.

Tested on Windows PowerShell 5.1, Windows 7 SP1 through Windows 11,
and Windows Server 2008 R2 SP1 through Windows Server 2025."
fi

# Wire up the remote (replace if it already exists).
if git remote get-url origin >/dev/null 2>&1; then
    echo "==> updating existing 'origin' remote"
    git remote set-url origin "$REPO_URL"
else
    echo "==> adding 'origin' remote -> $REPO_URL"
    git remote add origin "$REPO_URL"
fi

# Push.
echo "==> git push -u origin main"
git push -u origin main

echo ""
echo "Done. Repo is live at: $REPO_URL"
