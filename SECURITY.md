# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.3.x   | Yes       |
| 2.2.x   | Security fixes only |
| 2.1.x   | No        |
| <= 2.0  | No        |

## Reporting a vulnerability

If you believe you have found a security issue in this project --
particularly one that could be used to weaken SentinelOne coverage on a
deployed endpoint -- please report it privately rather than opening a
public issue.

**Preferred channel**: GitHub's private vulnerability reporting at
<https://github.com/asukarieh/S1-ExclusionGenerator/security/advisories/new>.
This routes a draft advisory directly to the maintainer without making
it visible to anyone else.

**Fallback**: email <alaa@sukarieh.com>.

When reporting, please include:

- A clear description of the issue and its impact.
- A minimal proof of concept or step-by-step reproduction (a KB entry
  that creates a blind spot, a code path that misparses a registry
  value, a quoting bug that lets an exclusion escape its intended
  scope, etc.).
- The platform and PowerShell / bash version where you observed it.
- Whether the issue has been disclosed to anyone else.

## Response timeline

You can expect:

- An acknowledgement within **3 business days** of the initial report.
- A first triage assessment (confirmed / not reproducible / out of
  scope) within **7 business days**.
- A fix or workaround for confirmed issues within **30 days** for the
  current supported version. More severe issues will be turned around
  faster.

## What is in scope

- Bugs in either script that cause an exclusion to apply more broadly
  than intended (e.g. a path glob that escapes its target directory).
- KB entries that produce an exclusion which would whitelist
  malware-relevant locations or extensions (`.exe`, `.dll`, `/tmp`
  unscoped, etc.).
- Logic in either script that mis-parses attacker-controlled input
  (filenames, registry values, environment variables) in a way that
  could mislead the operator into pasting a dangerous exclusion into
  the SentinelOne console.
- Vulnerabilities in tooling shipped with the project (the helper
  shell scripts, the lint workflow).

## What is out of scope

- Reports about SentinelOne itself. The project is a recommendation
  tool; SentinelOne's agent behaviour is the vendor's responsibility.
  Report agent bugs to <https://www.sentinelone.com/legal/responsible-disclosure-policy/>.
- Generic Windows / Linux misconfigurations that aren't introduced by
  this project.
- Findings whose only impact is degraded performance.
- Findings that require an already-compromised privileged shell on the
  target box.

## Disclosure

Once a fix lands, the advisory will be published with credit to the
reporter (unless they request anonymity). If you'd like a CVE
assigned, mention that in the report and we'll request one via
GitHub's CVE workflow.
