---
name: KB addition / change
about: Add a product to the knowledge base, or correct an existing entry.
title: "[KB] "
labels: knowledge-base
---

## Product

| Field | Value |
|---|---|
| Name | e.g. Oracle GoldenGate |
| Vendor | |
| Category | Database / Middleware / FinTech / Backup / SIEM / Monitoring / Web / ... |
| Where it runs | Windows / Linux / both |
| Risk level | Critical / High / Medium / Low (see Notes below) |

## Why this needs an exclusion

A short rationale: what does this product do, and what specifically
breaks or slows down under SentinelOne without the exclusion? Real
operator pain (file lock contention, scan-induced latency, etc.) is the
strongest justification.

## Proposed exclusions

### Paths

```
C:\Program Files\Vendor\Product\
%PRODUCT_HOME%\data\
```

(Use `%VAR%` tokens for environment-defined paths -- they're resolved at
report time on the inventory host.)

### Processes

```
product.exe
productd
helper*.exe
```

### Extensions

```
.dbf
.bkp
```

*(Only data extensions. Never `.exe`, `.dll`, `.so`, `.bin`, or anything
that matches user-writable binaries.)*

## Risk level guidance

| Risk | When to use |
|---|---|
| Critical | Product genuinely falls over without the exclusion (databases, billing, AD) |
| High | Severe performance impact / occasional false positives |
| Medium | Mild noise, exclusion is a polish item |
| Low | Mostly informational -- nice to have, not required |

## Tested where

- [ ] On a real production deployment of this product
- [ ] On a lab / dev installation
- [ ] Theoretical -- I have read the vendor's recommended exclusion guide but haven't tested

Be honest about which one. Theoretical entries are still useful, just
flagged in the Notes.

## References

Vendor's official exclusion guide, support article, or community write-up.
