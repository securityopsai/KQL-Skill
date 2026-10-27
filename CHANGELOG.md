# Changelog

## 2026-10-27 — KQL-Skill repository

- Project published as `securityopsai/KQL-Skill`: skill, worked use case, evaluation artefacts, docs.

## 2026-10-23 — tooling merge

- `scripts/kql_text.py` lexer; lint and harness rebuilt on it; 38 offline regression tests.
- Lint: literal text can no longer suppress findings; term-index boundary aligned with Kusto docs
  (warn under 3 characters, info at exactly 3); isolated-mode import shim.
- Harness: rewrites `now()` and `ago()`, requires explicit `__ingestion_time` fixtures, strict value
  validation, path-safe output.
- Patterns: fail-closed watchlist templates, `entra_empty_safe`, `dayofweek()` cast fix, exact-match
  process exclusion, `xdr_contract` duplicate group-by key fixed.
- References: Kusto term index, `_Type` in `union withsource`, Sentinel suppression pauses the whole rule,
  incident grouping is not dedup, DeviceInfo bridge only for device-keyed tables, ingestion window is not
  exactly-once, "Not yet assessed" for unassessed blind spots.

## 2026-10-22 — skill update from community review

- Four new references (hunting patterns, rule windows and baselines, KQL gotchas, identity and email
  patterns); four existing references extended; SKILL.md router rewritten with nine gates and a hunting
  workflow; `kql_lint.py` added; eleven pattern generators added; five eval cases; iteration-1 evaluation.

## Original

- `sentinel-fp-workflow` v1: FP triage workflow, four references, pattern generator, test harness.
