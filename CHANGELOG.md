# Changelog

## 2026-11-03 — Sentinel platform contract

- New reference `sentinel-platform-contract.md` and stdlib script `sentinel_template_lint.py`: checks ARM/JSON/YAML
  rule templates and `savedSearches` hunts against the limits the Sentinel API enforces at create time (format
  placeholders, custom details, entity mappings, enums, scheduling, grouping, GUIDs, `subTechniques` on GA
  `apiVersion`, export `id`). Five regression tests added (43 total).
- SKILL.md: routing row and script entry; gate 6 extended with the template contract; new gate 8 "run on the
  target workspace" (ten gates); new workflow for reworking a rule pack from an incident export; five fix-matrix
  rows (periodic machine-account noise, service self-maintenance, silence rules, single operational errors,
  workspace-wide tamper rules); checklist lines for template lint, target-workspace run and disabled import.
- Patterns: `recurring_baseline_suppress`, `learned_silence_threshold`, `machine_actor_self_maintenance` (26 total).
- References: recurrence baseline and learned silence threshold in `rule-windows-and-baselines.md` §4; five
  gotchas in `kql-gotchas.md` (`has` on compound names, `coalesce` over `tostring`, tabular `in` outside `where`,
  silence threshold longer than `queryPeriod`, empty `{{Column}}` in alert titles); template lint and
  semantic validation in the `detection-as-code.md` CI gates.

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
