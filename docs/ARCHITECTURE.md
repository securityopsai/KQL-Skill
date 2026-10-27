# Architecture

The skill follows progressive disclosure: `SKILL.md` is always loaded when the skill triggers; the
references are loaded only when the router sends Claude to them; the scripts run without being loaded.

```
SKILL.md (router, ~2,000 words)
 ├─ Reference routing table ──► references/*.md (loaded per task)
 ├─ Nine quality gates
 ├─ Hunting workflow
 ├─ FP triage process + fix selection matrix
 ├─ Quick-reference patterns
 └─ Validation checklist
scripts/
 ├─ kql_text.py          lexer: strings (ordinary, verbatim, triple-backtick), line and block comments → code / comment views
 ├─ kql_lint.py          heuristic checks over the lexed views; per-line suppression; markdown fence support; self-test
 ├─ kql_test_harness.py  fixture → datatable shadowing, now()/ago()/ingestion_time() rewriting, emit or run, assertions
 └─ kql_fp_patterns.py   23 parameterised templates (exclusions, windows, baselines, fingerprints, bridges, fences)
tests/test_helpers.py    38 offline regression tests covering the lexer, harness, lint and patterns
evals/                   5 cases: prompt.md, case.yaml, graders/, files/ (skill-creator / claude plugin eval layout)
```

## References

| File | Load when | Holds |
|---|---|---|
| `kql-performance.md` | writing or reviewing any query | operator choice, filter order, join alternatives, command-line matching discipline, output shaping, review checklist |
| `kql-gotchas.md` | anything surprising | operator semantics that produced real bugs, XDR vs Sentinel delta table, telemetry facts (sampling, ActionType churn), table and column churn map |
| `rule-windows-and-baselines.md` | any scheduled rule | rule contract in KQL, Sentinel ingestion-delay form, XDR ingestion-time semantics, baseline guard gaps and floors, dedup across runs, local time |
| `hunting-patterns.md` | hunts, threat reports, promotion | hunt vs detection contract, hunt header, hunt funnel, report-to-pack workflow, pattern catalogue (first-seen, prevalence, beaconing, anomaly, sequences, flow fingerprints, graph, TI), promotion checklist, IR query packs |
| `identity-email-patterns.md` | Entra, M365, MDO | result-code classification, flow fingerprints, token replay, audit-log parsing by name, mailbox and URL chains |
| `xdr-custom-detections.md` | XDR rules | required columns and bridging, frequency/lookback pairs, 150-alert cap, dedup semantics, NRT restrictions, XDR-only functions, auditing the platform |
| `detection-as-code.md` | repos, CI, tests, reuse | layout, full Sentinel YAML contract, entity-mapping discipline, CI gates and lint list, fixture classes, watchlist taxonomy, functions, summary rules |
| `documentation-templates.md` | documenting | detection specification, hunt header, report-pack page, change record, FP worksheet, client report, watchlist schema, benign-true-positive taxonomy |

## Design decisions

- **Hard gates over advice.** The evaluation showed that the prescriptive statements (required columns,
  no self-inflicted `Timestamp` filter, explicit `join kind=`) are what separate skill runs from unassisted
  runs. Where Microsoft phrases something as a recommendation, the skill still treats it as the contract
  and says why.
- **Facts carry their source.** Statements about the platform cite Microsoft Learn; statements about
  community practice carry counts from the repository review; conventions are labelled as conventions.
- **Fail closed in generated exclusions.** Watchlist templates read `RuleScope` and `ExpiryDate` with
  `column_ifexists()` so simpler watchlists parse, but a missing or past expiry excludes nothing.
- **The harness never invents data.** A query that uses `ingestion_time()` needs explicit ingestion
  timestamps in its fixtures; shadowing with inline tables would otherwise silently filter every row.
- **Lint is a smoke detector.** It encodes the defect classes with the highest counts in real repositories
  and nothing subtler; an offline Kusto parse and a tenant run remain required.
