# KQL-Skill — `sentinel-fp-workflow`

A Claude skill for KQL detection engineering and threat hunting on **Microsoft Sentinel** and
**Microsoft Defender XDR**. It makes Claude work through a fixed set of quality gates, pull in the
platform facts that are easy to get wrong (lookback semantics, ingestion time, required columns,
join defaults, term indexing), lint its own KQL, and leave behind a rule document a reviewer can act on.

The skill's installed name is `sentinel-fp-workflow`. Installing the package from `dist/` replaces an
existing skill of that name rather than adding a duplicate.

| | |
|---|---|
| Platforms | Sentinel scheduled and NRT analytics rules, Defender XDR custom detections, advanced hunting |
| What it produces | KQL detections and hunts, Sentinel rule YAML, detection specifications, unit-test fixtures, FP triage records |
| Tooling | `kql_lint.py` (static checks), `kql_test_harness.py` (fixture-based unit tests), `kql_fp_patterns.py` (23 snippet generators) |
| Evidence base | ~5,000 hunting queries and detection rules from 24 public repositories, verified against Microsoft Learn |
| Measured effect | 100% assertion pass rate with the skill vs 77% without, on five blind-graded tasks (see [docs/EVALS.md](docs/EVALS.md)) |

## Quick start

1. Install the skill: upload `dist/sentinel-fp-workflow.skill` in claude.ai (Settings → Skills) or copy
   `skill/` into your Claude Code skills directory. Details in [docs/INSTALL.md](docs/INSTALL.md).
2. Ask for a detection, a hunt, a review, or a conversion. Example prompts and what to expect are in
   [docs/USAGE.md](docs/USAGE.md).
3. Run the checks locally before trusting any generated rule:

```bash
cd skill
python3 -B -m unittest discover -s tests -v          # 38 offline regression tests for the scripts
python3 scripts/kql_lint.py --selftest                # lint self-test
python3 scripts/kql_lint.py --platform xdr my_rule.kql
python3 scripts/kql_test_harness.py --query my_rule.kql --fixture-dir tests/fixtures/my_rule --out-dir build/
```

## Repository layout

```
skill/                        the skill
  SKILL.md                    router: quality gates, hunting workflow, FP triage, fix matrix, checklist
  references/                 eight reference files loaded on demand (see docs/ARCHITECTURE.md)
  scripts/                    kql_lint.py, kql_test_harness.py, kql_fp_patterns.py, kql_text.py
  tests/                      offline regression tests for the scripts
  evals/                      five test cases with prompts, input files and assertions
usecases/
  zscaler-lan-proxy-bypass/   worked example: 4 XDR custom detections, 1 Sentinel rule, spec, fixtures
docs/
  ARCHITECTURE.md             components and how they fit together
  INSTALL.md                  installing and updating the skill
  USAGE.md                    prompts, outputs, and how to read a generated rule
  EVALS.md                    the evaluation: method, results, caveats, how to re-run
  ARTICLE.md                  a short, opinionated introduction
  eval-iteration-1/           raw eval artefacts: benchmark, graded outputs, static viewer
dist/
  sentinel-fp-workflow.skill  installable package
```

## What the skill enforces

Every new or changed rule must pass these gates before it is considered deployable:

1. Intent stated in one sentence and mapped to the MITRE technique the predicate asserts.
2. Alerts aggregated to the entity an analyst investigates, with floored, compound thresholds.
3. Query windows that match the schedule: ingestion-delay handling on Sentinel, no self-inflicted
   `Timestamp` filter on the XDR recent window, baselines that end before the alert window.
4. Tunables hoisted into `let` statements with the false positive each one trades against, and a
   fenced region for environment-specific exclusions.
5. Performance and semantics review: explicit `join kind=`, capped sets, indexed operators, parameter
   bags read by name, case-insensitive file-name matching, no `search`, `union *` or `take`.
6. Platform contract: entity mappings whose columns exist in the final projection (Sentinel);
   `Timestamp`, `ReportId`, `DeviceId` carried through aggregation (XDR); valid frequency and lookback.
7. Unit tests: true positive, benign lookalike, threshold boundary, empty input.
8. A detection specification with data sources, permission required, blind spots, precision statement
   and version history.
9. A measured precision rate and a kill switch for any rule wired to a response action.

## Status and limits

The lint is heuristic (regex over a lexed view of the query), not a KQL parser; treat it as a first gate
before an offline Kusto parse and a tenant run. Example thresholds are placeholders. The skill does not
execute queries or deploy rules. Platform facts were verified against Microsoft Learn in October 2026 and
will drift; `references/kql-gotchas.md` carries a table-churn map to update.

## License

MIT. See [LICENSE](LICENSE).
