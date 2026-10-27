# Using the skill

The skill triggers on requests to write, review, tune, test or convert KQL detections and hunting
queries for Sentinel or Defender XDR, and on requests to turn a threat report into queries. Prompts that
worked well in evaluation:

| Ask | What you get |
|---|---|
| "I need a Defender XDR custom detection that fires when a process never seen accessing lsass.exe does so, hourly. Save the KQL and a rule doc." | `detection.kql` with first-seen logic, a guard gap between baseline and alert window, required columns via `arg_min`, hoisted tunables; `rule.md` with MITRE T1003.001, tunables, false positives, blind spots |
| "Write a Sentinel scheduled rule YAML for password spray from one IP using SigninLogs, hourly, deployable without surprises." | `rule.yaml` with the ingestion-delay window, result codes classified into credential-valid vs invalid, `dcount` of users per IP, entity mappings whose columns exist in the output, grouping and alert enrichment |
| "Review this custom detection (flawed.md) and give me a corrected version." | `review.md` listing each defect with a one-line reason; `fixed.kql` that passes the lint |
| "Here is a threat report excerpt. Turn it into hunting queries for XDR; tell me which could become detections." | `hunts.md`: a pack of narrow queries tiered IOC → artefact → behaviour, each with a hypothesis header and MITRE mapping, a promotion table, and the report's samples stored as test fixtures |
| "Convert this hunting query to an hourly XDR custom detection." | `detection.kql` with ranking replaced by thresholds and a population filter, plus `promotion-notes.md` explaining the 4-hour lookback consequence, dedup, sampling caveats and post-deploy checks |

## Reading a generated rule

Every query the skill writes carries a header you can audit:

```kql
// DETECTION STRATEGY: ...        what behaviour, why it matters, MITRE technique
// THE MECHANIC: ...              what the attacker does that produces this telemetry
// THE RESILIENCE: ...            why the chosen key survives benign change
// DATA: <table / ActionType> — retention assumed — sampled: yes/no
// TP LIKELIHOOD WHEN IT FIRES: ... COVERAGE CAVEAT: ...
// STEP n: ...                    what each block does
// ANALYST ACTION: ...            what to check in the output
```

followed by a `let` block of tunables, a fenced `// Begin environment-specific filter.` region, and a
trailing comment naming the dedup key and impacted assets. If a generated rule lacks these, it was not
produced through the skill's gates.

## The scripts

```bash
# lint a rule (platform auto-detected from Timestamp vs TimeGenerated; override with --platform)
python3 skill/scripts/kql_lint.py --platform xdr rule.kql
# lint every ```kql block in a markdown file, relaxing rule-only checks for hunts
python3 skill/scripts/kql_lint.py --hunt hunts.md
# build a unit-test query from a fixture (emit only)
python3 skill/scripts/kql_test_harness.py --query rule.kql --fixture tests/fixtures/rule/tp.json
# run fixtures against an empty workspace and assert
python3 skill/scripts/kql_test_harness.py --query rule.kql --fixture-dir tests/fixtures/rule --run --workspace <guid>
# list snippet generators, render one
python3 skill/scripts/kql_fp_patterns.py --list
python3 skill/scripts/kql_fp_patterns.py -p first_seen_gap -P lookback 30d -P gap 2d -P base_table DeviceProcessEvents \
    -P time_col Timestamp -P filter_condition 'FileName in~ (Tools)' -P key_cols 'DeviceId, FileName'
```

Lint findings are prefixed `E` (error, exit code 1), `W` (warning, error with `--strict`) or `I` (info).
Suppress a single finding with a trailing `// lint:ignore W005` comment; the suppression must be in a
comment, not inside a string literal.

Fixture format for the harness: a JSON object with `query_now` (pinned clock), `tables` (each with an
optional `schema` and an `events` list), `expected_alerts` and optional `expected_columns`. If the query
uses `ingestion_time()`, every event needs an `__ingestion_time` value; the harness refuses to invent one.

## Worked example

`usecases/zscaler-lan-proxy-bypass/` shows the full output for one use case: a user points the browser
or system proxy at another LAN host that egresses directly, bypassing Zscaler. It contains four XDR
custom detections, a Sentinel rule, a specification with assumptions, blind spots and preflight queries,
and fixtures with the built test queries.
