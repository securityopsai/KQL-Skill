---
name: sentinel-fp-workflow
description: KQL detection engineering and threat hunting for Microsoft Sentinel and Defender XDR. Covers analytics rules and custom detections, hunting patterns (first-seen, prevalence, beaconing, anomaly, sequence, flow fingerprinting) and hunt-to-detection promotion, rule windows and ingestion delay, baselines and dedup, KQL performance and gotchas, identity/email idioms, unit testing with mock data, detection-as-code (CI/CD, YAML, lint, ASIM/functions/watchlists/summary rules), FP triage, exclusions, documentation, and the Sentinel platform contract (ARM/JSON/Bicep/YAML import, alert-detail formats, custom details, entity mappings, scheduling and MITRE limits). Use when writing or reviewing KQL rules or hunts, turning a threat report into queries, tuning or reworking rules from an incident export, restructuring a rule pack, building XDR custom detections, testing detection logic, analyzing alert noise, managing FP ratios for client reporting, or when a Sentinel rule template import fails or is about to be imported.
---

# KQL Detection Engineering, Hunting & FP Workflow

Detection engineering and hunting for Microsoft Sentinel and Defender XDR, quality-first. This
file is the router and the core workflows; depth lives in `references/`. Examples are starting points,
not evidence of tenant readiness; distinguish vendor requirements from repository conventions; the
skill writes rules, tests and documents, it does not deploy or take response actions.

## Reference Routing

| Task | Load |
|------|------|
| Writing/reviewing any KQL query (operators, joins, matching, output shaping) | `references/kql-performance.md` |
| Operator semantics that bite, XDR↔Sentinel deltas, telemetry facts, table churn | `references/kql-gotchas.md` |
| Rule schedule, ingestion delay, baseline windows, floors, dedup across runs | `references/rule-windows-and-baselines.md` |
| Hunting query design, hunt funnel, threat report → hunt pack, pattern catalogue, hunt → detection promotion | `references/hunting-patterns.md` |
| Identity (Entra), token, audit-log parsing, email (MDO) idioms | `references/identity-email-patterns.md` |
| Defender XDR custom detection (required columns, NRT, dedup, response actions) | `references/xdr-custom-detections.md` |
| Rule repos, YAML contract, CI lint, unit testing, watchlists/functions/summary rules | `references/detection-as-code.md` |
| Building, editing or importing a Sentinel rule template (ARM/JSON/Bicep/YAML), packaging hunting queries, or an import/deployment failed | `references/sentinel-platform-contract.md` + run `scripts/sentinel_template_lint.py` |
| Detection specification, hunt header, report-pack page, change record, FP worksheet, BTP taxonomy | `references/documentation-templates.md` |

Scripts:

- `scripts/kql_lint.py` — static checks for the defect classes found most often in real rule repos
  (bare `join`, unbounded `make_set`, short terms, positional indexing, platform column drift,
  zero-overlap windows, placeholders, full-sample `has_all`). Run on every `.kql` and on each
  ` ```kql ` block of a `.md`; `--selftest` to verify.
- `scripts/sentinel_template_lint.py` — lint an ARM template / resource list / rule YAML against the
  limits the Sentinel API enforces at create time (placeholder counts, custom details, entity
  mappings, enums, scheduling, grouping, GUIDs, `subTechniques` on a GA `apiVersion`, non-ARM members
  such as an export's `id`), and lints hunting-query (`savedSearches`) resources too. Run it on every
  file you hand over, single files included.
- `scripts/kql_test_harness.py` — build unit-test queries from fixtures (datatable substitution, pinned `now()`/`ago()`, explicit `__ingestion_time` fixture column when the query uses `ingestion_time()`), emit or run. Emission is not a passing test; the query still needs a KQL engine.
- `scripts/kql_text.py` — string/comment-aware lexical helper shared by the lint and the harness; not a KQL parser.
- `tests/test_helpers.py` — offline regression tests for the scripts: `python3 -B -m unittest discover -s tests -v` from the skill directory.
- `scripts/kql_fp_patterns.py` — generate tuned KQL snippets: exclusions, windows, baselines, flow fingerprints, bridges.

## Detection Authoring Quality Gates

Every new or modified rule must pass ALL gates before deploy. A failed gate is a review blocker.

1. **Intent stated** — one sentence: what attacker behaviour does this catch, mapped to MITRE
   tactic + technique **for the behaviour the predicate asserts** (not the data source). If you
   can't state it, the rule is a hunt, not a detection.
2. **Entity-level alerting** — aggregate to the entity the analyst investigates
   (`summarize arg_max(...) by DeviceId` / account / mailbox), never one alert per raw row;
   compound, floored thresholds with a population filter for rarity logic.
3. **Windows match the schedule** — `let query_frequency / query_period / query_wait` mirror the
   rule metadata; run window on `ingestion_time()`, baseline window ends before the alert window;
   no zero-overlap `TimeGenerated` schedule; no self-inflicted `Timestamp` filter on the XDR recent
   window. See `references/rule-windows-and-baselines.md`.
4. **Tunables hoisted and explained** — thresholds, windows, exclusions in `let` at the top or in
   watchlists, each with a comment stating its meaning and the FP it trades against; a fenced
   `// Begin/End environment-specific filter.` region; no tenant literals or placeholders.
5. **Performance and semantics reviewed** — checklists in `references/kql-performance.md` and
   `references/kql-gotchas.md` (explicit `join kind=`, capped sets, indexed operators, parameter
   bags read by name, `=~` on file names, no `search`/`union *`/`take`).
6. **Platform contract met** — Sentinel: entity mappings whose columns exist case-sensitively in the
   final projection, grouping/suppression, version bump. XDR: `Timestamp`/`ReportId`/`DeviceId`
   (bridged via `DeviceInfo` for TVM tables), valid frequency/lookback pair, NRT restrictions, dedup
   key documented. See `references/xdr-custom-detections.md`. Sentinel templates:
   `scripts/sentinel_template_lint.py` passes on the artifact that will be imported. The API rejects
   the whole deployment for any one of: more than 3 `{{Column}}` placeholders in an alert name or
   description format, more than 20 custom details, more than 10 entity mappings or 3 identifiers per
   entity, frequency longer than period or either outside 5 min – 14 d, a sub-technique in
   `techniques`, `subTechniques` on a GA `apiVersion` (only `-preview` versions have it – use
   `2023-12-01-preview`), a severity outside Informational/Low/Medium/High (no Critical), grouping by
   an entity the rule does not map. For GUI deployment through *Deploy a custom template*, drop the
   export's resource-level `id`. Full list and the reasons in `references/sentinel-platform-contract.md`.
7. **Unit tested** — true positive (for report-derived rules: the report's own sample), benign
   lookalike, threshold boundary (n-1 / n / n+1), empty input; one fixture set per platform variant.
   Use `scripts/kql_test_harness.py`; lint first with `scripts/kql_lint.py`.
8. **Run on the target workspace** — the Sentinel API validates KQL semantically against the
   workspace when the rule is created, so a missing table, saved function or column fails the
   import, not the first run. Paste the resolved query into Logs with the rule's `queryPeriod` as the
   range before you import.
9. **Documented** — detection specification per `references/documentation-templates.md` incl.
   data sources with ActionType, permission required, **blind spots** (write "None expected." only
   after assessing; otherwise "Not yet assessed" plus the gap), precision/coverage statement,
   version history with impact; PR-reviewed. Never invent a measured precision rate.
10. **Response actions earn their precision** — any rule wired to isolate/purge/disable states a
   measured TP rate and a kill switch.

## Hunting Workflow

1. Write the hypothesis into the query header (`DETECTION STRATEGY / MECHANIC / RESILIENCE /
   DATA + retention + sampled? / TP likelihood + coverage caveat / ANALYST ACTION`).
2. Know the data first: tables, `ActionType` values new vs a 180 d baseline, ingestion delay per table.
3. Hunt as a **funnel** (population stats → derived attribute → editable shortlist → entity
   enrichment → DFIR pivots), one `TimeFrame` knob across stages.
4. From a threat report: a **pack** of 3–10 narrow queries on one page, tiered IOC → artefact →
   behaviour, invariant tokens only, sample stored as the TP fixture, vendor-alert view included.
5. Pick the pattern from the catalogue (first-seen with guard gap, two-tier prevalence, beaconing,
   two-stage anomaly, `scan` sequences, flow fingerprint, threshold newly crossed, graph paths, TI).
6. Promote with the checklist in `references/hunting-patterns.md` §5 — windows, thresholds,
   per-entity collapse, watchlists, dedup, blind spots, rewritten description. Hunt YAML carries
   **no** severity or scheduling fields. ep3p's convention (same function is a hunt when
   `query_frequency == query_period`, a detection when `<`) is a useful design habit, not a platform
   rule: a scheduled detection may legitimately have equal frequency and period.

## Reworking a Rule Pack from an Incident Export

The common request: "here are the rules and here are N incidents, they are all false positives, fix
the rules". Work from the data, not from the rule text:

1. **Profile the incidents per rule** — count, distinct hosts/accounts, cadence (median gap between
   incidents per entity), time-of-day, first==last activity. A rule firing per host every 90–120
   minutes under a machine account is a periodic system process (Group Policy refresh, service
   restart), not an actor. A rule whose incidents show a 1970-01-01 timestamp or an empty field in
   the title has a query/data-shape bug, not a detection problem.
2. **Classify each cluster** (TP / BTP / FP) and name the root cause in one line. The fix follows
   from the cause (matrix below); do not start by adding exclusions.
3. **Keep what the data cannot see** — rules with zero incidents are not "fine"; review their logic
   once (string matching, `has` vs `contains` on compound provider names, thresholds inside the
   lookback) and leave them otherwise unchanged. Say so.
4. **Keep rule GUIDs** when renaming or renumbering so the import updates in place and incident
   history stays attached. A rule you split out gets a new, deterministic GUID.
5. **Generate the template from source** (KQL files + a build script), lint it with
   `scripts/sentinel_template_lint.py`, and deliver the queries standalone too so they can be pasted
   into Logs. Export disabled. Split hunts out: a disabled "hunt-only" rule goes into a separate
   hunting-query template (`savedSearches`, see `references/sentinel-platform-contract.md`). Deliver
   one combined file per kind plus one import file per rule and per hunt.
6. **Learn tenant facts, don't hard-code them** – internal domains, admin accounts and hosts come
   from the data (for example, member-UPN suffixes from `SigninLogs`), with an optional override list
   that is empty by default. Check the learned set for poisoning paths, and keep its lookback within
   `queryPeriod`.
7. **Record expected effect per rule** against the sample ("would have produced 0 of the 1,887") and
   list what must be verified on the live workspace.

## FP Triage Process

1. **Classify** — True Positive, Benign True Positive (BTP), or False Positive (seed list of known
   BTP generators in `references/documentation-templates.md`)
2. **Root cause** — Query logic flaw, missing exclusion, environmental noise, data quality issue,
   **window/ingestion mismatch**, baseline poisoning, or platform dedup not engaged
3. **Fix approach** — Rule tuning vs. watchlist exclusion vs. automation rule suppression
4. **Document** — templates in `references/documentation-templates.md`; every exclusion gets a
   blind-spot line ("excluding X means attack Y via X will not fire")
5. **Validate** — re-run unit fixtures; the true-positive fixture must still fire after the exclusion

## Fix Selection Matrix

| Root Cause | Fix Approach | Risk |
|------------|--------------|------|
| Overly broad query | Tune KQL in analytics rule | Medium |
| Known-good entity | Add to exclusion watchlist (rule-scope keyed, expiring) | Low |
| Vendor/tool noise | Automation rule auto-close, or BTP tag | Low |
| Data quality (nulls, three spellings of empty) | Fix at source or null handling | High |
| Scheduled tasks / maintenance | Time-based exclusion (`datetime_utc_to_local`) or BTP | Medium |
| Duplicate alerts across runs | Stable event/entity keys + run window (XDR dedup key; Sentinel incident grouping). Sentinel `suppressionEnabled` pauses the *whole rule*, not one entity — use it only when that coverage loss is intended | Low–Medium |
| Missed events / late alerts | Ingestion-delay window (`ingestion_time()`), `query_wait` | Medium |
| Quiet entity alerts on 1 → 2 | Floor the threshold; absolute floor beside anomaly sensitivity | Low |
| Periodic system noise under a machine account (GPO refresh 4719, service-start config rewrites) | Recurrence baseline: alert only when the (entity, change) was seen < N times in the lookback; user-account actors always alert (`rule-windows-and-baselines.md` §4) | Medium |
| Service maintaining its own objects (CA publishing its CRL, host updating its own AD entry) | Exclude only machine actor + own object + maintenance attribute; everything else unchanged | Medium |
| "Silence" rule on an event-driven log, or fixed timeout longer than the lookback | Drop the stream or learn a per-entity threshold from the baseline; never-seen becomes a daily coverage finding | Low |
| Single operational error treated as an incident (one rejected NDES request) | Burst threshold per entity per run | Low |
| Tamper rule scoped to the whole workspace (any rule edit, any admin) | Scope to the pack's own GUIDs; exclude the named change process; deletes always alert | Low |

Rule of thumb: prefer the fix that does NOT require a rule redeploy (watchlist, automation rule)
when the exclusion is data, and a query change when the exclusion is logic. Never copy-paste
exclusions across rules — centralise (code reuse section of `references/detection-as-code.md`).

## Core KQL Patterns (quick reference)

Generate with `scripts/kql_fp_patterns.py --list`.

```kql
// Watchlist exclusion (Sentinel) — tostring() every watchlist column
let Excluded = _GetWatchlist('FP_Exclusions') | project Entity = tolower(tostring(Entity));
SecurityEvent | where tolower(TargetUserName) !in (Excluded)

// Ingestion-delay window (Sentinel scheduled rule)
let ingestion_delay = 2min; let rule_look_back = 5min;
CommonSecurityLog
| where TimeGenerated >= ago(ingestion_delay + rule_look_back)
| where ingestion_time() > ago(rule_look_back)

// First-seen with guard gap (baseline grain == join grain)
let known = T | where Timestamp between (ago(30d) .. ago(2d)) | distinct DeviceId, FileName;
T | where Timestamp > ago(2d) | join kind=leftanti known on DeviceId, FileName

// Entity dedup with XDR contract preserved
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), EventCount=count(), Ctx=make_set(X, 50) by DeviceId
| where EventCount > 5

// Null-safe field handling (Entra "empty" has three spellings)
| where isnotempty(TargetUserName) and TargetUserName !in ("-", "none", "[]")
```

## Validation Checklist

- [ ] `scripts/kql_lint.py` clean on every platform variant
- [ ] Unit fixtures pass: TP (incl. report sample) fires, benign lookalike does not, boundary cases correct, empty input safe
- [ ] `scripts/sentinel_template_lint.py` passes on the exact artifact being imported (Sentinel)
- [ ] Each query run in Logs on the **target** workspace with the rule's `queryPeriod`; expected volume ≪ 150/run (XDR)
- [ ] Windows: frequency ≤ period ≤ 14 d (Sentinel); ingestion-delay handling present; baseline excludes alert window
- [ ] Exclusion doesn't suppress known-bad patterns (TP fixture still fires); blind-spot line written
- [ ] Entity mappings / required columns intact after the change; dedup key still matches projection
- [ ] Resource indicator not "High"; no `FileProfile`/`SeenBy` in a rule meant for Sentinel
- [ ] Version bumped, change record written, peer review done
- [ ] Imported disabled; enabled one rule at a time
- [ ] Document expected FP reduction %; schedule 7-day post-deploy review
