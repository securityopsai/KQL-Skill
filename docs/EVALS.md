# Evaluation

## Method

Five tasks, each run three ways with independent agents: the updated skill, the original skill it
replaced, and no skill at all. Outputs were anonymised and graded by a separate agent against the same
written assertions, with mechanical checks (required columns, join kinds, capped sets, lint results)
pre-computed by script and verified by the grader. Timing and token use were recorded per run.

| Case | Task |
|---|---|
| `xdr-first-seen-lsass-access` | hourly XDR custom detection for a process never seen accessing lsass.exe, with a rule document |
| `sentinel-password-spray-rule` | Sentinel scheduled rule YAML for password spray from one IP, deployable without surprises |
| `review-and-fix-flawed-query` | review a deliberately flawed XDR detection and produce a corrected one |
| `threat-report-to-hunt-pack` | turn a fictional threat report into hunting queries and say which could become detections |
| `promote-hunt-to-detection` | convert a 7-day beaconing hunt into an hourly XDR custom detection with notes |

## Results (iteration 1, one run per configuration)

| Case | Updated skill | Original skill | No skill |
|---|---|---|---|
| XDR first-seen lsass access | 10/10 | 9/10 | 7/10 |
| Sentinel password-spray rule | 9/9 | 8/9 | 6/9 |
| Review and fix a flawed query | 8/8 | 8/8 | 8/8 |
| Threat report to hunt pack | 11/11 | 10/11 | 8/11 |
| Promote hunt to detection | 12/12 | 11/12 | 9/12 |
| **Mean pass rate** | **100%** | **92%** | **77%** |
| Mean tokens | 153k | 111k | 82k |
| Mean wall time | 8.0 min | 6.0 min | 4.1 min |

Where the no-skill runs lost points: a self-inflicted `Timestamp > ago(4h)` filter on an hourly XDR rule,
no `ingestion_time()` run window in the Sentinel rule, a rule document claiming hourly rules only evaluate
Timestamps in the last four hours, no mention of the 150-alert cap or MDE network sampling, indicators
re-typed inline, missing MITRE mappings, `T1110` instead of `T1110.003`, uncapped sets.

Where the original skill lost points against the update: no guard margin between baseline and alert
windows, a recency-guard variable instead of an ingestion-time run window, sensor sampling not named as a
false-negative source, an untimed detection draft in the hunt pack.

## Caveats

- One run per configuration; a one-assertion difference is suggestive, not conclusive.
- The review case does not discriminate: the base model already reviews flawed KQL well.
- The first eight assertions per case were permissive OR-lists; ten stricter assertions were added after
  the blind graders' critique, and most of the separation comes from those.
- Assertions and skill share an author, and one strict check uses the skill's own lint. Graders were blind
  to labels but skill outputs are recognisable by their header style.
- The updated skill costs roughly 75% more tokens than an unassisted run.

Raw artefacts (benchmark, per-run outputs, grading with evidence, timings, a static review viewer) are in
`eval-iteration-1/`.

## Re-running

The cases under `skill/evals/` use the layout `claude plugin eval` reads:

```bash
cd skill
claude plugin eval . --allow-tools Write,Edit,Bash --scaffold
```

Each case runs with and without the skill and the report lands under `evals/results/`. These are real,
billed model runs. Alternatively drive the same cases with Anthropic's `skill-creator` skill, which also
produces the benchmark and the review viewer used for iteration 1.
