# Contributing

- Keep `SKILL.md` a router: new depth goes into a reference file with a row in the routing table.
- Every factual claim about the platform cites Microsoft Learn; every claim about community practice
  says which repository it came from. Conventions are labelled as conventions.
- New lint rules need a self-test case in `scripts/kql_lint.py` and, where the lexer is involved, a test
  in `tests/test_helpers.py`. Run both before opening a pull request:

```bash
cd skill
python3 -B -m unittest discover -s tests -v
python3 scripts/kql_lint.py --selftest
python3 scripts/kql_lint.py --hunt references/*.md SKILL.md
```

- KQL in references must lint clean in `--hunt` mode; use `// lint:ignore CODE — reason` only with a reason.
- Add or adjust an eval case under `skill/evals/` when a change is meant to alter Claude's output.
- Rebuild `dist/sentinel-fp-workflow.skill` when anything under `skill/` changes (see docs/INSTALL.md).
