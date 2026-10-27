# Installing the skill

## claude.ai (web and desktop)

1. Download `dist/sentinel-fp-workflow.skill`.
2. In claude.ai open **Settings → Skills** (or the skill card's **Save skill** button when the file is
   shared in a conversation) and upload the file.
3. The skill's name is `sentinel-fp-workflow`. If a skill with that name already exists in your library
   (for example an earlier version synced to Claude Code), the upload replaces it.

The package contains only `SKILL.md`, `references/`, `scripts/` and `tests/`. The `evals/` folder stays in
this repository on purpose; it is for regression testing the skill, not for use at runtime.

## Claude Code

Copy the `skill/` directory into a skills location Claude Code reads:

```bash
# project-scoped
mkdir -p .claude/skills && cp -r skill .claude/skills/sentinel-fp-workflow
# or user-scoped
mkdir -p ~/.claude/skills && cp -r skill ~/.claude/skills/sentinel-fp-workflow
```

Claude Code lists the skill from the `name` and `description` in `SKILL.md` and consults it when a task
matches. You can also invoke it explicitly with `/sentinel-fp-workflow`.

## Updating

Rebuild the package after changing anything under `skill/`:

```bash
# from a checkout of Anthropic's skill-creator skill
python3 -m scripts.package_skill /path/to/KQL-Skill/skill /path/to/KQL-Skill/dist
```

Then re-upload `dist/sentinel-fp-workflow.skill`. Run the checks in the README first; the package
script validates the frontmatter but does not run the tests.

## Requirements

Python 3.9 or later for the scripts; no third-party packages. `--run` mode of the test harness shells
out to `az monitor log-analytics query` and therefore needs the Azure CLI and a workspace. Everything
else is offline.
