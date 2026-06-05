---
name: checks
description: Run the mandatory mcp-janus task checklist (build + test + lint). Use before marking any task done.
disable-model-invocation: false
---

Run the project's three mandatory verification steps in order. Stop and report the first failure:

1. `task build` — must compile cleanly
2. `task test` — all tests must pass
3. `task lint` — no lint errors

Report: which steps passed, which failed, and the relevant error output if any.
