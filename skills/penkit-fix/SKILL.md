---
name: penkit-fix
description: "Applies to the project the changes proposed by /penkit-remediate in remediation.json (all of them, or the numbers given). Use after /penkit-remediate, or when the user asks to apply, implement or fix the items of a penkit remediation (in any language)."
argument-hint: "[1,3] [penkit/reports/<date>]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash(ls penkit/reports*)
  - Bash(git rev-parse *)
  - Bash(git status)
  - Bash(git status *)
  - Bash(git diff)
  - Bash(git diff *)
---

# penkit fix

Applies to the project the changes listed in the `remediation.json` written by `/penkit-remediate`. The list says what to change and why; your role is to implement it in the code as it is now, without going beyond it. Answer in the user's language.

This skill is a link to the penkit repository, created by `penkit init`: do not edit it from the project.

## Steps

1. **Remediation.** Use the report directory given as argument, otherwise the most recent one in `penkit/reports/` that contains a `remediation.json` (the names are timestamps `YYYYMMDD-HHMMSS`: the last in alphabetical order). If there is none, tell the user to run `/penkit-remediate` first and stop. Read the file: its `guidance` and the meaning of its fields are described in the `penkit-remediate` skill.

2. **State of the code.** Compare `project.commit` with the current commit (`git rev-parse --short HEAD`). If they differ, say so in one sentence: the code may have changed since the proposals were written, so each change will be checked against the current code. If `git status` shows uncommitted changes, say so too: the user will want to tell them apart from the fixes in `git diff`.

3. **Items.** Apply the numbers given as argument (e.g. `1,3`), otherwise every item of kind `change`. Never apply an item of kind `false_positive`, even if its number is given: say why it is left alone (its `rationale`). An item of kind `rerun` is not a change in the project: recall what it says to do before running the tool again. If a number does not exist, say so. Before changing anything, list in a few lines the items you are going to apply (number, severity, title).

4. **Apply**, item by item, in the order of the `id`s:
   - Read the code at the item's `files` and around them before changing it: the lines may have moved, `before` may no longer match exactly. Implement what `change` describes, in the style of the project; `after` is an example, not text to paste blindly.
   - If the proposal no longer fits the code (code already fixed, file removed, rationale no longer true), do not force it: skip the item and say why.
   - Stay within the item: no refactoring, no change that it does not describe.
   - `commands` (installing or upgrading a package, regenerating a lockfile): show each command and run it only once the user has agreed.
   - `manual_steps` (revoking and renewing a secret, purging the git history): never run them yourself, even if asked in passing for the git history, which rewrites it for everyone. Keep them for the summary.
   - A secret moved out of the code: read it from the environment (or the secret manager the project already uses), and never copy its value into your answer, a commit message or a new file.

5. **No checks.** Run neither the project's tests nor `penkit audit`: checking the changes is left to the user.

6. **Summary** in the chat:
   - one line per item: applied, skipped (why) or partially applied;
   - the files changed and the commands run;
   - the `manual_steps` left to the user, first if they concern a secret: revoking it is the only real fix, the code change alone is not enough;
   - how to check: run `/penkit-audit` again (`--only` the tools of the applied items), after restarting the app if ZAP is among them, so that it scans the changed code.

   Do not commit: the user reviews the changes with `git diff` and commits them. The reports and `remediation.json` stay in `penkit/reports/<date>/`, ignored by git: never suggest committing them.
