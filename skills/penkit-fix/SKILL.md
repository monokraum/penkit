---
name: penkit-fix
description: "Applies to the project the changes proposed by /penkit-remediate in remediation.json (all of them, or the numbers given), on a dedicated git branch with one commit per item, then pushes the branch and opens a merge request (pull request). Use after /penkit-remediate, or when the user asks to apply, implement or fix the items of a penkit remediation (in any language)."
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
  - Bash(git log *)
  - Bash(git branch *)
  - Bash(git remote *)
  - Bash(git switch -c penkit-fix/*)
  - Bash(git add *)
  - Bash(git commit *)
  - Bash(git push -u origin penkit-fix/*)
  - Bash(gh repo view *)
  - Bash(gh pr create *)
  - Bash(glab repo view *)
  - Bash(glab mr create *)
---

# penkit fix

Applies to the project the changes listed in the `remediation.json` written by `/penkit-remediate`, on a dedicated git branch with one commit per item, then pushes the branch and opens a merge request. The list says what to change and why; your role is to implement it in the code as it is now, without going beyond it. Answer in the user's language.

This skill is a link to the penkit repository, created by `penkit init`: do not edit it from the project.

## Steps

1. **Remediation.** Use the report directory given as argument, otherwise the most recent one in `penkit/reports/` that contains a `remediation.json` (the names are timestamps `YYYYMMDD-HHMMSS`: the last in alphabetical order). If there is none, tell the user to run `/penkit-remediate` first and stop. Read the file: its `guidance` and the meaning of its fields are described in the `penkit-remediate` skill.

2. **State of the code.**
   - Compare `project.commit` with the current commit (`git rev-parse --short HEAD`). If they differ, say so in one sentence: the code may have changed since the proposals were written, so each change will be checked against the current code.
   - The tracked files must have no uncommitted change (`git status --porcelain --untracked-files=no` is empty): otherwise they would end up in the fix commits. If there are some, show them and stop: the user commits or stashes them, you do not do it for them.
   - Note the current branch (`git branch --show-current`): it is the base of the fix branch and the target of the merge request. If HEAD is detached, stop and ask the user which branch to start from.

3. **Items.** Apply the numbers given as argument (e.g. `1,3`), otherwise every item of kind `change`. Never apply an item of kind `false_positive`, even if its number is given: say why it is left alone (its `rationale`). An item of kind `rerun` is not a change in the project: recall what it says to do before running the tool again. If a number does not exist, say so. Before changing anything, list in a few lines the items you are going to apply (number, severity, title).

4. **Branch.** Create the branch `penkit-fix/<report directory name>` (e.g. `penkit-fix/20261113-102300`) from the current commit with `git switch -c`. If it already exists, add `-2`, `-3`… Never reuse or reset an existing branch.

5. **Apply and commit**, item by item, in the order of the `id`s:
   - Read the code at the item's `files` and around them before changing it: the lines may have moved, `before` may no longer match exactly. Implement what `change` describes, in the style of the project; `after` is an example, not text to paste blindly.
   - If the proposal no longer fits the code (code already fixed, file removed, rationale no longer true), do not force it: skip the item, without a commit, and say why.
   - Stay within the item: no refactoring, no change that it does not describe.
   - `commands` (installing or upgrading a package, regenerating a lockfile): show each command and run it only once the user has agreed. If they refuse, skip the item.
   - `manual_steps` (revoking and renewing a secret, purging the git history): never run them yourself, even if asked in passing for the git history, which rewrites it for everyone. Keep them for the merge request and the summary.
   - A secret moved out of the code: read it from the environment (or the secret manager the project already uses), and never copy its value into your answer, a commit message, the merge request or a new file.
   - **One commit per item**, as soon as it is applied: `git add` only the files of this item, by name (never `git add -A` or `git add .`), and check with `git diff --cached --stat` that nothing else is staged. Follow the commit message conventions of the project if `git log` shows some; otherwise a subject such as `fix(security): <item title>` and a short body with the severity, the tool, the findings covered (`location`) and the `rationale`, ending with `penkit remediation item <id>`.
   - If a git hook refuses the commit, never bypass it (`--no-verify`): fix the cause if it is within the item, otherwise undo this item's changes (`git restore --staged --worktree <its files>`, only the files you changed for it), skip it and say why.

6. **No checks.** Run neither the project's tests nor `penkit audit`: checking the changes is left to the user and to the merge request's review.

7. **Push and merge request.** If no item was committed, push nothing and open no merge request: say so and go to the summary.
   - Find the forge from `git remote get-url origin`: GitHub (`gh`) or GitLab (`glab`). If there is no `origin` remote, if the forge is another one, or if its CLI is missing or not authenticated, do not push: give the user the commands to run and go to the summary.
   - The commits and the merge request describe vulnerabilities that are not fixed in production yet. If the repository is public (`gh repo view --json visibility`, `glab repo view`), say so and push only once the user has agreed.
   - Push with `git push -u origin <branch>`, then open the merge request towards the base branch noted at step 2: `gh pr create --base <base> --head <branch>` or `glab mr create --target-branch <base> --source-branch <branch>`, with a title such as `Security fixes from the penkit audit of <date>` and a description that lists:
     - the items applied, one line each: number, severity, title, short commit hash;
     - the items skipped, with the reason;
     - the commands run;
     - the `manual_steps` left to do, first if they concern a secret: revoking it is the only real fix, the code change alone is not enough;
     - that the changes were checked neither by the tests nor by a new audit: run `/penkit-audit` again on the branch (after restarting the app if ZAP is concerned).

     No secret value and no local path (the report stays on the machine that ran the audit).

8. **Summary** in the chat:
   - the branch, and one line per item: committed (short hash), skipped (why) or partially applied;
   - the commands run;
   - the link to the merge request, or why it was not created and the commands to run;
   - the `manual_steps` left to the user, first if they concern a secret;
   - how to check: run `/penkit-audit` again on the branch (`--only` the tools of the applied items), after restarting the app if ZAP is among them, so that it scans the changed code.

   The reports and `remediation.json` stay in `penkit/reports/<date>/`, ignored by git: never commit them, they describe the app's vulnerabilities.
