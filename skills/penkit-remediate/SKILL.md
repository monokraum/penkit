---
name: penkit-remediate
description: "Proposes the changes to make in the project (code, dependencies, configuration) to address the findings of the last penkit audit, ranked by severity, after reading the code behind each finding, and saves them in remediation.json for a coding agent. Does not apply them. Use after /penkit-audit, or when the user asks how to fix, remediate or address the findings of a penkit audit (in any language)."
argument-hint: "[penkit/reports/<date>]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash(ls penkit/reports*)
  - Write(penkit/reports/**/remediation.json)
  - Bash(python3 -m json.tool penkit/reports/*)
---

# penkit remediate

Turns the findings of a penkit audit into a list of changes to make in the project, ranked by severity, presented in the chat and saved in `remediation.json` next to the report, for a coding agent that will implement them (`/penkit-fix`, or another one). The audit says what is wrong; your role is to say what to change, where and why, after reading the code. You **propose**: you do not change any project file, `/penkit-fix` applies the changes. Answer in the user's language.

This skill is a link to the penkit repository, created by `penkit init`: do not edit it from the project.

## Steps

1. **Report.** Use the directory given as argument, otherwise the most recent one in `penkit/reports/` (the names are timestamps `YYYYMMDD-HHMMSS`: the last in alphabetical order). Read its `summary.json`: `tools[]` gives each tool's `status`, and its `findings[]`, each with `severity`, `title`, `location` and `detail`. For more context on a finding, the tool's raw JSON is listed in its `reports[]` (paths relative to the report directory).

2. **Scope.** Keep the findings of every severity except `info`. If none is left, say so in one sentence and stop. A tool with the status `error` or `skipped` becomes an item of the list ("re-run X", with the reason given in its `summary` and `notes`): until it runs, the list is incomplete, and you say so.

3. **Group.** One item per change, not per finding: every finding that the same change fixes goes in the same item. For example, all the URLs where ZAP reports the same missing header (one middleware or config change), all the CVEs of the same package (one upgrade), the same Semgrep rule repeated in a helper used everywhere (one change in the helper).

4. **Read and decide.** For each group, open the code at the reported locations and around them (callers, the framework's configuration, the dependency manifests), then write down the change. What to check for each tool:
   - **Betterleaks (secret).** A committed secret must be considered compromised: the change is always to **revoke and renew** it with its provider, then read it from the environment or a secret manager instead of the code. Never copy the value of a secret into your answer, even redacted. If the finding is only in the git history (`commit` in `detail`, file gone or changed), say so: purging the history (`git filter-repo`, then a force push) rewrites it for everyone, it is a separate operation for the user to decide, never part of the changes you apply. A test fixture, example or obviously fake value is a probable false positive.
   - **Semgrep (code).** Follow the data: does the flagged value come from the user (request, file, environment), and is it already validated or escaped further up? If not, propose the fix that fits the project's language and framework (parameterized query, the framework's escaping, allow-list, safe API). If the value cannot be controlled by an attacker, it is a probable false positive.
   - **OSV-Scanner (dependency).** `detail` gives the fixed versions. Find whether the package is a direct dependency (manifest) or a transitive one (via which package), and give the change: version to require, command of the ecosystem's package manager, lockfile to regenerate. Flag a major version change (breaking changes possible). With no fixed version published: an alternative, a mitigation in the code, or the risk to accept, stated as such.
   - **ZAP (running app).** `detail` gives ZAP's generic solution: find where it applies in this project (middleware, framework settings, server or reverse proxy configuration in the repository). If the fix is outside the repository (infrastructure, CDN), say so.

   A finding is something to examine, not a confirmed vulnerability. When the code shows it is a false positive, say so with the reason instead of proposing a change; when you cannot decide, say what is missing to decide.

5. **Rank.** By the highest severity of the group (`critical`, `high`, `medium`, `low`, then `unknown`), then by number of findings fixed. The items "re-run X" come after the changes, then the probable false positives, in a section of their own.

6. **Save** the list in `remediation.json`, in the report directory (it overwrites the one of a previous run on the same report), then check it with `python3 -m json.tool <path>`. It is read by a coding agent that has not seen this conversation: each item must be enough on its own to implement the change. Keys in English, text in the user's language, paths relative to the project root:

   ```json
   {
     "schema_version": 1,
     "report": "penkit/reports/20261113-102300",
     "generated": "2026-11-13T10:41:00+01:00",
     "project": {"name": "shop", "commit": "dabcd6e", "branch": "main"},
     "guidance": "Changes proposed from a penkit audit, not verified fixes. Apply only the items requested, read the code before changing it, do not run the commands or the manual steps without asking the user.",
     "items": [
       {
         "id": 1,
         "kind": "change",
         "severity": "high",
         "title": "SQL injection in the product search",
         "tool": "semgrep",
         "findings": [{"severity": "high", "title": "sqlalchemy-execute-raw-query", "location": "app/search.py:42"}],
         "files": ["app/search.py:42"],
         "change": "Replace the f-string query with a parameterized query (text() with bind parameters).",
         "rationale": "q comes from the query string and reaches execute() without escaping.",
         "before": "db.execute(f\"SELECT * FROM products WHERE name LIKE '%{q}%'\")",
         "after": "db.execute(text(\"SELECT * FROM products WHERE name LIKE :q\"), {\"q\": f\"%{q}%\"})",
         "commands": [],
         "manual_steps": [],
         "regression_risk": null
       }
     ]
   }
   ```

   - `id`: the number of the item in the chat, so that "apply 3" means the same item for the user and for the coding agent.
   - `kind`: `change` (a change to make), `rerun` (a tool to run again: `change` gives the reason and what to fix first, `files` is empty), or `false_positive` (`rationale` gives the reason, the coding agent leaves it alone).
   - `project`: copied from `summary.json`; `commit` tells the coding agent which state of the code the proposals were written for.
   - `findings`: the findings covered, copied from `summary.json` (`severity`, `title`, `location`), so that the coding agent can find them in the report.
   - `before` / `after`: a short extract when it makes the change clearer, otherwise `null`.
   - `commands`: commands that change the project (upgrade a package, regenerate a lockfile); `manual_steps`: what no agent can do in the code (revoke and renew a secret with its provider, purge the git history). Both are run by the user or with their approval.
   - No secret value, even redacted, anywhere in the file.

7. **Present** the list in the chat, numbered like the `id`s, one block per item:
   - severity, short title, tool and number of findings covered;
   - files to change (`path:line`), or the command to run;
   - the change, and why it fixes the finding, in two or three sentences;
   - a short before/after extract when it makes the change clearer;
   - the risk of regression, if any (major upgrade, behavior change for the users).

   Then give the path of `remediation.json`.

8. **Next.** If the list has at least one item of kind `change`, offer in one sentence to run `/penkit-fix` to apply them: all of them, or only the numbers the user gives (`/penkit-fix 1,3`). Run it only if the user agrees. Otherwise, stop there.

The reports and `remediation.json` are in the project's `penkit/reports/<date>/`, ignored by git: never suggest committing them, they describe the app's vulnerabilities.
