---
name: penkit-audit
description: "Full security audit of the project with penkit: secrets (betterleaks), flaws in the code (semgrep), vulnerable dependencies (osv-scanner) and scan of the running app (Noir + ZAP), then an HTML report with an overview and each tool's report. Use when the user asks for \"penkit audit\", a security audit, scan or analysis of the project (in any language), or wants to check that a security fix removed a finding."
argument-hint: "[--only betterleaks,semgrep,osv-scanner,noir-zap]"
allowed-tools:
  - Bash(penkit audit)
  - Bash(penkit audit *)
---

# penkit audit

Runs penkit's four scans on the current project and summarizes the report. The `penkit` command does all the work; your role is to have the target confirmed, run it from the project root, then summarize the result without overwhelming the user. Answer in the user's language.

This skill is a link to the penkit repository, created by `penkit init`: do not edit it from the project.

## Steps

1. **ZAP target.** Read `[app] url` in `.penkit.toml` (if the file is missing, the user must run `penkit init` first: see step 2). ZAP will run an **active scan** against it: it sends real payloads (creations, updates, injections). If this is the first scan in this conversation, say so in one sentence and check with the user that the app runs on a local or staging instance with a database that can be recreated, never production. If the app is not running, offer to start it (based on the project's README) or to run anyway: ZAP will then be marked "Not run" and the three other tools will run normally.

2. **Run.** The ZAP scan takes from a few seconds to several minutes: run the command in the background and wait for it to finish.

   ```bash
   penkit audit $ARGUMENTS
   ```

   `--only` restricts the scan to some tools (`betterleaks`, `semgrep`, `osv-scanner`, `noir-zap`, comma-separated): useful to re-check quickly after a fix.

   Exit codes: `0` scan finished (with or without findings), `1` at least one tool failed, `2` refused before starting: `penkit audit` itself checks the tools, the configuration and the `.gitignore`.

   If it refuses, show the output and tell the user what to run in their terminal (or with `! <command>` in the prompt), without running it yourself:
   - a tool is missing or has a different version: `penkit install` (it installs software; `penkit install --fix` to replace a different version);
   - `.penkit.toml` is missing or invalid, or `penkit/` is not ignored by git: `penkit init` (it edits the `.gitignore`).

3. **Summarize.** Read `summary.json` in the directory given by the `Report:` line and give the user:
   - the overall verdict in one sentence (number of findings by severity, tools that failed or did not run);
   - one line per tool: its status and its summary;
   - the 3 to 5 most severe findings, if any, with their location;
   - the link to the report, copied as-is from the `Link:` line of the output (a `file://` URL), alone on its line so that it opens in one click in the browser. Do not rebuild it by hand.

   Do not interpret a finding beyond what it says: a Semgrep or ZAP finding is something to examine, not a confirmed vulnerability. The reports are in the project's `penkit/reports/<date>/`, ignored by git: never suggest committing them, they describe the app's vulnerabilities.

4. **Next.**
   - If the audit found nothing other than Info findings: stop there.
   - Otherwise, offer in one sentence to run `/penkit-remediate`: it reads the code behind each finding and proposes the changes to make in the project, ranked by severity, without applying them. Run it only if the user agrees.
