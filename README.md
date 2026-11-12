# penkit

Security audit of a web app, run from Claude Code, with four open source tools at pinned versions and a single HTML report.

| Tool | What it covers |
| --- | --- |
| **Betterleaks** 1.9.0 | Exposed secrets (API keys, tokens, passwords), in the files and the git history |
| **Semgrep** 1.182.0 | Flaws in the code (SAST): injections, XSS, SSRF, eval, weak crypto… |
| **OSV-Scanner** 2.7.0 | Known vulnerabilities (CVE) and malicious packages in the dependencies |
| **Noir** 1.4.0 + **ZAP** 2.17.0 | API routes mapped from the code, then attacked on the running app (DAST) |

Out of scope: IDOR and business logic, routes behind authentication, Docker configuration and infrastructure.

## Getting Started

Requirements: Linux x86_64 or arm64, Python 3.11+, git, Docker, pipx, `~/.local/bin` in the PATH.

1. **Download and install** (once per machine): installs the `penkit` command and the tools at their pinned versions, after checking their commits and checksums.

   ```bash
   git clone https://github.com/monokraum/penkit.git
   penkit/install.sh
   ```

2. **Prepare the project** (once per project), from the root of the repository to audit:

   ```bash
   penkit init
   ```

   It asks for the address of the running app, creates `.penkit.toml`, adds the report folder to `.gitignore` and links the `penkit-audit` skill into the project.

3. **Run the audit** in Claude Code, from the project: `/penkit-audit`, or simply ask "run the security audit". Claude has the ZAP target confirmed, runs the four tools and summarizes the results.

> ⚠️ ZAP runs an **active scan** (real payloads: creations, updates, injections). Only on a local or staging instance with a database that can be recreated, never in production. penkit refuses a non-local URL unless `allow_remote = true`.

## The report

Each audit writes a static report in `penkit/reports/<date>/` at the root of the project, ignored by git since it describes the app's vulnerabilities. Open `index.html`:

- **Overview**: verdict, totals by severity and one card per tool;
- **Reports by tool**: summary of each tool, with links to its detailed results, its native report (full ZAP and OSV-Scanner HTML reports), its raw JSON and its log.

The pages need no JavaScript or network access: they open offline.

![Overview page of a penkit report (demo data)](docs/report-overview.png)
