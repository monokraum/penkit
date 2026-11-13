"""Tests without network or tools: python3 -m unittest discover -s tests"""
import json
import subprocess
import tomllib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import penkit  # noqa: E402
import report  # noqa: E402


def cfg(url="http://localhost:8000", **over):
    c = {"app": {"url": url, "allow_remote": False}, "semgrep": {"configs": ["p/ci"]},
         "zap": {"mode": "api", "timeout_minutes": 60}}
    for k, v in over.items():
        c[k].update(v)
    return c


class ConfigTest(unittest.TestCase):
    def test_local_url_accepted(self):
        for url in ("http://localhost:8000", "http://127.0.0.1:3000", "https://[::1]:8443"):
            self.assertEqual(penkit.validate_config(cfg(url)), [], url)

    def test_remote_url_refused_unless_allowed(self):
        self.assertTrue(penkit.validate_config(cfg("https://example.com")))
        self.assertEqual(penkit.validate_config(cfg("https://staging.example.com", app={"allow_remote": True})), [])

    def test_bad_values(self):
        self.assertTrue(penkit.validate_config(cfg("localhost:8000")))
        self.assertTrue(penkit.validate_config(cfg(zap={"mode": "full"})))
        self.assertTrue(penkit.validate_config(cfg(semgrep={"configs": []})))

    def test_unknown_keys_refused(self):
        c = cfg()
        c["reports"] = {"dir": "~/penkit-reports"}
        c["zap"]["timeout"] = 5
        errs = penkit.validate_config(c)
        self.assertTrue(any(e.startswith("[reports] unknown section") for e in errs), errs)
        self.assertTrue(any("[zap] timeout: unknown key" in e for e in errs), errs)

    def test_template_has_only_known_keys(self):
        with tempfile.TemporaryDirectory() as d:
            penkit.write_default_config(Path(d), "http://localhost:8000")
            raw = tomllib.loads((Path(d) / ".penkit.toml").read_text())
            self.assertEqual(set(raw), set(penkit.CONFIG_SCHEMA))
            for section, keys in raw.items():
                self.assertEqual(set(keys), penkit.CONFIG_SCHEMA[section], section)

    def test_default_config_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "pyproject.toml").write_text("")
            (p / "package.json").write_text("{}")
            penkit.write_default_config(p, "http://localhost:9000")
            self.assertTrue((p / ".penkit.toml").is_file())
            self.assertFalse((p / "penkit").exists())      # only created by penkit audit
            c = penkit.load_config(p)
            self.assertEqual(c["app"]["url"], "http://localhost:9000")
            self.assertIn("p/python", c["semgrep"]["configs"])
            self.assertIn("p/javascript", c["semgrep"]["configs"])
            self.assertEqual(penkit.validate_config(c), [])


class PenkitDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.p)], check=True)
        (self.p / "app.py").write_text("x = 1\n")
        penkit.write_default_config(self.p, "http://localhost:8000")
        self.msgs = penkit.ensure_gitignored(self.p)
        for sub in ("wrk", "reports/20260101-000000/raw"):
            (self.p / "penkit" / sub).mkdir(parents=True)
        (self.p / "penkit/wrk/endpoints.json").write_text("{}")
        (self.p / "penkit/reports/20260101-000000/raw/zap.json").write_text("{}")

    def tearDown(self):
        self.tmp.cleanup()

    def gitignore(self):
        return (self.p / ".gitignore").read_text()

    def test_config_tracked_outputs_ignored(self):
        files = penkit.tracked_files(self.p)
        self.assertIn(".penkit.toml", files)
        self.assertIn(".gitignore", files)
        self.assertFalse([f for f in files if f.startswith("penkit/")], files)
        self.assertTrue(penkit.penkit_ignored(self.p))
        self.assertIn("\n/penkit/\n", "\n" + self.gitignore())

    def test_gitignore_idempotent(self):
        before = self.gitignore()
        self.assertEqual(penkit.ensure_gitignored(self.p), [])
        self.assertEqual(self.gitignore(), before)

    def test_gitignore_appended_after_existing_content(self):
        (self.p / ".gitignore").write_text("node_modules/")        # no trailing newline
        penkit.ensure_gitignored(self.p)
        self.assertEqual(self.gitignore(), f"node_modules/\n\n{penkit.GITIGNORE_COMMENT}\n/penkit/\n"
                                           "/.claude/skills/penkit-audit\n/.claude/skills/penkit-remediate\n"
                                           "/.claude/skills/penkit-fix\n")

    def test_existing_patterns_are_enough(self):
        (self.p / ".gitignore").write_text("penkit/\n.claude\n")
        self.assertEqual(penkit.ensure_gitignored(self.p), [])
        self.assertEqual(self.gitignore(), "penkit/\n.claude\n")

    def test_only_missing_entry_added(self):
        (self.p / ".gitignore").write_text("/penkit/\n")
        penkit.ensure_gitignored(self.p)
        self.assertEqual(self.gitignore(), f"/penkit/\n\n{penkit.GITIGNORE_COMMENT}\n/.claude/skills/penkit-audit\n"
                                           "/.claude/skills/penkit-remediate\n/.claude/skills/penkit-fix\n")

    def test_new_skill_link_added_to_older_gitignore(self):
        (self.p / ".gitignore").write_text("/penkit/\n/.claude/skills/penkit-audit\n")
        penkit.ensure_gitignored(self.p)
        self.assertEqual(self.gitignore(), "/penkit/\n/.claude/skills/penkit-audit\n\n"
                                           f"{penkit.GITIGNORE_COMMENT}\n/.claude/skills/penkit-remediate\n"
                                           "/.claude/skills/penkit-fix\n")

    def test_skill_links_created_ignored_and_idempotent(self):
        msgs = penkit.ensure_skill_links(self.p)
        self.assertEqual(len(msgs), 3)
        for name, msg in zip(("penkit-audit", "penkit-remediate", "penkit-fix"), msgs):
            link = self.p / ".claude/skills" / name
            self.assertTrue(msg.endswith("(created)"), msg)
            self.assertEqual(link.resolve(), penkit.skill_src(name).resolve())
            self.assertTrue((link / "SKILL.md").is_file())
            self.assertNotIn(f".claude/skills/{name}", penkit.tracked_files(self.p))
        self.assertFalse([m for m in penkit.ensure_skill_links(self.p) if "created" in m])

    def test_skill_link_fixed_but_real_folder_untouched(self):
        link = self.p / ".claude/skills/penkit-audit"
        link.parent.mkdir(parents=True)
        link.symlink_to(self.p / "old-penkit")
        self.assertIn("fixed", penkit.ensure_skill_links(self.p)[0])
        self.assertEqual(link.resolve(), penkit.skill_src("penkit-audit").resolve())
        link.unlink()
        link.mkdir()
        self.assertTrue(penkit.ensure_skill_links(self.p)[0].startswith("✘"))
        self.assertTrue(link.is_dir() and not link.is_symlink())

    def test_earlier_negation_cannot_reinclude(self):
        # Git cannot re-include a file whose parent directory is excluded: /penkit/ wins.
        (self.p / ".gitignore").write_text("!penkit/reports/x.json\n")
        msgs = penkit.ensure_gitignored(self.p)
        self.assertFalse([m for m in msgs if m.startswith("✘")], msgs)
        self.assertTrue(penkit.penkit_ignored(self.p))

    def test_noir_copy_excludes_outputs_even_without_gitignore(self):
        (self.p / ".gitignore").unlink()
        with tempfile.TemporaryDirectory() as dest:
            penkit.export_sources(self.p, Path(dest))
            self.assertTrue((Path(dest) / "app.py").exists())
            self.assertTrue((Path(dest) / ".penkit.toml").exists())
            self.assertFalse((Path(dest) / "penkit").exists())

    def test_fresh_wrk_empties_folder(self):
        w = penkit.fresh_wrk(self.p)
        self.assertEqual(list(w.iterdir()), [])

    def test_betterleaks_config_extends_project_rules(self):
        ctx = penkit.Ctx(self.p, {}, {}, self.p / "penkit/reports/x", penkit.fresh_wrk(self.p))
        self.assertIn("useDefault = true", penkit.betterleaks_config(ctx).read_text())
        (self.p / ".gitleaks.toml").write_text("")
        text = penkit.betterleaks_config(ctx).read_text()
        self.assertIn(str(self.p / ".gitleaks.toml"), text)
        self.assertIn('paths = ["^penkit/"]', text)


class LockTest(unittest.TestCase):
    def test_lock_complete(self):
        lock = penkit.load_lock()
        self.assertEqual(set(lock), set(penkit.CHECKS))
        for tid in ("betterleaks", "osv-scanner", "noir"):
            self.assertRegex(lock[tid]["commit"], r"^[0-9a-f]{40}$")
            sums = lock[tid].get("archive_sha256") or lock[tid]["binary_sha256"]
            for arch in ("x86_64", "aarch64"):
                self.assertRegex(sums[arch], r"^[0-9a-f]{64}$", f"{tid} {arch}")
        self.assertRegex(lock["zap"]["digest"], r"^sha256:[0-9a-f]{64}$")


class ParsingTest(unittest.TestCase):
    def test_normalize_spec_merges_double_slashes(self):
        spec = {"paths": {"/api/x": {"get": {"a": 1}}, "//api/x": {"get": {"a": 2}, "post": {}},
                          "//health": {"get": {}}}}
        out, dupes = penkit.normalize_spec(spec)
        self.assertEqual(dupes, 1)
        self.assertEqual(sorted(out["paths"]), ["/api/x", "/health"])
        self.assertEqual(out["paths"]["/api/x"]["get"], {"a": 1})
        self.assertIn("post", out["paths"]["/api/x"])

    def test_cvss_level(self):
        self.assertEqual([penkit.cvss_level(s) for s in ("9.8", "7.0", "5.3", "0.1", "", None)],
                         ["critical", "high", "medium", "low", "unknown", "unknown"])


class ReportTest(unittest.TestCase):
    def summary(self):
        tool = lambda tid, status, findings: penkit.result(tid, status=status, summary=f"{tid} summary",
                                                          findings=findings, version="1.0")
        return {
            "penkit_version": "test", "target_url": "http://localhost:8000",
            "started": "2026-11-11T18:00:00+01:00", "finished": "2026-11-11T18:01:00+01:00",
            "project": {"name": "demo", "path": "/x", "commit": "abc1234", "branch": "main", "dirty": False},
            "tools": [
                tool("betterleaks", "ok", []),
                tool("semgrep", "findings", [{"severity": "high", "title": "<script>alert(1)</script>",
                                              "location": "a.py:1", "ref": "javascript:alert(1)"}]),
                tool("osv-scanner", "skipped", []),
                tool("noir-zap", "error", []),
            ],
        }

    def test_build_escapes_and_links(self):
        with tempfile.TemporaryDirectory() as d:
            run = Path(d)
            (run / "summary.json").write_text(json.dumps(self.summary()))
            report.build(run)
            for name in ("index.html", "reports.html", "assets/penkit.css",
                         "tools/betterleaks.html", "tools/semgrep.html", "tools/osv-scanner.html", "tools/noir-zap.html"):
                self.assertTrue((run / name).exists(), name)
            detail = (run / "tools/semgrep.html").read_text()
            self.assertNotIn("<script>alert", detail)
            self.assertIn("&lt;script&gt;", detail)
            self.assertNotIn('href="javascript:', detail)
            index = (run / "index.html").read_text()
            self.assertIn("1 critical or high issue", index)
            self.assertIn("Incomplete analysis", index)
            self.assertIn('href="reports.html#noir-zap"', index)


if __name__ == "__main__":
    unittest.main()
