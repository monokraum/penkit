#!/usr/bin/env python3
"""penkit — security audit of a web app with betterleaks, semgrep, osv-scanner and Noir + ZAP.

    penkit.py install [--fix]       install / verify the tools (run again after changing tools.lock.toml)
    penkit.py init    [--url URL]   prepare the project: .penkit.toml, .gitignore, links to the penkit skills
    penkit.py audit   [--only a,b]  run the scans and build the HTML report

The audited project is the git repository of the current directory.

Standard library only (Python 3.11+).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LOCK_FILE = ROOT / "tools.lock.toml"
PENKIT_DIR = "penkit"                 # penkit outputs in the audited project (ignored by git)
CONFIG_NAME = ".penkit.toml"
BIN_DIR = Path.home() / ".local" / "bin"
SKILL_NAME = "penkit-audit"                       # entry point, named in the "Ready" message
SKILL_NAMES = (SKILL_NAME, "penkit-remediate")   # skills linked into the project by penkit init
TOOL_IDS = ["betterleaks", "semgrep", "osv-scanner", "noir-zap"]
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


# ───────────────────────────── utilities ─────────────────────────────

def say(msg: str = "") -> None:
    print(msg, flush=True)


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    env = {**os.environ, "NO_COLOR": "1", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    return subprocess.run(cmd, capture_output=True, text=True, env=env, **kw)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def arch() -> str:
    m = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(m, m)


def load_lock() -> dict:
    with open(LOCK_FILE, "rb") as f:
        return tomllib.load(f)


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "penkit"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def tag_commit(repo: str, version: str) -> str:
    """Commit the vX.Y.Z tag points to (the ^{} line for an annotated tag)."""
    out = run(["git", "ls-remote", repo, f"refs/tags/v{version}", f"refs/tags/v{version}^{{}}"], timeout=60)
    lines = dict(reversed(line.split("\t")) for line in out.stdout.strip().splitlines() if "\t" in line)
    return lines.get(f"refs/tags/v{version}^{{}}") or lines.get(f"refs/tags/v{version}", "")


def find_project() -> Path:
    p = Path.cwd().resolve()
    top = run(["git", "-C", str(p), "rev-parse", "--show-toplevel"])
    return Path(top.stdout.strip()) if top.returncode == 0 else p


# ───────────────────────────── tool checks ─────────────────────────────

@dataclass
class Check:
    id: str
    name: str
    expected: str
    state: str = "absent"            # ok | absent | mismatch | error
    found: str = ""                  # version found
    path: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.state == "ok"


def _check_binary(c: Check, lock: dict, version_cmd: list[str], parse) -> Check:
    p = shutil.which(c.id)
    if not p:
        return c
    c.path = p
    out = run([p, *version_cmd], timeout=30)
    c.found, extra = parse(out.stdout + out.stderr)
    problems = []
    if c.found != c.expected:
        problems.append(f"version {c.found or '?'} instead of {c.expected}")
    problems += extra
    want = lock.get("binary_sha256", {}).get(arch())
    if want:
        got = sha256(Path(p))
        if got != want:
            problems.append(f"binary checksum differs ({got[:12]}… instead of {want[:12]}…)")
    else:
        c.notes.append(f"no pinned binary checksum for {arch()}: only the version was checked")
    c.state = "mismatch" if problems else "ok"
    c.notes = problems + c.notes
    return c


def check_betterleaks(lock):
    c = Check("betterleaks", "Betterleaks", lock["version"])
    return _check_binary(c, lock, ["version"], lambda s: (s.strip().splitlines()[-1].strip() if s.strip() else "", []))


def check_osv(lock):
    c = Check("osv-scanner", "OSV-Scanner", lock["version"])

    def parse(s):
        v = re.search(r"osv-scanner version:\s*(\S+)", s)
        cm = re.search(r"commit:\s*([0-9a-f]{40})", s)
        extra = [] if cm and cm.group(1) == lock["commit"] else [f"commit {cm.group(1)[:12] if cm else '?'}… instead of {lock['commit'][:12]}…"]
        return (v.group(1) if v else ""), extra
    return _check_binary(c, lock, ["--version"], parse)


def check_noir(lock):
    c = Check("noir", "Noir", lock["version"])
    return _check_binary(c, lock, ["--version"], lambda s: ((re.search(r"\d+\.\d+\.\d+", s) or [""])[0], []))


def check_semgrep(lock):
    c = Check("semgrep", "Semgrep", lock["version"])
    p = shutil.which("semgrep")
    if not p:
        return c
    c.path = p
    out = run([p, "--version", "--disable-version-check"], timeout=60)
    m = re.search(r"\d+\.\d+\.\d+", out.stdout)
    c.found = m.group(0) if m else ""
    c.state = "ok" if c.found == c.expected else "mismatch"
    if not c.ok:
        c.notes.append(f"version {c.found or '?'} instead of {c.expected}")
    return c


def zap_ref(lock) -> str:
    return f"{lock['image']}@{lock['digest']}"


def check_zap(lock):
    c = Check("zap", "ZAP (Docker image)", lock["version"])
    if not shutil.which("docker"):
        c.state, c.notes = "error", ["Docker missing: install it, then add your account to the docker group"]
        return c
    info = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if info.returncode != 0:
        c.state = "error"
        c.notes = ["Docker daemon unreachable (is it running? is your account in the docker group?)"]
        return c
    ref = zap_ref(lock)
    c.path = ref
    insp = run(["docker", "image", "inspect", "--format", '{{index .Config.Labels "org.opencontainers.image.version"}}', ref], timeout=30)
    if insp.returncode != 0:
        return c                     # absent: to be pulled by digest
    c.found = insp.stdout.strip() or lock["version"]
    c.state = "ok"
    return c


CHECKS = {
    "betterleaks": check_betterleaks,
    "semgrep": check_semgrep,
    "osv-scanner": check_osv,
    "noir": check_noir,
    "zap": check_zap,
}


def check_all(lock: dict) -> list[Check]:
    return [fn(lock[k]) for k, fn in CHECKS.items()]


def print_checks(checks: list[Check]) -> None:
    icon = {"ok": "✔", "absent": "✘", "mismatch": "≠", "error": "!"}
    label = {"ok": "OK", "absent": "missing", "mismatch": "different", "error": "error"}
    for c in checks:
        found = c.found or "—"
        say(f"  {icon[c.state]} {c.name:<20} expected {c.expected:<9} found {found:<9} {label[c.state]:<10} {c.path}")
        for n in c.notes:
            say(f"      · {n}")


# ───────────────────────────── installation ─────────────────────────────

def _verify_commit(lock) -> None:
    got = tag_commit(lock["repo"], lock["version"])
    if got != lock["commit"]:
        raise RuntimeError(f"STOP: tag v{lock['version']} points to {got or '?'} instead of {lock['commit']}")
    say(f"    commit of tag v{lock['version']}: OK")


def _verify_sha(path: Path, want: str | None, what: str) -> None:
    if not want:
        raise RuntimeError(f"no pinned checksum ({what}, {arch()}): installation refused")
    got = sha256(path)
    if got != want:
        raise RuntimeError(f"STOP: {what} checksum {got} instead of {want}")
    say(f"    {what} checksum: OK")


def _install_bin(src: Path, name: str) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    dest = BIN_DIR / name
    tmp = dest.with_suffix(".penkit-tmp")
    shutil.copyfile(src, tmp)
    tmp.chmod(0o755)
    tmp.replace(dest)
    say(f"    installed: {dest}")
    return dest


def install_betterleaks(lock):
    _verify_commit(lock)
    a = arch()
    url = lock["url"].format(version=lock["version"], arch=lock["arch"][a])
    with tempfile.TemporaryDirectory(prefix="penkit-") as d:
        archive = Path(d) / Path(urllib.parse.urlparse(url).path).name
        download(url, archive)
        _verify_sha(archive, lock["archive_sha256"].get(a), "archive")
        with tarfile.open(archive) as t:
            member = t.getmember("betterleaks")
            if not member.isfile():
                raise RuntimeError("unexpected archive: betterleaks is not a regular file")
            t.extract(member, d, filter="data")
        binary = Path(d) / "betterleaks"
        want = lock.get("binary_sha256", {}).get(a)
        if want:
            _verify_sha(binary, want, "binary")
        _install_bin(binary, "betterleaks")


def _install_single_binary(lock, name):
    _verify_commit(lock)
    a = arch()
    url = lock["url"].format(version=lock["version"], arch=lock["arch"][a])
    with tempfile.TemporaryDirectory(prefix="penkit-") as d:
        f = Path(d) / name
        download(url, f)
        _verify_sha(f, lock["binary_sha256"].get(a), "binary")
        _install_bin(f, name)


def install_semgrep(lock):
    if not shutil.which("pipx"):
        raise RuntimeError("pipx missing: sudo apt install pipx (or python3 -m pip install --user pipx), then run again")
    out = run(["pipx", "install", "--force", lock["pipx_spec"]], timeout=900)
    if out.returncode != 0:
        raise RuntimeError("pipx failed:\n" + out.stderr[-2000:])
    say(f"    installed with pipx: {lock['pipx_spec']}")


def install_zap(lock):
    ref = zap_ref(lock)
    say(f"    docker pull {ref}")
    out = run(["docker", "pull", ref], timeout=1800)
    if out.returncode != 0:
        raise RuntimeError("docker pull failed:\n" + out.stderr[-2000:])


INSTALLERS = {
    "betterleaks": install_betterleaks,
    "semgrep": install_semgrep,
    "osv-scanner": lambda lock: _install_single_binary(lock, "osv-scanner"),
    "noir": lambda lock: _install_single_binary(lock, "noir"),
    "zap": install_zap,
}


# ───────────────────────────── project configuration ─────────────────────────────

STACK_RULES = [
    (("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"), "p/python"),
    (("package.json",), "p/javascript"),
    (("tsconfig.json",), "p/typescript"),
    (("go.mod",), "p/golang"),
    (("pom.xml", "build.gradle", "build.gradle.kts"), "p/java"),
    (("Gemfile",), "p/ruby"),
    (("composer.json",), "p/php"),
    (("Cargo.toml",), "p/rust"),
]


def tracked_files(project: Path) -> list[str]:
    """Tracked files + untracked files not ignored by .gitignore (empty if not a git repository)."""
    out = subprocess.run(["git", "-C", str(project), "ls-files", "-z", "-co", "--exclude-standard"],
                         capture_output=True)
    if out.returncode != 0:
        return []
    return [f for f in out.stdout.decode().split("\0") if f]


def detect_semgrep_packs(project: Path) -> list[str]:
    names = {Path(f).name for f in tracked_files(project)} or {p.name for p in project.rglob("*") if p.is_file()}
    packs = ["p/owasp-top-ten", "p/security-audit", "p/secrets"]
    for files, pack in STACK_RULES:
        if names & set(files) and pack not in packs:
            packs.append(pack)
    return packs


CONFIG_TEMPLATE = """\
# penkit — project configuration, read by "penkit audit".

[app]
# Address of the RUNNING app: Noir writes it into the spec, ZAP attacks this URL.
url = "{url}"
# The active ZAP scan sends real payloads: penkit refuses any address that is
# not local. Set to true only for a disposable staging instance.
allow_remote = false

[semgrep]
# Semgrep registry rulesets (adapt to the stack).
configs = [{packs}]

[zap]
# "api"      : active scan of every route found by Noir (local / staging only)
# "baseline" : passive, non-intrusive scan of the URL only
mode = "api"
# Maximum duration of the ZAP scan, in minutes.
timeout_minutes = 60
"""


# Scan outputs (penkit/wrk/, penkit/reports/): never read back by the tools, never committed.
PENKIT_OUTPUTS = (f"{PENKIT_DIR}/",)
SKILL_LINKS = {name: f".claude/skills/{name}" for name in SKILL_NAMES}
# (path tested with git check-ignore, pattern added to .gitignore). A skill link is a
# file for git: no trailing "/", otherwise the pattern would only match a directory.
GITIGNORE_ENTRIES = ((f"{PENKIT_DIR}/probe", f"/{PENKIT_DIR}/"),
                     *((link, f"/{link}") for link in SKILL_LINKS.values()))
GITIGNORE_COMMENT = "# penkit: reports (vulnerabilities, routes, requests) and local links to the penkit skills"


def penkit_dir(project: Path) -> Path:
    return project / PENKIT_DIR


def config_path(project: Path) -> Path:
    return project / CONFIG_NAME


def wrk_dir(project: Path) -> Path:
    return penkit_dir(project) / "wrk"


def reports_dir(project: Path) -> Path:
    return penkit_dir(project) / "reports"


def ensure_penkit_dir(project: Path) -> None:
    d = penkit_dir(project)
    if d.is_symlink() or (d.exists() and not d.is_dir()):
        raise RuntimeError(f"{d} exists and is not a directory: penkit refuses to use it")
    d.mkdir(exist_ok=True)


def is_git_repo(project: Path) -> bool:
    return run(["git", "-C", str(project), "rev-parse", "--git-dir"]).returncode == 0


def git_ignored(project: Path, path: str) -> bool:
    """Is the path ignored by git? (it does not need to exist)"""
    return run(["git", "-C", str(project), "check-ignore", "-q", path]).returncode == 0


def penkit_ignored(project: Path) -> bool:
    return git_ignored(project, GITIGNORE_ENTRIES[0][0])


def ensure_gitignored(project: Path) -> list[str]:
    """Add penkit/ and the skill links to the project's .gitignore, unless they are already ignored.

    Returns the messages to print; a line starting with ✘ reports a failure.
    """
    if not is_git_repo(project):
        return []
    missing = [(probe, pattern) for probe, pattern in GITIGNORE_ENTRIES if not git_ignored(project, probe)]
    if not missing:
        return []
    gi = project / ".gitignore"
    text = gi.read_text() if gi.exists() else ""
    block = ("\n" if text and not text.endswith("\n") else "") + ("\n" if text.strip() else "")
    lines = "".join(f"{pattern}\n" for _, pattern in missing)
    with open(gi, "a") as f:
        f.write(f"{block}{GITIGNORE_COMMENT}\n{lines}")
    msgs = [f"added to {gi}: {', '.join(p for _, p in missing)}"]
    for probe, pattern in missing:
        if not git_ignored(project, probe):
            msgs.append(f"✘ {pattern} still tracked by git despite the .gitignore (a \"!\" rule?)")
    return msgs


def _ensure_link(link: Path, target: Path) -> str:
    """Create or fix the symbolic link link → target. Returns a message (✘ if refused)."""
    if link.is_symlink():
        current = Path(os.readlink(link))
        if link.resolve() == target.resolve():
            return f"{link} → {current}"
        link.unlink()
        link.symlink_to(target)
        return f"{link} → {target} (fixed, was pointing to {current})"
    if link.exists():
        return f"✘ {link} exists and is not a link: penkit leaves it alone"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    return f"{link} → {target} (created)"


def skill_src(name: str) -> Path:
    return ROOT / "skills" / name


def ensure_skill_links(project: Path) -> list[str]:
    return [_ensure_link(project / link, skill_src(name)) for name, link in SKILL_LINKS.items()]


def write_default_config(project: Path, url: str) -> Path:
    packs = ", ".join(f'"{p}"' for p in detect_semgrep_packs(project))
    path = config_path(project)
    path.write_text(CONFIG_TEMPLATE.format(url=url, packs=packs))
    return path


def fresh_wrk(project: Path) -> Path:
    """Empty penkit/wrk/: disposable working directory, recreated for every scan."""
    w = wrk_dir(project)
    if w.is_symlink():
        raise RuntimeError(f"{w} is a symbolic link: penkit refuses to empty it")
    if w.exists():
        shutil.rmtree(w)
    w.mkdir(parents=True)
    return w


def load_config(project: Path) -> dict:
    with open(config_path(project), "rb") as f:
        cfg = tomllib.load(f)
    cfg.setdefault("app", {}).setdefault("allow_remote", False)
    cfg.setdefault("semgrep", {}).setdefault("configs", ["p/owasp-top-ten", "p/security-audit", "p/secrets"])
    cfg.setdefault("zap", {}).setdefault("mode", "api")
    cfg["zap"].setdefault("timeout_minutes", 60)
    return cfg


CONFIG_SCHEMA = {
    "app": {"url", "allow_remote"},
    "semgrep": {"configs"},
    "zap": {"mode", "timeout_minutes"},
}


def validate_config(cfg: dict) -> list[str]:
    """An unknown key is an error: an outdated config must not go unnoticed."""
    errs = []
    for section, value in cfg.items():
        if section not in CONFIG_SCHEMA:
            errs.append(f"[{section}] unknown section (expected: {', '.join(f'[{s}]' for s in CONFIG_SCHEMA)})")
        elif isinstance(value, dict):
            for key in sorted(set(value) - CONFIG_SCHEMA[section]):
                errs.append(f"[{section}] {key}: unknown key (expected: {', '.join(sorted(CONFIG_SCHEMA[section]))})")
    url = cfg["app"].get("url", "")
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        errs.append(f"[app] invalid url: {url!r} (e.g. http://localhost:8000)")
    elif u.hostname not in LOCAL_HOSTS and not u.hostname.startswith("127.") and not cfg["app"]["allow_remote"]:
        errs.append(f"[app] url {url} is not local: active ZAP scan refused (allow_remote = true for a disposable staging)")
    c = cfg["semgrep"]["configs"]
    if not isinstance(c, list) or not c or not all(isinstance(x, str) and x for x in c):
        errs.append("[semgrep] configs must be a non-empty list of rulesets")
    if cfg["zap"]["mode"] not in ("api", "baseline"):
        errs.append(f"[zap] mode {cfg['zap']['mode']!r}: allowed values \"api\" or \"baseline\"")
    if not isinstance(cfg["zap"]["timeout_minutes"], int) or cfg["zap"]["timeout_minutes"] <= 0:
        errs.append("[zap] timeout_minutes must be a positive integer")
    return errs


def app_reachable(url: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "penkit"}), timeout=5) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return True, f"HTTP {e.code}"            # the app answers, even with an error
    except (urllib.error.URLError, OSError) as e:
        return False, str(getattr(e, "reason", e))


# ───────────────────────────── install / init commands ─────────────────────────────

def cmd_install(args) -> int:
    lock = load_lock()
    say(f"penkit install — tools (versions pinned in tools.lock.toml, {arch()})")
    checks = check_all(lock)
    print_checks(checks)

    fix = args.fix
    mismatched = [c for c in checks if c.state == "mismatch"]
    if mismatched and not fix and sys.stdin.isatty():
        fix = ask(f"\n  Install the pinned versions in {BIN_DIR} instead? [y/N] ").lower() in ("y", "yes")
    todo = [c for c in checks if c.state == "absent" or (c.state == "mismatch" and fix)]
    blocked = mismatched if not fix else []
    failed = []
    for c in todo:
        say(f"\n  → installing {c.name} {c.expected}")
        try:
            INSTALLERS[c.id](lock[c.id])
        except Exception as e:  # noqa: BLE001 — report it and carry on with the other tools
            failed.append(c.id)
            say(f"    ✘ {e}")

    if todo:
        say("\n  New check:")
        checks = check_all(lock)
        print_checks(checks)
        for c in checks:
            installed = BIN_DIR / c.id
            if not c.ok and c.id not in ("zap", "semgrep") and installed.exists() and c.path != str(installed):
                say(f"      · {c.path} comes before {installed} in the PATH: remove it or reorder the PATH")

    if blocked:
        say(f"\n  Different versions left untouched. To install the pinned versions in {BIN_DIR}:")
        say("    penkit install --fix")

    ok = all(c.ok for c in checks)
    say("\n" + ("✔ Tools ready" if ok else "✘ Tools not ready: fix the points above"))
    return 0 if ok else 1


def cmd_init(args) -> int:
    lock = load_lock()
    project = find_project()
    say(f"penkit init — project {project} ({arch()})")
    say("\n1. Tools (versions pinned in tools.lock.toml)")
    checks = check_all(lock)
    print_checks(checks)
    if not all(c.ok for c in checks):
        say("  → to install or fix: penkit install")

    say("\n2. Project configuration")
    cfg_file = config_path(project)
    if not cfg_file.exists():
        url = args.url
        if not url and sys.stdin.isatty():
            url = ask("  Address of the running app, target of ZAP [http://localhost:8000]: ")
        write_default_config(project, url or "http://localhost:8000")
        say(f"  created: {cfg_file}")
    else:
        say(f"  existing: {cfg_file}")
    cfg = load_config(project)
    errs = validate_config(cfg)
    for e in errs:
        say(f"  ✘ {e}")
    say(f"  app         : {cfg['app']['url']}  (ZAP mode: {cfg['zap']['mode']})")
    say(f"  semgrep     : {', '.join(cfg['semgrep']['configs'])}")
    say(f"  reports     : {reports_dir(project)}/")
    git_errs = []
    if is_git_repo(project):
        for m in ensure_gitignored(project):
            say(f"  {m}" if m.startswith("✘") else f"  git         : {m}")
            if m.startswith("✘"):
                git_errs.append(m)
        if not git_errs:
            say(f"  git         : {PENKIT_DIR}/ and the skill links ignored; {CONFIG_NAME} to commit")
    ok, why = app_reachable(cfg["app"]["url"])
    say(f"  app reachable: {'yes (' + why + ')' if ok else 'no (' + why + ') — start it before penkit audit'}")

    say("\n3. Claude Code skills")
    links = ensure_skill_links(project)
    for link in links:
        say(f"  {link}" if link.startswith("✘") else f"  skill       : {link}")

    ready = all(c.ok for c in checks) and not errs and not git_errs and not any(m.startswith("✘") for m in links)
    say("\n" + (f"✔ Ready: in Claude Code, /{SKILL_NAME} or \"run the security audit\"" if ready
                 else "✘ Not ready: fix the points above"))
    return 0 if ready else 1


# ───────────────────────────── running the tools ─────────────────────────────

@dataclass
class Ctx:
    project: Path
    cfg: dict
    lock: dict
    run_dir: Path
    wrk: Path

    @property
    def raw(self) -> Path:
        return self.run_dir / "raw"

    @property
    def logs(self) -> Path:
        return self.run_dir / "logs"


def exec_logged(cmd: list[str], log: Path, cwd: Path | None = None, timeout: int = 1800) -> tuple[int, float]:
    t0 = time.monotonic()
    try:
        p = run(cmd, cwd=cwd, timeout=timeout)
        rc, out = p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out = -1, f"{e.stdout or ''}{e.stderr or ''}\n[penkit] timed out ({timeout} s)"
    with open(log, "a") as f:
        f.write(f"$ {' '.join(cmd)}\n{ANSI.sub('', out if isinstance(out, str) else out.decode(errors='replace'))}\n[exit {rc}]\n\n")
    return rc, time.monotonic() - t0


def rel(ctx: Ctx, p: Path) -> str:
    return str(p.relative_to(ctx.run_dir))


def result(tool_id: str, **kw) -> dict:
    base = {"id": tool_id, "status": "ok", "summary": "", "findings": [], "reports": [], "commands": [],
            "notes": [], "duration_s": 0.0, "extra": {}}
    base.update(kw)
    return base


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text() or "null") or default
    except (OSError, json.JSONDecodeError):
        return default


def betterleaks_config(ctx: Ctx) -> Path:
    """Project rules (or the default ones) + exclusion of the penkit/ directory.

    In dir mode, betterleaks does not read .gitignore: without this exclusion it would
    read the previous reports again.
    """
    own = next((ctx.project / n for n in (".betterleaks.toml", ".gitleaks.toml") if (ctx.project / n).is_file()), None)
    extend = f"path = {json.dumps(str(own))}" if own else "useDefault = true"
    cfg = ctx.wrk / "betterleaks.toml"
    cfg.write_text(f"""# generated by penkit for every scan
[extend]
{extend}

[[allowlists]]
description = "penkit: working directory and reports"
paths = ["^{PENKIT_DIR}/"]
""")
    return cfg


def run_betterleaks(ctx: Ctx) -> dict:
    log = ctx.logs / "betterleaks.log"
    config = betterleaks_config(ctx)
    r = result("betterleaks", version=ctx.lock["betterleaks"]["version"])
    modes = [("git", "git history"), ("dir", "files on disk")]
    if not (ctx.project / ".git").exists():
        modes = [("dir", "files on disk")]
        r["notes"].append("not a git repository: history not scanned")
    errors = []
    for mode, label in modes:
        out = ctx.raw / f"betterleaks-{mode}.json"
        cmd = ["betterleaks", mode, ".", "--redact", "--no-banner", "--no-color",
               "-c", str(config.relative_to(ctx.project)), "-f", "json", "-r", str(out)]
        rc, d = exec_logged(cmd, log, cwd=ctx.project)
        r["duration_s"] += d
        r["commands"].append(" ".join(cmd))
        if rc not in (0, 1) or not out.exists():
            errors.append(f"betterleaks {mode}: exit code {rc}")
            continue
        r["reports"].append({"label": f"JSON — {label}", "path": rel(ctx, out), "kind": "json"})
        for f in read_json(out, []):
            r["findings"].append({
                "severity": "high",
                "title": f.get("Description") or f.get("RuleID") or "Secret",
                "location": f"{f.get('File', '?')}:{f.get('StartLine', '?')}",
                "detail": " · ".join(x for x in [
                    f"rule {f.get('RuleID')}" if f.get("RuleID") else "",
                    f"commit {f['Commit'][:10]}" if f.get("Commit") else "",
                    f"{f.get('Author', '')} {f.get('Date', '')[:10]}".strip(),
                    f"fingerprint {f.get('Fingerprint')}" if f.get("Fingerprint") else "",
                ] if x),
                "source": label,
            })
    r["reports"].append({"label": "Execution log", "path": rel(ctx, log), "kind": "log"})
    n = len(r["findings"])
    if errors:
        r["status"], r["notes"] = "error", r["notes"] + errors
    else:
        r["status"] = "findings" if n else "ok"
    r["summary"] = f"{report.plural(n, 'exposed secret', 'exposed secrets')}" if n else "No secret found"
    return r


SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
               "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_semgrep(ctx: Ctx) -> dict:
    log = ctx.logs / "semgrep.log"
    out = ctx.raw / "semgrep.json"
    r = result("semgrep", version=ctx.lock["semgrep"]["version"])
    cmd = ["semgrep", "scan", "--metrics=off", "--disable-version-check"]
    for c in ctx.cfg["semgrep"]["configs"]:
        cmd += ["--config", c]
    for d in PENKIT_OUTPUTS:
        cmd += ["--exclude", d.rstrip("/")]
    cmd += ["--json", "-o", str(out), "."]
    rc, r["duration_s"] = exec_logged(cmd, log, cwd=ctx.project)
    r["commands"].append(" ".join(cmd))
    data = read_json(out, {})
    if rc not in (0, 1) or not data:
        r["status"] = "error"
        r["notes"].append(f"semgrep: exit code {rc}")
    for f in data.get("results", []):
        extra, meta = f.get("extra", {}), f.get("extra", {}).get("metadata", {})
        cwe = meta.get("cwe") or []
        cwe = cwe if isinstance(cwe, list) else [cwe]
        refs = meta.get("references") or []
        tags = [str(x).split(":")[0] for x in cwe][:3]
        if meta.get("confidence"):
            tags.append(f"{str(meta['confidence']).lower()} confidence")
        r["findings"].append({
            "severity": SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), "medium"),
            "title": f.get("check_id", "").rsplit(".", 1)[-1] or "Semgrep rule",
            "location": f"{f.get('path', '?')}:{f.get('start', {}).get('line', '?')}",
            "detail": extra.get("message", ""),
            "tags": tags,
            "ref": refs[0] if refs else "",
            "rule": f.get("check_id", ""),
        })
    errs = data.get("errors") or []
    if errs:
        r["notes"].append(f"{report.plural(len(errs), 'scan error', 'scan errors')} reported by semgrep (see the JSON)")
    scanned = len(data.get("paths", {}).get("scanned", []))
    r["extra"] = {"files_scanned": scanned, "rulesets": ctx.cfg["semgrep"]["configs"]}
    r["reports"] += [{"label": "Raw JSON", "path": rel(ctx, out), "kind": "json"},
                     {"label": "Execution log", "path": rel(ctx, log), "kind": "log"}]
    n = len(r["findings"])
    if r["status"] != "error":
        r["status"] = "findings" if n else "ok"
    r["summary"] = (report.plural(n, "potential flaw", "potential flaws") if n else "No flaw found") \
        + f" · {report.plural(scanned, 'file', 'files')}"
    return r


OSV_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def cvss_level(score: str) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"


def run_osv(ctx: Ctx) -> dict:
    log = ctx.logs / "osv-scanner.log"
    out_json, out_html = ctx.raw / "osv-scanner.json", ctx.raw / "osv-scanner.html"
    r = result("osv-scanner", version=ctx.lock["osv-scanner"]["version"])
    base = ["osv-scanner", "scan", "source", "-r", str(ctx.project)]
    rc, d1 = exec_logged(base + ["--format", "json", "--output-file", str(out_json)], log)
    rc2, d2 = exec_logged(base + ["--format", "html", "--output-file", str(out_html)], log)
    r["duration_s"] = d1 + d2
    r["commands"] += [" ".join(base + ["--format", "json", "--output-file", "osv-scanner.json"]),
                      " ".join(base + ["--format", "html", "--output-file", "osv-scanner.html"])]
    if rc == 128:
        r.update(status="skipped", summary="No lockfile found")
        r["reports"].append({"label": "Execution log", "path": rel(ctx, log), "kind": "log"})
        return r
    data = read_json(out_json, {})
    if rc not in (0, 1) or not data:
        r["status"] = "error"
        r["notes"].append(f"osv-scanner: exit code {rc}")
    pkgs_vuln = set()
    for res in data.get("results", []):
        src = res.get("source", {}).get("path", "")
        src = os.path.relpath(src, ctx.project) if src.startswith(str(ctx.project)) else src
        for p in res.get("packages", []):
            pk = p.get("package", {})
            vulns = {v.get("id"): v for v in p.get("vulnerabilities", [])}
            for g in p.get("groups", []):
                v = next((vulns[i] for i in g.get("ids", []) if i in vulns), {})
                ds_sev = str(v.get("database_specific", {}).get("severity", "")).upper()
                sev = OSV_SEV.get(ds_sev) or cvss_level(g.get("max_severity"))
                fixed = sorted({e["fixed"] for a in v.get("affected", []) for rg in a.get("ranges", [])
                                for e in rg.get("events", []) if "fixed" in e})
                ids = g.get("aliases") or g.get("ids") or []
                pkgs_vuln.add((pk.get("name"), pk.get("version")))
                r["findings"].append({
                    "severity": sev,
                    "title": v.get("summary") or (g.get("ids") or ["?"])[0],
                    "location": f"{pk.get('name')}@{pk.get('version')} ({pk.get('ecosystem')}) — {src}",
                    "detail": ("Fixed in " + ", ".join(fixed)) if fixed else "No fixed version published",
                    "tags": ids[:4] + (["dev"] if "dev" in (p.get("dependency_groups") or []) else [])
                            + ([f"CVSS {g['max_severity']}"] if g.get("max_severity") else []),
                    "ref": f"https://osv.dev/vulnerability/{(g.get('ids') or [''])[0]}",
                })
    if out_html.exists() and rc2 in (0, 1):
        r["reports"].append({"label": "OSV-Scanner HTML report", "path": rel(ctx, out_html), "kind": "native"})
    r["reports"] += [{"label": "Raw JSON", "path": rel(ctx, out_json), "kind": "json"},
                     {"label": "Execution log", "path": rel(ctx, log), "kind": "log"}]
    lockfiles = [os.path.relpath(x, ctx.project) for x in re.findall(r"Scanned (\S+) file", log.read_text())]
    r["extra"] = {"lockfiles": sorted(set(lockfiles))}
    n = len(r["findings"])
    if r["status"] != "error":
        r["status"] = "findings" if n else "ok"
    r["summary"] = (f"{report.plural(n, 'vulnerability', 'vulnerabilities')} in {report.plural(len(pkgs_vuln), 'package', 'packages')}"
                    if n else "No known vulnerability") + f" · {report.plural(len(set(lockfiles)), 'lockfile', 'lockfiles')}"
    return r


ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
ZAP_CONF = {"0": "false positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}
TAG = re.compile(r"<[^>]+>")


def export_sources(project: Path, dest: Path) -> int:
    """Clean copy of the repository for Noir: no ignored files, no previous reports."""
    files = tracked_files(project)
    if not files:
        skip = {".git", "node_modules", ".venv", "venv", "dist", "build"}
        outputs = {penkit_dir(project)}
        shutil.copytree(project, dest, symlinks=True, dirs_exist_ok=True,
                        ignore=lambda d, names: [n for n in names if n in skip or Path(d) / n in outputs])
        return -1
    for f in files:
        if f.startswith(PENKIT_OUTPUTS):
            continue
        src = project / f
        if src.is_file() and not src.is_symlink():
            (dest / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / f)
    return len(files)


HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")


def normalize_spec(spec: dict) -> tuple[dict, int]:
    """Merge the duplicate routes "//x" and "/x".

    Noir reads the OpenAPI specs present in the repository; when they declare
    `servers: url: /`, it prepends that "/" to the routes. ZAP would then attack every
    route twice, once on a URL that does not exist.
    """
    merged, dupes = {}, 0
    for path, ops in (spec.get("paths") or {}).items():
        clean = re.sub(r"/{2,}", "/", path)
        target = merged.setdefault(clean, {})
        for key, op in ops.items():
            if key in target:
                dupes += key in HTTP_METHODS
                continue
            target[key] = op
    return {**spec, "paths": merged}, dupes


def run_noir_zap(ctx: Ctx) -> dict:
    log = ctx.logs / "noir-zap.log"
    url = ctx.cfg["app"]["url"]
    mode = ctx.cfg["zap"]["mode"]
    r = result("noir-zap", version=f"Noir {ctx.lock['noir']['version']} · ZAP {ctx.lock['zap']['version']}")
    noir_file = ctx.raw / "endpoints-noir.json"
    endpoints_file = ctx.raw / "endpoints.json"

    # 1. Noir: map the routes from the code
    with tempfile.TemporaryDirectory(prefix="penkit-src-") as src:
        n_files = export_sources(ctx.project, Path(src))
        if n_files < 0:
            r["notes"].append("not a git repository: Noir scans a copy without .git, node_modules, venv, dist, build")
        cmd = ["noir", "scan", src, "-u", url, "-f", "oas3", "-o", str(noir_file), "--no-color"]
        rc, d = exec_logged(cmd, log)
    r["duration_s"] += d
    r["commands"].append(" ".join(["noir", "scan", "<clean copy of the repository>"] + cmd[3:]))
    spec, dupes = normalize_spec(read_json(noir_file, {}))
    endpoints_file.write_text(json.dumps(spec, indent=2))
    if dupes:
        r["notes"].append(f"{report.plural(dupes, 'duplicate route', 'duplicate routes')} \"//…\" merged in the spec given to ZAP")
    endpoints = sorted(
        {(m.upper(), p) for p, ops in spec["paths"].items() for m in ops if m.lower() in HTTP_METHODS},
        key=lambda x: (x[1], x[0]))
    r["extra"]["endpoints"] = [{"method": m, "path": p} for m, p in endpoints]
    if rc != 0 or not noir_file.exists():
        r["status"] = "error"
        r["notes"].append(f"noir: exit code {rc}")
    else:
        r["reports"] += [{"label": "OpenAPI spec given to ZAP", "path": rel(ctx, endpoints_file), "kind": "json"},
                         {"label": "Raw Noir output", "path": rel(ctx, noir_file), "kind": "json"}]

    # 2. ZAP: attack the running app
    reachable, why = app_reachable(url)
    r["extra"]["app"] = {"url": url, "reachable": reachable, "detail": why}
    if not reachable:
        r["status"] = "error" if r["status"] == "error" else "skipped"
        r["notes"].append(f"ZAP not run: {url} unreachable ({why}). Start the app, then run again.")
        r["summary"] = f"{report.plural(len(endpoints), 'route mapped', 'routes mapped')} · ZAP not run (app unreachable)"
        r["reports"].append({"label": "Execution log", "path": rel(ctx, log), "kind": "log"})
        return r
    if mode == "api" and not endpoints:
        mode = "baseline"
        r["notes"].append("Noir found no route: passive ZAP scan (baseline) of the URL instead")

    wrk = ctx.wrk / "zap"
    wrk.mkdir()
    if os.getuid() != 1000:          # the container's "zap" user has uid 1000
        wrk.chmod(0o777)
    zap = ["docker", "run", "--rm", "--network", "host", "-v", f"{wrk}:/zap/wrk:rw", zap_ref(ctx.lock["zap"])]
    if mode == "api":
        shutil.copy2(endpoints_file, wrk / "endpoints.json")
        zap += ["zap-api-scan.py", "-t", "/zap/wrk/endpoints.json", "-f", "openapi"]
    else:
        zap += ["zap-baseline.py", "-t", url]
    zap += ["-r", "zap.html", "-J", "zap.json"]
    rc, d = exec_logged(zap, log, timeout=ctx.cfg["zap"]["timeout_minutes"] * 60 + 300)
    r["duration_s"] += d
    r["commands"].append(" ".join(zap))
    r["extra"]["zap_mode"] = mode
    kept = ctx.raw / "zap"
    kept.mkdir()
    for name in ("zap.html", "zap.json"):
        if (wrk / name).is_file():
            shutil.copyfile(wrk / name, kept / name)
    data = read_json(kept / "zap.json", {})
    if rc not in (0, 1, 2) or not data:
        r["status"] = "error"
        r["notes"].append(f"ZAP: exit code {rc}" + (" (timed out)" if rc == -1 else ""))
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            inst = a.get("instances", [])
            uris = sorted({f"{i.get('method', '')} {i.get('uri', '')}".strip() for i in inst})
            tags = [f"CWE-{a['cweid']}"] if str(a.get("cweid", "")) not in ("", "-1", "0") else []
            count = int(a["count"]) if str(a.get("count", "")).isdigit() else len(inst)
            tags += [f"{ZAP_CONF.get(str(a.get('confidence')), '?')} confidence",
                     report.plural(count, "occurrence", "occurrences")]
            r["findings"].append({
                "severity": ZAP_RISK.get(str(a.get("riskcode")), "info"),
                "title": a.get("name") or a.get("alert", "ZAP alert"),
                "location": (uris[0] if uris else site.get("@name", "")) + (f" (+{len(uris) - 1})" if len(uris) > 1 else ""),
                "detail": TAG.sub(" ", a.get("solution", "")).strip(),
                "tags": tags,
                "ref": next(iter(TAG.sub(" ", a.get("reference", "")).split()), ""),
                "uris": uris[:20],
            })
    if (kept / "zap.html").exists():
        r["reports"].append({"label": "Full ZAP HTML report", "path": rel(ctx, kept / "zap.html"), "kind": "native"})
    if (kept / "zap.json").exists():
        r["reports"].append({"label": "Raw ZAP JSON", "path": rel(ctx, kept / "zap.json"), "kind": "json"})
    r["reports"].append({"label": "Execution log", "path": rel(ctx, log), "kind": "log"})
    n = len(r["findings"])
    if r["status"] != "error":
        r["status"] = "findings" if n else "ok"
    scan = "active scan" if mode == "api" else "passive scan"
    routes = report.plural(len(endpoints), "route", "routes")
    r["summary"] = f"{routes} · {report.plural(n, 'ZAP alert', 'ZAP alerts')} ({scan})" if n else f"{routes} · no ZAP alert ({scan})"
    return r


RUNNERS = {"betterleaks": run_betterleaks, "semgrep": run_semgrep, "osv-scanner": run_osv, "noir-zap": run_noir_zap}


def git_meta(project: Path) -> dict:
    def g(*a):
        p = run(["git", "-C", str(project), *a])
        return p.stdout.strip() if p.returncode == 0 else ""
    return {"commit": g("rev-parse", "--short", "HEAD"), "branch": g("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(g("status", "--porcelain")), "subject": g("log", "-1", "--format=%s")}


def cmd_audit(args) -> int:
    lock = load_lock()
    project = find_project()
    if not config_path(project).exists():
        say(f"✘ {config_path(project)} missing: run penkit init first")
        return 2
    cfg = load_config(project)
    errs = validate_config(cfg)
    if is_git_repo(project) and not penkit_ignored(project):
        errs.append(f"{PENKIT_DIR}/ not ignored by git: the reports could end up committed")
    checks = check_all(lock)
    bad = [c for c in checks if not c.ok]
    if errs or bad:
        say("✘ penkit audit refused:")
        print_checks(bad)
        for e in errs:
            say(f"  · {e}")
        if bad:
            say("Tools: run penkit install")
        if errs:
            say("Configuration: run penkit init")
        return 2
    only = [x.strip() for x in args.only.split(",")] if args.only else TOOL_IDS
    unknown = set(only) - set(TOOL_IDS)
    if unknown:
        say(f"✘ unknown tool(s): {', '.join(sorted(unknown))} (choices: {', '.join(TOOL_IDS)})")
        return 2

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    ensure_penkit_dir(project)
    run_dir = reports_dir(project) / stamp
    (run_dir / "raw").mkdir(parents=True)
    (run_dir / "logs").mkdir()
    ctx = Ctx(project, cfg, lock, run_dir, fresh_wrk(project))
    started = dt.datetime.now().astimezone()
    say(f"penkit audit — {project}\n  reports: {run_dir}")

    results = []
    for tid in only:
        say(f"  → {report.TOOLS[tid]['name']} …")
        try:
            res = RUNNERS[tid](ctx)
        except Exception as e:  # noqa: BLE001 — a failing tool does not block the others
            res = result(tid, status="error", summary="penkit internal error", notes=[repr(e)])
        results.append(res)
        say(f"    {res['status']:<9} {res['summary']}  ({res['duration_s']:.0f} s)")
        for n in res["notes"]:
            say(f"      · {n}")

    summary = {
        "penkit_version": "0.1.0",
        "project": {"name": project.name, "path": str(project), **git_meta(project)},
        "target_url": cfg["app"]["url"],
        "started": started.isoformat(timespec="seconds"),
        "finished": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "tools": results,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    report.build(run_dir)
    say(f"\nReport: {run_dir / 'index.html'}")
    say(f"Link: {(run_dir / 'index.html').resolve().as_uri()}")
    return 1 if any(r["status"] == "error" for r in results) else 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="penkit", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("install", help="install / verify the tools at their pinned versions")
    p.add_argument("--fix", action="store_true", help="also replace different versions (in ~/.local/bin)")
    p.set_defaults(fn=cmd_install)
    p = sub.add_parser("init", help="prepare the project: .penkit.toml, .gitignore, links to the penkit skills")
    p.add_argument("--url", help="address of the app (only when creating .penkit.toml)")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("audit", help="run the 4 scans and build the HTML report")
    p.add_argument("--only", help=f"subset: {','.join(TOOL_IDS)}")
    p.set_defaults(fn=cmd_audit)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
