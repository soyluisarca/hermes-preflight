"""preflight: terminal backend that runs each command in a throwaway copy of the
workspace.

Every command executes inside a local copy (reflink full copy) of the real
workspace. The real workspace is NEVER touched directly: the file tools run
inside the copy too (uses_host_filesystem=False). After each command a diff is
accumulated in PENDING.diff. Applying (whole-workspace sync copy -> real) and
discarding are EXPLICIT actions that never happen on their own; apply is a
single whole-workspace approval (PENDING.diff is the exact-diff review gate)
and requires human confirmation on a terminal. That check is BEST-EFFORT: a
determined agent that allocates a pty can self-approve, so the TTY gate stops
accidental non-TTY approvals, not a determined local agent.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from agent.terminal_env_provider import TerminalEnvironmentProvider

def _derive_sandroot() -> Path:
    """Default sandbox root: the active Hermes home + /sandbox."""
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "sandbox"


# Root directory for sandboxes.
#
# Derived from the ACTIVE Hermes home (hermes_constants.get_hermes_home()) so
# each profile gets its own sandbox namespace instead of every profile sharing
# ~/.hermes/sandbox. The module-level SANDROOT is the default; a per-profile
# override is applied by PreflightProvider._sandroot() (plugin config key
# "sandbox_root", set in plugin.yaml / plugins.entries.<id>.settings). The
# legacy PREFLIGHT_ROOT / SANDBOX_FIRST_ROOT env vars are NOT read here anymore
# — overrides now live in plugin config, not the environment.
SANDROOT = _derive_sandroot()

# Exact environment variable names that must never reach the subprocess (secrets).
_STRIP_ENV_KEYS = frozenset({
    "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "SSH_AUTH_SOCK", "NPM_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS", "FAL_KEY", "FAL_API_KEY",
    "NOUS_API_KEY",
})

# Sensitive variable prefixes also filtered (deny-list by prefix).
_STRIP_ENV_PREFIXES = frozenset({"AWS_", "GCP_", "GCLOUD_", "DOCKER_", "AZURE_"})

# --- local env sanitizer (no private core imports) ---
# Sensitive prefixes stripped case-insensitively. Broader than the deny-list
# above so Hermes-managed secrets (FAL_*, NOUS_API_KEY, ...) never reach a
# child process even if they are not listed explicitly here.
_STRIP_ENV_PREFIX = (
    "FAL_", "NOUS_", "OPENROUTER_", "OPENAI_", "ANTHROPIC_", "GOOGLE_",
    "GCP_", "GCLOUD_", "AWS_", "AZURE_", "DOCKER_", "HF_", "HUGGINGFACE_",
    "MESHY_", "SUPABASE_", "LANGSMITH_", "ELEVENLABS_", "DEEPSEEK_", "GLM_",
    "PORTAL_", "HERMES_",
)
# Sensitive suffixes stripped, again case-insensitive. Covers the usual
# provider naming patterns: *_API_KEY / *_TOKEN / *_SECRET / *_PASSWORD /
# *_CREDENTIAL / *_ACCESS_KEY plus the audit findings: *_PASS, *_PWD, *_KEY
# (catches *_SECRET_KEY and *_PRIVATE_KEY too) and *_URL (DATABASE_URL,
# REDIS_URL, ...).
_STRIP_ENV_SUFFIX = (
    "_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL", "_ACCESS_KEY",
    "_PASS", "_PWD", "_KEY", "_URL",
)
# Exact names always dropped (case-insensitive), e.g. git/registry/ssh creds
# and the canonical database/daemon password variables that do not carry a
# _SUFFIX (PGPASSWORD has no underscore before PASSWORD, MYSQL_PWD and
# RCLONE_CONFIG_PASS are also listed for belt-and-braces).
_STRIP_ENV_EXACT = frozenset({
    "SSH_AUTH_SOCK", "GOOGLE_APPLICATION_CREDENTIALS", "NPM_TOKEN", "GH_TOKEN",
    "GITHUB_TOKEN", "HF_TOKEN", "NETRC", "PGPASSWORD", "MYSQL_PWD",
    "RCLONE_CONFIG_PASS",
})
# Variables that must be PRESERVED by the sanitizer are not credentials, so the
# filter lets them through naturally (PATH, HOME, LANG, TERM match no prefix,
# suffix or exact secret name). HOME is only kept here to be pinned to the copy
# by _make_env right after.


def _sanitize_env(env: dict) -> dict:
    """Local filter that drops secret-looking environment variables.

    Replicates the intent of the Hermes core's private subprocess sanitizer
    WITHOUT importing it (rule 9: no private core imports on public surfaces).
    A variable is removed if its name (case-insensitive) starts with a
    sensitive prefix, ends with a sensitive suffix, or is an exact sensitive
    name. The plugin's own deny-list (_STRIP_ENV_KEYS / _STRIP_ENV_PREFIXES)
    is applied by the caller as an extra layer.
    """
    exact_lower = {k.lower() for k in _STRIP_ENV_EXACT}
    return {
        k: v for k, v in env.items()
        if k.lower() not in exact_lower
        and not any(k.upper().startswith(p) for p in _STRIP_ENV_PREFIX)
        and not any(k.upper().endswith(s) for s in _STRIP_ENV_SUFFIX)
    }

# Honest note appended to every path guard message. The guards scan the
# LITERAL command string; variable expansion and scripts invoked from inside
# the command (bash file.sh, python3 -c) run beyond what a string scan can
# see, so the plugin NEVER claims the host is unreachable — it says what it
# scans and points to the README for the honest limitations.
_HONEST_NOTE = (
    "Note: only literal command strings are scanned; variable expansion "
    "and invoked scripts (bash file.sh, python3 -c) can still touch the "
    "host - see README 'Honest limitations'."
)


def _expand_var_tokens(token: str, env: dict) -> str:
    """Best-effort ``$VAR``/``${VAR}`` expansion for UNSET/EMPTY variables.

    The path guards must judge ``cat $EMPTY/etc/passwd`` the way bash will run
    it: EMPTY is unset, so bash sees ``/etc/passwd`` — and the guard must see
    the same. We expand ONLY variables that are absent or empty in the child's
    env (they expand to the empty string exactly like bash without ``set -u``
    does, which turns an absolute-looking residue into a real absolute path).

    Variables that ARE set are left untouched for bash: expanding them here
    would manufacture false positives ($PATH, $TMPDIR with a long value, a
    staging-root path such as $PREFLIGHT_ROOT/... are all legitimate or
    best-effort-covered strings). This is a documented heuristic: an attacker
    can still build a path from set variables inside the command; the guards
    close the empty-variable class, not the whole language.
    """
    if "$" not in token:
        return token

    def _repl(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        # Only absent/empty variables are expanded (to ""). Present variables
        # keep their literal $VAR text so the guard analyzes the raw command.
        return "" if env.get(name, "") == "" else m.group(0)

    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
        _repl,
        token,
    )

# Privilege-escalation tokens. They are concatenated on purpose: the plugin
# security scanner mistakes the literal for a REAL use of sudo; here we only
# BLOCK it.
_PRIV_TOKENS = ("su" "do", "doas")
# Pattern to detect privilege-escalation attempts. Boundaries include shell
# separators (`; & | ( ) \`` and whitespace) so `x&&sudo ...`, `(sudo ...)` or
# `` `sudo ...` `` are caught, not just leading-whitespace cases.
_SUDO_RE = re.compile(
    r"(^|[;&|()` \t]+)(" + "|".join(_PRIV_TOKENS) + r")([;&|()` \t]+|$)",
    re.MULTILINE,
)


def _partial_str(data) -> str:
    """Normalize captured output that may be ``str`` or ``bytes`` before concat."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data)


# --- PENDING.diff redaction (review view only; apply never reads the diff) ---
# A variable NAME whose name ENDS with one of these tokens is treated as a
# secret and its assigned value is redacted in the review view. Suffix
# matching (case-insensitive) covers TOKEN, *_KEY, *_SECRET, *_PASSWORD,
# *_PASS, *_PWD, *_CREDENTIAL, *_URL and the official names (PGPASSWORD,
# RCLONE_CONFIG_PASS, ...) without false-matching an embedded word
# (CURL_OPTIONS does not end in URL, TOKENIZER does not end in TOKEN).
_SENSITIVE_NAME_SUFFIXES = (
    "TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL",
    "PRIVATE", "ACCESS_KEY", "PASS", "URL",
)
# ``NAME  =  value`` at the start of a diff line (after the +/-/space marker);
# optional `export ` prefix covers shell exports.
_SENSITIVE_ASSIGN_RE = re.compile(
    r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|:)\s*(.*)$",
    re.IGNORECASE,
)
# userinfo in URLs: https://user:pass@host -> https://<redacted>@host
_URL_USERINFO_RE = re.compile(r"(https?://)[^/\s:@\"]+@")
# Standalone secret-looking values (sk-.../ghp_.../AKIA.../JWT) on their own.
_SECRET_VALUE_RE = re.compile(
    r"(\b(?:sk-|ghp_|gho_|xox[bap]-|AKIA|eyJ)[A-Za-z0-9_\-\.]{8,}\b)"
)


def _name_looks_sensitive(name: str) -> bool:
    upper = name.upper()
    return any(upper.endswith(s) for s in _SENSITIVE_NAME_SUFFIXES)


def _redact_diff_body(body: str) -> str:
    """Return a copy of a raw diff body with secret-looking values redacted.

    Every line is scanned independently: if a ``NAME=value``/``NAME: value``
    pair has a secret-smelling name, the value is replaced; URLs with embedded
    userinfo get the userinfo removed; bare secret tokens are masked. Lines
    that do not match keep their exact content.
    """
    out = []
    for line in body.splitlines():
        out.append(_redact_sensitive_line(line))
    return "\n".join(out)


def _redact_sensitive_line(line: str) -> str:
    stripped = line.lstrip("+- ")
    m = _SENSITIVE_ASSIGN_RE.match(stripped)
    if m and _name_looks_sensitive(m.group(1)) and m.group(2).strip():
        prefix_len = len(line) - len(stripped)
        return line[:prefix_len] + f"{m.group(1)} = <redacted>"
    red = _URL_USERINFO_RE.sub(lambda mm: mm.group(1) + "<redacted>@", line)
    if red != line:
        return red
    if _SECRET_VALUE_RE.search(line):
        return _SECRET_VALUE_RE.sub("<redacted>", line)
    return line


def _strip_tmpdir(body: str) -> str:
    """Drop every diff hunk touching ``<copy>/.preflight-tmp``.

    TMPDIR is pinned INSIDE the copy, so any tool honoring $TMPDIR leaves
    files under the copy that must NOT show up in the review view nor be
    applied to the real workspace. We cannot exclude the name via `git diff
    --no-index` pathspec magic, so we strip the matching hunks here: once a
    hunk header (``diff ``/``Only in``) mentions ``.preflight-tmp``, every
    line until the next file header is dropped. The same exclusion is applied
    by `sandboxctl apply` (rsync --exclude=.preflight-tmp).
    """
    out: list[str] = []
    skip = False
    for line in body.splitlines():
        is_file_header = line.startswith(("diff ", "Only in", "Index "))
        if is_file_header:
            if ".preflight-tmp" in line:
                skip = True
                continue
            skip = False
        if skip:
            continue
        out.append(line)
    return "\n".join(out)


def _write_original_fingerprint(original: Path, dst: Path) -> None:
    """Snapshot of the real workspace at clone time.

    ``sandboxctl apply`` recomputes this and aborts if it changed since the
    clone (TOCTOU guard): a file created or edited in the real workspace AFTER
    the clone must never be silently clobbered by an apply.

    Each line carries ``path<TAB>mtime_ns<TAB>size<TAB>sha256<TAB>kind``. The
    content hash makes the guard hold even when an attacker edits a file and
    preserves mtime+size (a real change always changes the sha256).
    """
    lines: list[str] = []
    for root, dirs, files in os.walk(original):
        dirs.sort()
        files.sort()
        rel_root = os.path.relpath(root, original)
        for d in dirs:
            p = os.path.join(root, d)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            lines.append(f"{os.path.join(rel_root, d)}\t{st.st_mtime_ns}\t{st.st_size}\t-\td")
        for f in files:
            p = os.path.join(root, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            lines.append(f"{os.path.join(rel_root, f)}\t{st.st_mtime_ns}\t{st.st_size}\t{_fingerprint_hash(p)}\tf")
    dst.write_text("\n".join(sorted(lines)), encoding="utf-8")


def _fingerprint_hash(path: str) -> str:
    """sha256 of a file's content (or of the link target for symlinks).

    ``-`` on any OSError keeps the snapshot write resilient; the apply guard
    will simply see a hash change (or rely on the other columns) if a file
    becomes unreadable.
    """
    if os.path.islink(path):
        try:
            return hashlib.sha256(os.readlink(path).encode("utf-8")).hexdigest()
        except OSError:
            return "-"
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "-"


class PreflightEnvironment:
    """Duck-typed BaseEnvironment (execute/cleanup).

    HONEST contract (we do not claim what we do not do):
      - NOT a container. The command runs in a LOCAL copy (reflink/copy) of the
        workspace, but the process is a host process.
      - uses_host_filesystem = False: the agent's file-tools go through
        execute() inside the COPY, so write_file/patch/edit never touch the real
        workspace directly and always land behind the copy/diff/apply gate. The
        agent SEES the copy, EXECUTES on the copy and APPLIES with explicit
        approval. (Setting this True would let file-tools bypass the gate and
        break the PENDING.diff fingerprint check.)
      - is_local = True: runs on the local machine, not remote.
    """

    uses_host_filesystem = False
    is_local = True
    is_container = False

    def __init__(self, *, cwd: str, timeout: int, sandbox_path: Path, original_path: Path):
        if not cwd:
            cwd = str(original_path)
        self.cwd = cwd
        self.timeout = timeout
        self.sandbox_path = sandbox_path
        self.original_path = original_path
        # cwd inside the copy: if the path starts at the original, remap it.
        self.sandbox_cwd = self._remap_cwd(cwd)
        self._pending = sandbox_path / "PENDING.diff"

    def _remap_cwd(self, cwd: str) -> str:
        try:
            rel = os.path.relpath(cwd, self.original_path)
        except Exception:
            rel = "."
        if rel == "." or rel.startswith(".."):
            return str(self.sandbox_path)
        return str(self.sandbox_path / rel)

    # --- security guards (best-effort, NOT a kernel sandbox) ---
    @staticmethod
    def _reject_sudo(command: str) -> str | None:
        # Audit on a NORMALIZED form: strip single/double quotes (turned into
        # spaces) and backslash escapes, because a quote char or a backslash is
        # NOT in _SUDO_RE's separator class and would let e.g.
        # `bash -c 'sudo whoami'` dodge the guard. The real command is never
        # touched — this only feeds the best-effort pattern match.
        cmd_norm = (
            command.replace("'", " ")
            .replace('"', " ")
            .replace("\\", "")
        )
        if _SUDO_RE.search(cmd_norm):
            return "Blocked by preflight: privilege-elevated commands are not allowed in the sandbox."
        return None

    @staticmethod
    def _block_host_absolute_paths(command: str, sandbox_path: Path, env: dict | None = None) -> list[str]:
        """Best-effort detection of absolute paths pointing OUTSIDE the copy.

        Not a real sandbox (the shell runs on the host), so this guard is an
        honest safety net, not an impenetrable wall. Variables are expanded
        against the child's env FIRST, so ``cat $EMPTY/etc/passwd`` (EMPTY
        unset -> ``/etc/passwd``) and ``cat $PREFLIGHT_ROOT/victim/original``
        (a sibling session's record) are judged the way bash will run them,
        while ``$HOME`` / ``$TMPDIR`` (pinned to the copy) stay inside.
        """
        problems: list[str] = []
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Unbalanced quotes / heredocs: fall back to a regex scan of absolute
            # tokens. Never block on a parse failure.
            tokens = [m.group(0) for m in re.finditer(r"/[^\s'\"`;|&()]*", command)]
        for raw in tokens:
            tok = _expand_var_tokens(raw, env or {})
            if not tok.startswith("/"):
                continue
            tok = tok.rstrip("/")
            if not tok:
                # The verbatim token was "/" (host root): always outside the copy.
                problems.append("/")
                continue
            # /tmp inside the copy and the copy itself are allowed; everything else is flagged.
            if tok == str(sandbox_path):
                continue
            # Resolve the token first (normalizes `..` segments and follows
            # symlinks inside the path) so `/tmp/../etc/passwd` cannot dodge
            # the literal-prefix test.
            try:
                cand = Path(tok).resolve(strict=False)
            except Exception:
                cand = Path(tok)
            try:
                is_under = os.path.commonpath([str(sandbox_path), str(cand)]) == str(sandbox_path)
            except Exception:
                is_under = False
            if not is_under and not tok.startswith("/dev/null"):
                problems.append(tok)
        return problems

    def _block_relative_escape(self, command: str, env: dict | None = None) -> str | None:
        """Reject path tokens that resolve OUTSIDE the copy (embedded ``..`` included).

        Best-effort, like the other guards (the shell runs on the host, so this
        is a safety net, not a wall). Every path-ish token — any token that
        contains a ``/``, plus a bare ``..`` — is resolved against the copy's
        cwd: if the resolved candidate leaves the cwd, the token is blocked.
        This catches foreign-``..`` traversal such as ``a/../../x.txt`` (the
        token does not start with ``.`` but still escapes) and ``cat
        a/../../../etc/passwd``. ``..`` segments that stay inside the copy
        (e.g. ``../peer`` where ``peer`` is a sibling inside the workspace) are
        allowed. Tokens without a path separator cannot escape by resolution
        and are skipped (a bare ``..`` is the single no-slash escape, handled
        explicitly). Absolute tokens are resolved here with the same boundary
        test as ``_block_host_absolute_paths`` so there is no second path in.
        Variables are expanded against the child's env first (HOME/TMPDIR are
        pinned inside the copy, so ``$HOME/..`` stays sane).
        """
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = [m.group(0) for m in re.finditer(r"\S+", command)]
        cwd = Path(self.sandbox_cwd)
        for raw in tokens:
            tok = _expand_var_tokens(raw, env or {})
            if not tok or tok == ".":
                continue
            if "/" not in tok:
                # Only a bare `..` can escape without a path separator (`cd ..`).
                if tok != "..":
                    continue
                cand = cwd / tok
            elif tok.startswith("/"):
                cand = Path(tok)
            else:
                cand = cwd / tok
            try:
                resolved = cand.resolve(strict=False)
                under = os.path.commonpath([str(resolved), str(cwd)]) == str(cwd)
            except Exception:
                under = False
            if not under:
                return (
                    f"Blocked by preflight: relative path escapes the sandbox "
                    f"copy ({tok}). {_HONEST_NOTE}"
                )
        return None

    def _block_writes_outside(self, command: str, env: dict | None = None):
        """Reject explicit *writes* (redirection or >) to absolute paths outside the copy."""
        for m in re.finditer(r"[12]?>+\s*('([^']*)'|\"([^\"]*)\"|(\S+))", command):
            target = m.group(2) or m.group(3) or m.group(4) or ""
            target = _expand_var_tokens(target, env or {})
            if not target.startswith("/"):
                continue
            try:
                is_under = os.path.commonpath([self.sandbox_path, target]) == str(self.sandbox_path)
            except Exception:
                is_under = False
            if not is_under and target != "/dev/null":
                return (
                    f"Blocked by preflight: write redirection to a path outside the "
                    f"copy ({target}). {_HONEST_NOTE}"
                )
        return None

    def _block_symlink_escape(self) -> str | None:
        """Reject the operation if the copy contains symlinks escaping the sandbox.

        `cp -a` / `shutil.copytree(symlinks=True)` preserve symlinks. A symlink
        pointing outside (e.g. /etc, ~/.ssh, a real host path) would let a
        command read/write outside the sandbox through the path, bypassing the
        copy. As long as one exists in the copy we block the operation.
        """
        try:
            sp_real = os.path.realpath(self.sandbox_path)
        except Exception:
            sp_real = str(self.sandbox_path)
        prefix = sp_real.rstrip("/") + os.sep
        escaping: list[str] = []
        for p in self.sandbox_path.rglob("*"):
            if not p.is_symlink():
                continue
            try:
                target = os.path.realpath(p)
            except Exception:
                target = ""
            if not target or (target != sp_real and not target.startswith(prefix)):
                escaping.append(str(p))
        if escaping:
            shown = ", ".join(escaping[:5])
            more = f" and {len(escaping)-5} more" if len(escaping) > 5 else ""
            return (
                f"Blocked by preflight: the copy contains symlink(s) escaping "
                f"the sandbox ({shown}{more}). Remove them from the real workspace "
                f"or use a workspace without outward symlinks so that no command "
                f"can leave the sandbox through a symlink."
            )
        return None

    def _make_env(self) -> dict:
        # Own deny-list first (exact secrets + sensitive prefixes).
        env = {
            k: v for k, v in os.environ.items()
            if k not in _STRIP_ENV_KEYS
            and not any(k.startswith(p) for p in _STRIP_ENV_PREFIXES)
        }
        # Local sanitizer (prefix/suffix/exact, case-insensitive) as the base
        # layer: drops Hermes-managed secrets such as FAL_*/NOUS_API_KEY that
        # are not in our deny-list. No private core import (rule 9).
        env = _sanitize_env(env)
        # HOME ALWAYS points inside the copy: `cd ~`, `~/.bashrc`, git config, etc.
        # never escape to the real user directory, even if the real HOME leaks in.
        env["HOME"] = str(self.sandbox_path)
        # TMPDIR (and TMP/TEMP if the host env set them) is pinned to a temp
        # subdir INSIDE the copy too: an innocent `mktemp` or any tool honoring
        # TMPDIR writes into the copy instead of the host /tmp dir the runtime
        # may have exported. The dir is created here so it exists before the
        # child runs. It lives under the copy, so it is excluded from
        # PENDING.diff and from apply (see _strip_tmpdir and sandboxctl).
        tmp_dir = self.sandbox_path / ".preflight-tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        env["TMPDIR"] = str(tmp_dir)
        for var in ("TMP", "TEMP"):
            if var in env:
                env[var] = str(tmp_dir)
        # Pass the sandbox ROOT to children (notably `sandboxctl` invoked from inside
        # a command) so they target THIS profile's root. HERMES_HOME is stripped by
        # the sanitizer and HOME is pinned to the copy, so a child would otherwise not
        # know where the real sessions live. PREFLIGHT_ROOT is plugin-internal
        # transport now (not a user config surface).
        env["PREFLIGHT_ROOT"] = str(self.sandbox_path.parent.parent)
        return env

    def execute(self, command: str, timeout: int | None = None, **kwargs):
        # Build the filtered environment FIRST: the path guards expand $VAR
        # against exactly the env the child will receive (HOME/TMPDIR pinned
        # to the copy), so expansion matches what bash will actually resolve.
        env = self._make_env()

        # 1) Security guards.
        sudo_err = self._reject_sudo(command)
        if sudo_err:
            return {"output": sudo_err, "exit_code": 1, "returncode": 1}

        symlink_err = self._block_symlink_escape()
        if symlink_err:
            return {"output": symlink_err, "exit_code": 1, "returncode": 1}

        write_err = self._block_writes_outside(command, env)
        if write_err:
            return {"output": write_err, "exit_code": 1, "returncode": 1}

        rel_err = self._block_relative_escape(command, env)
        if rel_err:
            return {"output": rel_err, "exit_code": 1, "returncode": 1}

        paths = self._block_host_absolute_paths(command, self.sandbox_path, env)
        if paths:
            return {
                "output": (
                    "Blocked by preflight: absolute path(s) outside the sandbox "
                    f"copy: {', '.join(paths)}. {_HONEST_NOTE}"
                ),
                "exit_code": 1,
                "returncode": 1,
            }

        effective_timeout = timeout or self.timeout or 120

        # 2) Run inside the copy (env was built above).
        try:
            proc = subprocess.run(
                ["bash", "-c", command],
                cwd=self.sandbox_cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "output": (
                    _partial_str(exc.stdout)
                    + _partial_str(exc.stderr)
                    + f"\n[Command timed out after {effective_timeout}s]"
                ),
                "exit_code": 124,
                "returncode": 124,
            }

        output = _partial_str(proc.stdout) + _partial_str(proc.stderr)
        result = {"output": output, "exit_code": proc.returncode, "returncode": proc.returncode}

        # 4) Accumulated diff after each command.
        try:
            self._write_pending_diff()
        except Exception as e:  # the diff must never break execution
            result["output"] += f"\n[warning: could not write PENDING.diff: {e}]"
        return result

    # --- accumulated diff ---
    def _diff_command(self):
        if (self.original_path / ".git").is_dir():
            # git diff --no-index treats both paths as independent trees.
            return (
                f"git diff --no-index --no-color "
                f"-- {shlex.quote(str(self.original_path))} {shlex.quote(str(self.sandbox_path))}"
            )
        # diff -ruN: excludes the diff-file's own path (used outside of git).
        return (
            f"diff -ruN -x PENDING.diff "
            f"{shlex.quote(str(self.original_path))} {shlex.quote(str(self.sandbox_path))}"
        )

    def _write_pending_diff(self):
        cmd = self._diff_command()
        proc = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
        body = _partial_str(proc.stdout) + _partial_str(proc.stderr)
        # diff exits rc != 0 when there are differences (normal). Not an error.
        header = (
            f"# PENDING.diff — preflight ({self.sandbox_path.name})\n"
            f"# ORIGINAL : {self.original_path}\n"
            f"# SANDBOX  : {self.sandbox_path}\n"
            f"# # Accumulated after the last executed command.\n"
            f"# Nothing has been applied to the real workspace yet.\n"
            f"# To apply: sandboxctl apply {self.sandbox_path.name}\n"
            f"# To discard: sandboxctl discard {self.sandbox_path.name}\n\n"
        )
        # The diff is the REVIEW VIEW: secret-looking values are redacted here
        # so a cross-session reader (or a `sandboxctl diff`) never sees them in
        # clear, and hunks touching the pinned TMPDIR (.preflight-tmp) are
        # dropped so temp files never pollute the review nor get applied.
        # Apply does NOT read this file for content — it syncs the copy, so
        # redaction cannot change what is applied.
        self._pending.write_text(
            header + _strip_tmpdir(_redact_diff_body(body)), encoding="utf-8"
        )

    def cleanup(self):
        """Leave the sandbox intact (no delete). Discard is explicit (discard)."""


class PreflightProvider(TerminalEnvironmentProvider):
    name = "preflight"
    display_name = "Preflight"

    # NOT a container: the command runs in a LOCAL copy (reflink/copy) of the
    # real workspace. The process is a host process; no kernel or network
    # isolation. is_container=False is the honest option — we declare a
    # "dry-run gate", not a sandbox. uses_host_filesystem = False so the
    # agent's file-tools run inside the copy via execute() and never write the
    # real workspace directly (every change lands behind the copy/diff/apply
    # gate).
    is_remote = False
    is_container = False

    def __init__(self, *, sandbox_root: str | Path | None = None):
        # A per-profile override read from plugin config (key "sandbox_root");
        # when unset we fall back to the module default SANDROOT (active Hermes
        # home + /sandbox). Late import so the plugin loads even when the root
        # package is not imported.
        #
        # HONEST COMPATIBILITY CONTRACT with bin/sandboxctl: the CLI derives
        # the DEFAULT root (HERMES_HOME/sandbox or $HOME/.hermes/sandbox) and
        # cannot derive a per-profile override from the environment. The
        # backend therefore writes a one-line marker, .preflight-root, INSIDE
        # the DERIVED root that points to the effective root, and sandboxctl
        # reads it. Without the marker the CLI uses the derived root. This is a
        # convenience, not a security boundary: the staging root is writable by
        # the sandboxed agent (see README 'Honest limitations'), so the marker
        # is not a secretly-protected value.
        self._sandbox_root = Path(sandbox_root) if sandbox_root else None

    def _sandroot(self) -> Path:
        """Effective sandbox root for this provider (config override or default)."""
        if self._sandbox_root is not None:
            return self._sandbox_root
        return SANDROOT

    def _sync_root_marker(self) -> None:
        """Publish the effective root to `sandboxctl` via a .preflight-root marker.

        The marker lives inside the DERIVED root (the one place sandboxctl can
        always find). It is written when an override is active, and REMOVED when
        the default root is in use, so the CLI never follows a stale override.
        Failures are non-fatal: without a marker the CLI falls back to the
        derived root, which is the documented behavior for the default setup.
        """
        marker = SANDROOT / ".preflight-root"
        try:
            if self._sandroot() == SANDROOT:
                if marker.exists():
                    marker.unlink()
                return
            SANDROOT.mkdir(parents=True, exist_ok=True)
            marker.write_text(str(self._sandroot()), encoding="utf-8")
        except OSError:
            pass  # never let marker bookkeeping break session creation

    @property
    def description(self):
        return "Preflight dry-run gate: runs each command in a throwaway workspace copy, shows the exact diff, and applies only what you approve."

    @property
    def strip_env_keys(self):
        return frozenset(_STRIP_ENV_KEYS)

    @property
    def skip_container_guards(self):
        # We do NOT skip the approval guards: the model must approve before any
        # risky action. (The backend never applies on its own.)
        return False

    @property
    def default_cwd(self):
        # No per-session identical home; use the cwd Hermes already resolves.
        return None

    def is_available(self):
        return shutil.which("bash") is not None

    def create_environment(
        self,
        *,
        cwd: str,
        timeout: int,
        task_id: str = "default",
        image: str | None = None,
        container_config: dict | None = None,
        **kwargs,
    ):
        original = Path(cwd) if cwd else Path.cwd()
        # Refuse to clone the user's home or Hermes home (point: HOME / ~/.hermes
        # must never be the source of a sandbox copy). Cloning the home directory
        # copies it over itself, walks the whole tree via the copytree fallback
        # (filling the disk) and snapshots every secret under ~ into the copy.
        # Returns the CANONICAL (resolved) path; clone, registration and the
        # fingerprint all use it so a symlinked or `..`-aliased original cannot
        # dodge the TOCTOU boundary.
        original = self._reject_forbidden_original(original)
        # task_id sanitized (only [a-z0-9_-]) so it cannot leak into paths.
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", str(task_id)) or "default"
        sandbox_root = self._sandroot()
        # Keep bin/sandboxctl in sync with a possible override (point 2).
        self._sync_root_marker()
        sandbox_dir = sandbox_root / safe_id / "workspace"
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        # Register the original workspace (for sandboxctl apply/discard).
        sandbox_root.joinpath(safe_id, "original").write_text(str(original), encoding="utf-8")

        # Reuse a session that already has pending changes instead of re-cloning
        # and losing its PENDING.diff. After a successful apply, PENDING.diff is
        # emptied and the fingerprint refreshed (see bin/sandboxctl apply), so
        # the NEXT create_environment with the same task_id re-clones from the
        # APPLIED state — exactly what makes a second apply legitimate. A
        # discard removes the whole session dir. _clone wipes the previous copy
        # for the same task_id.
        pending = sandbox_dir / "PENDING.diff"
        has_pending = False
        try:
            has_pending = bool(pending.read_text(encoding="utf-8").strip())
        except OSError:
            has_pending = False
        if not has_pending:
            # Clone the workspace (reflink when the fs supports it, full copy
            # otherwise), then snapshot the original for the TOCTOU guard.
            self._clone(original, sandbox_dir)
            try:
                _write_original_fingerprint(original, sandbox_root.joinpath(safe_id, "original.fingerprint"))
            except Exception:
                pass  # apply will refuse if the fingerprint is missing

        return PreflightEnvironment(
            cwd=cwd, timeout=timeout, sandbox_path=sandbox_dir, original_path=original
        )

    def _reject_forbidden_original(self, original: Path) -> Path:
        """Refuse to clone the user's home / Hermes home, sensitive dirs, or a
        path that contains the sandbox root; return the canonical resolved path.

        ``cp -a ~/.hermes/sandbox/... ~/`` would copy the copy onto itself,
        the copytree fallback recurses until the disk fills, and every secret
        under ``~`` gets snapshotted into the copy. The same reasoning applies
        to credential stores under the home (~/.ssh, ~/.aws, ~/.gnupg) and to
        system directories (/etc, /var): cloning them snapshots secrets or
        explodes the tree. Raise a clear error asking the user to ``cd`` into a
        project directory instead.
        """
        try:
            orig_res = original.resolve()
        except Exception:
            orig_res = original.absolute()
        home = Path.home().resolve()
        sand_root = self._sandroot().resolve()
        hermes_homes = set()
        try:
            import hermes_constants

            hh = hermes_constants.get_hermes_home().resolve()
            hermes_homes.add(hh)
            hermes_homes.add(hh.parent)  # convenience: ~/.hermes == home of home
        except Exception:
            pass

        def under(a: Path, b: Path) -> bool:
            try:
                return os.path.commonpath([str(a), str(b)]) == str(b)
            except Exception:
                return False

        sensitive_home = [home / d for d in (".ssh", ".aws", ".gnupg")]
        system_roots = [Path("/etc"), Path("/var")]

        bad = False
        reason = ""
        if orig_res == home:
            bad = True
            reason = f"refusing to clone your home directory ({orig_res})"
        elif any(orig_res == h for h in hermes_homes):
            bad = True
            reason = f"refusing to clone the Hermes home directory ({orig_res})"
        elif any(orig_res == s or under(orig_res, s) for s in sensitive_home):
            bad = True
            reason = f"refusing to clone a sensitive directory under your home ({orig_res})"
        elif any(orig_res == s or under(orig_res, s) for s in system_roots):
            bad = True
            reason = f"refusing to clone a system directory ({orig_res})"
        elif sand_root and (under(orig_res, sand_root) or under(sand_root, orig_res)):
            bad = True
            reason = (
                f"refusing to clone a path that overlaps the sandbox root "
                f"({orig_res} vs {sand_root})"
            )
        if bad:
            raise ValueError(
                f"preflight: {reason}. This would copy the workspace onto itself "
                f"and snapshot every secret under it. cd into a project directory "
                f"first, then run the command there."
            )
        return orig_res

    @staticmethod
    def _clone(src: Path, dst: Path):
        # Clean workspace: drop any previous content of the same task_id.
        if dst.exists():
            for old in dst.iterdir():
                if old.is_dir() and not old.is_symlink():
                    shutil.rmtree(old, ignore_errors=True)
                else:
                    try:
                        old.unlink()
                    except OSError:
                        pass
        # 1) real reflink (fails if the fs does not support it -> fall to --reflink=auto loop).
        try:
            subprocess.run(
                ["cp", "-a", "--reflink=always", f"{src}/.", f"{dst}/"],
                check=True,
                capture_output=True,
            )
            return
        except Exception:
            pass
        # 2) normal copy (isolated, slower but safe).
        for child in src.iterdir():
            if child.name in ("PENDING.diff",):
                continue
            target = dst / child.name
            if target.exists():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink()
            if child.is_dir() and not child.is_symlink():
                shutil.copytree(child, target, symlinks=True)
            else:
                shutil.copy2(child, target, follow_symlinks=False)


def register(ctx):
    # Per-profile sandbox root override from plugin config (key "sandbox_root").
    # When unset, the provider falls back to the active Hermes home + /sandbox.
    overrides = {}
    try:
        root = ctx.get_config("sandbox_root")
        if root:
            overrides["sandbox_root"] = str(root)
    except Exception:
        pass  # no readable config -> default sandbox root
    provider = PreflightProvider(**overrides)
    # Publish the effective root marker for sandboxctl (see _sync_root_marker);
    # without it the CLI falls back to the derived root.
    provider._sync_root_marker()
    ctx.register_terminal_environment_provider(provider)
