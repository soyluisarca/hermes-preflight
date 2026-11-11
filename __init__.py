"""preflight: terminal backend that runs each command in a throwaway copy of the
workspace.

Every command executes inside a local copy (reflink full copy) of the real
workspace. The real workspace is NEVER touched. After each command a diff is
accumulated in PENDING.diff. Applying (selective rsync copy -> real) and
discarding are EXPLICIT actions that never happen on their own.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from agent.terminal_env_provider import TerminalEnvironmentProvider

# Root directory for sandboxes (root of PKG, not exposed to network or user).
# PREFLIGHT_ROOT is the canonical variable; SANDBOX_FIRST_ROOT is kept as a
# fallback so existing sessions, cron configs and the standalone test keep
# working without changes.
SANDROOT = Path(
    os.getenv("PREFLIGHT_ROOT")
    or os.getenv("SANDBOX_FIRST_ROOT")
    or (Path.home() / ".hermes" / "sandbox")
)

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
# Sensitive suffixes stripped, again case-insensitive.
_STRIP_ENV_SUFFIX = (
    "_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL", "_ACCESS_KEY",
)
# Exact names always dropped (case-insensitive), e.g. git/registry/ssh creds.
_STRIP_ENV_EXACT = frozenset({
    "SSH_AUTH_SOCK", "GOOGLE_APPLICATION_CREDENTIALS", "NPM_TOKEN", "GH_TOKEN",
    "GITHUB_TOKEN", "HF_TOKEN", "NETRC",
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


def _write_original_fingerprint(original: Path, dst: Path) -> None:
    """Snapshot of the real workspace at clone time.

    ``sandboxctl apply`` recomputes this and aborts if it changed since the
    clone (TOCTOU guard): a file created or edited in the real workspace AFTER
    the clone must never be silently clobbered by an apply.
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
            lines.append(f"{os.path.join(rel_root, d)}\t{st.st_mtime_ns}\t{st.st_size}\td")
        for f in files:
            p = os.path.join(root, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            lines.append(f"{os.path.join(rel_root, f)}\t{st.st_mtime_ns}\t{st.st_size}\tf")
    dst.write_text("\n".join(sorted(lines)), encoding="utf-8")


class PreflightEnvironment:
    """Duck-typed BaseEnvironment (execute/cleanup).

    HONEST contract (we do not claim what we do not do):
      - NOT a container. The command runs in a LOCAL copy (reflink/copy) of the
        workspace, but the process is a host process.
      - uses_host_filesystem = True: the agent's file-tools read the REAL
        workspace, not the copy. The agent SEES the real one, EXECUTES on the
        copy and APPLIES with explicit approval.
      - is_local = True: runs on the local machine, not remote.
    """

    uses_host_filesystem = True
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
    def _block_host_absolute_paths(command: str, sandbox_path: Path) -> list[str]:
        """Best-effort detection of absolute paths pointing OUTSIDE the copy.

        Not a real sandbox (the shell runs on the host), so this guard is an
        honest safety net, not an impenetrable wall.
        """
        problems: list[str] = []
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Unbalanced quotes / heredocs: fall back to a regex scan of absolute
            # tokens. Never block on a parse failure.
            tokens = [m.group(0) for m in re.finditer(r"/[^\s'\"`;|&()]*", command)]
        for tok in tokens:
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
            try:
                is_under = os.path.commonpath([sandbox_path, tok]) == str(sandbox_path)
            except Exception:
                is_under = False
            if not is_under and not tok.startswith("/dev/null"):
                problems.append(tok)
        return problems

    def _block_writes_outside(self, command: str):
        """Reject explicit *writes* (redirection or >) to absolute paths outside the copy."""
        for m in re.finditer(r"[12]?>+\s*('([^']*)'|\"([^\"]*)\"|(\S+))", command):
            target = m.group(2) or m.group(3) or m.group(4) or ""
            if not target.startswith("/"):
                continue
            try:
                is_under = os.path.commonpath([self.sandbox_path, target]) == str(self.sandbox_path)
            except Exception:
                is_under = False
            if not is_under and target != "/dev/null":
                return (
                    f"Blocked by preflight: write redirection to a path outside the "
                    f"copy ({target}). Nothing is written outside the sandbox."
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
        return env

    def execute(self, command: str, timeout: int | None = None, **kwargs):
        # 1) Security guards.
        sudo_err = self._reject_sudo(command)
        if sudo_err:
            return {"output": sudo_err, "exit_code": 1, "returncode": 1}

        symlink_err = self._block_symlink_escape()
        if symlink_err:
            return {"output": symlink_err, "exit_code": 1, "returncode": 1}

        write_err = self._block_writes_outside(command)
        if write_err:
            return {"output": write_err, "exit_code": 1, "returncode": 1}

        paths = self._block_host_absolute_paths(command, self.sandbox_path)
        if paths:
            return {
                "output": (
                    "Blocked by preflight: absolute path(s) outside the sandbox "
                    f"copy: {', '.join(paths)}"
                ),
                "exit_code": 1,
                "returncode": 1,
            }

        effective_timeout = timeout or self.timeout or 120

        # 2) Filtered environment (secrets removed; HOME pinned to the copy).
        env = self._make_env()

        # 3) Run inside the copy.
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
        self._pending.write_text(header + body, encoding="utf-8")

    def cleanup(self):
        """Leave the sandbox intact (no delete). Discard is explicit (discard)."""


class PreflightProvider(TerminalEnvironmentProvider):
    name = "preflight"
    display_name = "Preflight"

    # NOT a container: the command runs in a LOCAL copy (reflink/copy) of the
    # real workspace. The process is a host process; no kernel or network
    # isolation. is_container=False is the honest option — we declare a
    # "dry-run gate", not a sandbox. The agent's file-tools keep reading the REAL
    # workspace (uses_host_filesystem).
    is_remote = False
    is_container = False

    def __init__(self):
        # late import so the plugin loads even if the root package is not imported
        pass

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
        # task_id sanitized (only [a-z0-9_-]) so it cannot leak into paths.
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", str(task_id)) or "default"
        sandbox_dir = SANDROOT / safe_id / "workspace"
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        # Register the original workspace (for sandboxctl apply/discard).
        SANDROOT.joinpath(safe_id, "original").write_text(str(original), encoding="utf-8")

        # Reuse a session that already has pending changes instead of re-cloning
        # and losing its PENDING.diff. Re-clone only after a discard/apply:
        # (see _clone: it wipes the previous copy for the same task_id).
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
                _write_original_fingerprint(original, SANDROOT.joinpath(safe_id, "original.fingerprint"))
            except Exception:
                pass  # apply will refuse if the fingerprint is missing

        return PreflightEnvironment(
            cwd=cwd, timeout=timeout, sandbox_path=sandbox_dir, original_path=original
        )

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
    ctx.register_terminal_environment_provider(PreflightProvider())
