# preflight

**An approval dry-run gate, not an isolation sandbox.** A terminal backend for
Hermes that runs **every command in a throwaway copy** of your workspace, shows
you exactly what would change (**exact diff**), and **applies** the changes to
the real workspace only if *you* explicitly approve them. A universal dry-run:
a misfired `rm -rf`, a migration or a script never touches your data by accident.

> One-line design: **the agent SEES the copy, EXECUTES on the copy, and APPLIES
> with your approval.**

Status: `v0.1.0` · plugin `validated` · standalone sandbox test `36/36 passing` ·
runs on `linux` and `macos`.

## Quickstart

```bash
hermes plugins enable preflight
hermes config set terminal.backend preflight
```

That's it. Your next terminal commands run inside a copy of the workspace and
nothing is applied until you run `sandboxctl apply <task_id>`.

## Why preflight?

Today an agent just executes real commands: a wrong `rm -rf` is data gone
forever. There is no universal "review this before I run it" step. With
**preflight** the agent works on a copy; if the command goes sideways you
discard the copy and the real workspace is untouched.

|                       | preflight                    | bubblewrap              | runbox / Docker     | deadbolt                 |
|-----------------------|------------------------------|-------------------------|---------------------|--------------------------|
| What it isolates      | the *workspace copy*         | the whole process       | the whole process   | the real filesystem      |
| Container / kernel    | No — host process            | Yes (namespaces/bind)   | Yes (Docker)        | No (still host process)  |
| Shows what changes    | Yes, **exact diff** + whole-workspace apply | No — isolates, doesn't teach | No — export, no diff    | No diff                  |
| Before writing        | Diff + explicit approval     | No review gate          | No review gate      | Write-approval prompts   |
| Re-apply to the real  | `apply`/`discard` explicit   | None (dies with ctr)    | `export` / copy     | N/A (writes go through)  |

- **bubblewrap** isolates but never *teaches*: it runs in a container and
  whatever happens inside dies with it, with no diff and no prior decision.
- **runbox** exports Docker images but offers no exact diff to review.
- **deadbolt** gates writes with approval prompts but shows no diff of the
  whole operation.
- **preflight** is a **decision gate**: you see exactly what would change and
  decide before it touches the real workspace.

## A real diff

After a command, the session's `PENDING.diff` shows what applying would do.
This is genuine `diff -ruN` output from a session where the sandbox changed a
config file and deleted a secret:

```
diff -ruN -x PENDING.diff /real/ws /sandbox/task-AB12/workspace
--- /real/ws/src/config.py        2026-11-10 22:46:02.783832625 -0600
+++ /sandbox/task-AB12/workspace/src/config.py  1969-12-31 18:00:00.000000000 -0600
@@ -1,2 +1,2 @@
-API_KEY = "sk-REAL-SECRET"
+API_KEY = "sk-SAFE-SECRET"
Only in /real/ws: credentials/db-password.txt
```

You review it, then decide to `apply` or `discard`.

`apply` approves the **whole pending diff** (the entire workspace copy is
synced into the real workspace via `rsync -a` plus explicit deletions, no
global `--delete`) — it does **not** offer per-file selection. `PENDING.diff`
is the review gate for **content**: it shows what text/files change. It is NOT
a byte-exact preview — mtimes, permissions and other metadata can change (or
whole files be synced) without appearing as diff lines. If you want only some
of the changes, edit the copy (or discard and start a focused session) before
applying.

## How it works

- `create_environment()` creates `<root>/<id>/workspace` and clones the workspace
  with **reflink** (`cp --reflink=always`, copy-on-write: zero-byte cost on
  btrfs/xfs, full copy as fallback). Existing pending changes for the same id
  are **reused**, never re-cloned, so your diff is not lost.
  > Design note: the idea originally asked for hardlinks (`cp -al`). Those are
  > not the primary method because they share inodes: `echo x > file` in the
  > sandbox would touch the original *without* going through `apply`. Reflink
  > gives the same "I copy no bytes" and isolates for real.
- `create_environment()` derives the sandbox root from the **active Hermes
  home** (`get_hermes_home() + /sandbox`), so each profile gets its own sandbox
  namespace; a per-profile `sandbox_root` key (plugin config) overrides it.
  Cloning the user's home or Hermes home is **refused** (`cd into a project`).
- `execute()` runs the command in the copy with a filtered environment
  (secrets stripped), applies guards, and returns `{output, exit_code}`.
- The backend sets `uses_host_filesystem = False`, so Hermes' file tools
  (`read_file`, `write_file`, `patch`, `search_files`) run **inside the copy**
  via `execute()`. They never touch the real workspace directly — every edit
  lands behind the copy/diff/apply gate.
- After each command it recomputes the diff original ↔ copy (`git diff
  --no-index` when there is a `.git`, `diff -ruN` otherwise) into
  `PENDING.diff`.
- **Nothing applies on its own.** `apply` runs a sync of the copy into the real
  workspace (no global `--delete`) after verifying a fingerprint that the real
  workspace has not changed since the clone (TOCTOU, now a sha256 content hash
  per file) and that the copy contains no symlink escaping the sandbox root;
  deletions are applied explicitly and only for paths gone from the copy.
  `apply` needs **human confirmation on an interactive terminal** — `--yes` is
  honored only when stdin is a TTY. This check is **best-effort**: a determined
  agent that allocates a pty (`python3 -c "import pty"`, `script`, `ssh -tt`)
  can self-approve. It stops accidental non-TTY approvals, not a determined
  local agent.

## Security guards (best-effort)

- Rejects `sudo` / `doas`, including after shell separators (`x&&sudo`,
  `(sudo …)`, `` `sudo …` ``). The check normalizes the command first (quotes and
  backslash escapes are stripped for the match), so wrappers like
  `bash -c 'sudo …'` are caught too.
- Rejects absolute paths that point **outside** the copy (including a bare `/`).
  Paths are **resolved** before the boundary test, so `/tmp/../etc/passwd`
  cannot dodge it.
- Shell variables in command tokens are expanded **against the child's env**
  before the boundary test (the same env that is injected: HOME and TMPDIR are
  pinned inside the copy). That closes the `$EMPTY/etc/passwd` class of
  bypasses — an unset variable expands to the empty string, `/etc/passwd` is
  seen for what it is and blocked. `$HOME/…` and `$TMPDIR/…` resolve inside the
  copy and keep working normally. Variables defined *inside the command itself*
  (`X=/etc; cat $X/passwd`) are invisible to this heuristic.
- Rejects relative paths that **escape** the copy by resolving every path-ish
  token against the copy's cwd — including embedded `..` that does not start
  with a dot, e.g. `a/../../x.txt` or `cat a/../../../etc/passwd`.
- Rejects write redirections (`>`, `2>`) to paths outside the copy.
- Rejects the operation if the copy contains **symlinks that escape** the
  sandbox (preserved by the clone; a symlink to `/etc` or `~/.ssh` would
  bypass the copy). `apply` re-runs the same symlink scan before syncing, so a
  symlink created during the session cannot be copied into the real workspace.
- **Filtered environment**: secrets are stripped from the subprocess using a
  **local** deny-list (it does not re-use the core's sanitizer). It strips any
  variable whose name starts with a sensitive prefix (`FAL_*`, `NOUS_*`,
  `OPENROUTER_*`, `ANTHROPIC_*`, `OPENAI_*`, `AWS_*`, `GCP_*`, `GCLOUD_*`,
  `AZURE_*`, `DOCKER_*`, `HF_*`, `HUGGINGFACE_*`, `MESHY_*`, `SUPABASE_*`),
  ends with a sensitive pattern (`*_API_KEY`, `*_TOKEN`, `*_SECRET`,
  `*_PASSWORD`, `*_CREDENTIAL`, `*_ACCESS_KEY`, `*_PASS`, `*_PWD`, `*_KEY`,
  `*_URL`), or is an exact key (`SSH_AUTH_SOCK`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `NPM_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`,
  `NETRC`, `PGPASSWORD`, `MYSQL_PWD`, `RCLONE_CONFIG_PASS`). All matching is
  case-insensitive.
- `PENDING.diff` is a **redacted review view**: `NAME=value` lines whose name
  smells like a secret (`TOKEN=`, `*_KEY=`, `*_SECRET=`, `*_PASSWORD=`,
  `*_URL=`...), URL userinfo and bare secret-looking tokens are masked, so a
  cross-session reader or `sandboxctl diff` never sees credentials in clear.
  Applying is NOT affected — apply syncs the copy, it never reads the diff.
- `HOME` and `TMPDIR` (plus `TMP`/`TEMP` when picked up from the host env) are
  pinned **inside the copy**: `cd ~`, `~/.bashrc`, git config, `mktemp` and any
  tool honoring `$TMPDIR` never escape to the real user directory or the host
  `/tmp`. The pinned temp dir is `<copy>/.preflight-tmp`, created with the
  environment; because it lives in the copy it is excluded from `PENDING.diff`
  and from `apply` (`rsync --exclude=.preflight-tmp`), so temp files never
  pollute the review nor get written to the real workspace.
- `skip_container_guards = False`: the model still goes through Hermes' approval
  guards.
- Pattern matching can reject benign commands that merely contain the word
  `sudo` (e.g. `echo 'no sudo here'`); this is a deliberate fail-safe, not a
  bug.

> These guards are **heuristics, not a kernel sandbox**. The command *does have
> network access* and runs as a host process. Every guard message says so
> explicitly and points here; the plugin never claims the host is unreachable
> from the copy. See "Honest limitations" below.

## When NOT to use preflight

- **Kernel isolation** is mandatory — preflight is a decision gate, not a
  container. Use Docker/Modal/VMs for hostile or untrusted code.
- **Hostile code** — a command meant to fight back (not just a mistaken `rm`)
  can defeat regex guards. Don't run untrusted code here.
- **Very large workspaces without copy-on-write** — on filesystems without
  CoW (e.g. EXT4) the full-copy fallback is slow; you may not want a full copy
  per session.

## Honest limitations

The guards scan **literal command strings only**. These concrete blind spots
are by name, not in the abstract:

- **Variable expansion can still touch the host.** `$HOME` and `$TMPDIR` are
  pinned inside the copy, but a host variable that reaches the child and is
  used in a path is expanded by bash after the string scan. Examples that can
  still read/write the host: an unset variable that concatenates an absolute
  path inside the command (`X=/etc; cat $X/passwd`), variables defined
  elsewhere in the same command line, and a host `$TMPDIR`/`$TMP`/`$TEMP`
  value when it predates the pin (the pin replaces the value the child sees,
  but the *string* `$TMPDIR` in a command is only judged after expansion).
- **Invoked scripts can still touch the host.** The guards see `bash
  script.sh`, not the script's contents: a script that contains `cat
  /etc/passwd` or `echo x > $HOME/out` runs on the host. Same for `python3 -c
  "..."`, `python -`, `. file.sh`, `source`, `curl | sh`, or any subprocess
  that executes code from inside a file. The line of command is scanned; the
  file it runs is not.
- **The staging root is NOT a trust boundary.** Sandboxes of different
  sessions live under one root (`<derived or override root>/<id>/…`), and the
  sandboxed agent receives `$PREFLIGHT_ROOT` pointing at that root. From
  inside a copy an agent can therefore **read or overwrite another session's
  registration record** (e.g. `$PREFLIGHT_ROOT/victim/original`) and the
  fingerprint file (`$PREFLIGHT_ROOT/victim/original.fingerprint`, which is
  writable). The guards block the obvious literal/expanded forms, but the
  staging area is a shared workspace, not a fortress: the real protection is
  the **human TTY confirmation on `apply`/`discard`** (best-effort, as stated)
  plus the fact that a tampered session still cannot change *your* decision to
  apply it or not.
- **The copy is not a boundary against the agent**: a relative `../` path can
  reach outside it (the guards resolve paths against the copy's cwd and reject
  the obvious escapes, but a determined command string can still evade — the
  guards are heuristics, not a kernel sandbox). The real protection is that
  apply needs **your** explicit approval on a terminal. That check is
  **best-effort too**: an agent with access to a pty can self-approve — see
  "When NOT to use preflight". Run untrusted/hostile code in a real container.
- **Not a real kernel sandbox.** The shell runs on the host (the `cwd` is a
  copy). Path/sudo guards are best-effort pattern matching and a cleverer
  nested shell could still evade them (e.g. `bash -c 'sudo …'` wrapped in
  base64).
- **The command has network access** — it is *not* a network-isolating sandbox.
- **WSL /mnt/c is slow** — a Windows-linked path is slow to walk/copy; keep the
  workspace on a Linux filesystem (e.g. `~/`) for fast reflink clones.
- **`sandboxctl` is not on your PATH** — add an alias in `~/.bashrc`:
  ```bash
  alias sandboxctl="$HOME/.hermes/plugins/preflight/bin/sandboxctl"
  ```
- Reflink falls back to a full copy on filesystems without CoW (e.g. EXT4):
  slower on big workspaces, equally safe.
- Different `task_id` means a different copy: changes are not shared between
  sessions.
- After a successful `apply`, the session is left clean: `PENDING.diff` is
  emptied and the integrity fingerprint is refreshed, so reusing the same
  `task_id` legitimately starts a fresh review (the next `create_environment`
  re-clones from the applied state). Applying again without new changes will
  simply report no pending changes instead of a stale "CHANGED"; apply without
  a fresh review still refuses if another real change happened meanwhile.
- The raw diff includes absolute path names; in a git repo you may want to
  review `PENDING.diff` against the repo.

## Multiple profiles

Every profile gets its own sandbox namespace (the backend derives the root
from the **active** Hermes home + `/sandbox`, or honors a per-profile
`sandbox_root` plugin-config key). `sandboxctl` derives the default root the
same way, and its destructive commands (`apply` / `discard`) refuse a
`PREFLIGHT_ROOT` that does not match the effective root.

**`sandbox_root` override + `sandboxctl`:** the CLI cannot derive a
per-profile override from the environment, so it does **not** claim to mirror
it. The backend writes the effective root to a one-line marker,
`<derived root>/.preflight-root`, and `sandboxctl` reads that marker: with the
marker present, status/apply/discard target the overridden root; without it
(no session created by the backend yet, or a default setup), the CLI uses the
derived root. The marker is a convenience so the CLI can honor the override —
it is **not** a trust boundary and does not bootstrap a second way to bypass
the TTY confirmation.

To target a *specific* profile's sessions from a shell that is not running
that profile, export its Hermes home first:

```bash
export HERMES_HOME=~/.hermes/profiles/<profile>
sandboxctl status
```

`PREFLIGHT_ROOT` is transport-only: the backend sets it for child scripts, and
it must equal the effective root (marker or derived), so a sandboxed command
cannot aim `discard` at another profile's sessions.

## Files

```
~/.hermes/plugins/preflight/
├── plugin.yaml          # id/version/kind: backend
├── __init__.py          # Provider + Environment + register(ctx)
├── bin/sandboxctl       # status | diff | apply | discard
├── tests/_test_sandbox.py # functional test (run: python3 tests/_test_sandbox.py)
├── tests/_probe_leak.py    # leak regression probe (run: python3 tests/_probe_leak.py)
├── tests/_poc_evidence.py  # audited PoCs demo (run: python3 tests/_poc_evidence.py)
└── README.md            # this file
```

## Quick verification

```bash
python3 tests/_test_sandbox.py   # must end with: TODO PASS ✔ (36 PASS)
python3 tests/_probe_leak.py     # must end with: TODO OK: sin fugas
python3 tests/_poc_evidence.py   # demos the audited PoCs are mitigated
hermes plugins validate ~/.hermes/plugins/preflight   # Validation passed, security scan safe
```
