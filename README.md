# preflight

**An approval dry-run gate, not an isolation sandbox.** A terminal backend for
Hermes that runs **every command in a throwaway copy** of your workspace, shows
you exactly what would change (**exact diff**), and **applies** the changes to
the real workspace only if *you* explicitly approve them. A universal dry-run:
a misfired `rm -rf`, a migration or a script never touches your data by accident.

> One-line design: **the agent SEES the real workspace, EXECUTES on the copy,
> and APPLIES with your approval.**

Status: `v0.1.0` · plugin `validated` · standalone sandbox test `9/9 passing` ·
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
| Shows what changes    | Yes, **exact diff** + select ive apply | No — isolates, doesn't teach | No — export, no diff    | No diff                  |
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

You review it, then decide to `apply` (it will *selectively* sync only those
paths) or `discard`.

## How it works

- `create_environment()` creates `<root>/<id>/workspace` and clones the workspace
  with **reflink** (`cp --reflink=always`, copy-on-write: zero-byte cost on
  btrfs/xfs, full copy as fallback). Existing pending changes for the same id
  are **reused**, never re-cloned, so your diff is not lost.
  > Design note: the idea originally asked for hardlinks (`cp -al`). Those are
  > not the primary method because they share inodes: `echo x > file` in the
  > sandbox would touch the original *without* going through `apply`. Reflink
  > gives the same "I copy no bytes" and isolates for real.
- `execute()` runs the command in the copy with a filtered environment
  (secrets stripped), applies guards, and returns `{output, exit_code}`.
- After each command it recomputes the diff original ↔ copy (`git diff
  --no-index` when there is a `.git`, `diff -ruN` otherwise) into
  `PENDING.diff`.
- **Nothing applies on its own.** `apply` runs a sync of the copy into the real
  workspace (no global `--delete`) after verifying a fingerprint that the real
  workspace has not changed since the clone (TOCTOU); deletions are applied
  explicitly and only for paths gone from the copy.

## Security guards (best-effort)

- Rejects `sudo` / `doas`, including after shell separators (`x&&sudo`,
  `(sudo …)`, `` `sudo …` ``). The check normalizes the command first (quotes and
  backslash escapes are stripped for the match), so wrappers like
  `bash -c 'sudo …'` are caught too.
- Rejects absolute paths that point **outside** the copy (including a bare `/`).
- Rejects write redirections (`>`, `2>`) to paths outside the copy.
- Rejects the operation if the copy contains **symlinks that escape** the
  sandbox (preserved by the clone; a symlink to `/etc` or `~/.ssh` would
  bypass the copy).
- **Filtered environment**: secrets are stripped from the subprocess using a
  **local** deny-list (it does not re-use the core's sanitizer). It strips any
  variable whose name starts with a sensitive prefix (`FAL_*`, `NOUS_*`,
  `OPENROUTER_*`, `ANTHROPIC_*`, `OPENAI_*`, `AWS_*`, `GCP_*`, `GCLOUD_*`,
  `AZURE_*`, `DOCKER_*`, `HF_*`, `HUGGINGFACE_*`, `MESHY_*`, `SUPABASE_*`),
  ends with a sensitive pattern (`*_API_KEY`, `*_TOKEN`, `*_SECRET`,
  `*_PASSWORD`, `*_CREDENTIAL`, `*_ACCESS_KEY`), or is an exact key
  (`SSH_AUTH_SOCK`, `GOOGLE_APPLICATION_CREDENTIALS`, `NPM_TOKEN`, `GH_TOKEN`,
  `GITHUB_TOKEN`, `NETRC`). All matching is case-insensitive.
- `HOME` is pinned **inside the copy**, so `cd ~`, `~/.bashrc`, git config etc.
  never escape to the real user directory.
- `skip_container_guards = False`: the model still goes through Hermes' approval
  guards.

> These guards are **heuristics, not a kernel sandbox**. The command *does have
> network access* and runs as a host process. See "What it doesn't do" below.

## When NOT to use preflight

- **Kernel isolation** is mandatory — preflight is a decision gate, not a
  container. Use Docker/Modal/VMs for hostile or untrusted code.
- **Hostile code** — a command meant to fight back (not just a mistaken `rm`)
  can defeat regex guards. Don't run untrusted code here.
- **Very large workspaces without copy-on-write** — on filesystems without
  CoW (e.g. EXT4) the full-copy fallback is slow; you may not want a full copy
  per session.

## Honest limitations

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
- The raw diff includes absolute path names; in a git repo you may want to
  review `PENDING.diff` against the repo.

## Files

```
~/.hermes/plugins/preflight/
├── plugin.yaml          # id/version/kind: backend
├── __init__.py          # Provider + Environment + register(ctx)
├── bin/sandboxctl       # status | diff | apply | discard
├── tests/_test_sandbox.py # functional test (run: python3 tests/_test_sandbox.py)
├── tests/_probe_leak.py    # leak regression probe (run: python3 tests/_probe_leak.py)
└── README.md            # this file
```

## Quick verification

```bash
python3 tests/_test_sandbox.py   # must end with: TODO PASS ✔
hermes plugins validate ~/.hermes/plugins/preflight   # Validation passed, security scan safe
```
