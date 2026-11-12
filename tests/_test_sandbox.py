#!/usr/bin/env python3
"""Test funcional de preflight (backend + sandboxctl).

Cubre (del más antiguo al más nuevo):
  1. el workspace REAL no cambia al ejecutar comandos en la copia,
  2. la copia refleja los cambios (borrados incluidos),
  3. PENDING.diff lista los borrados y los writes de file-tools (gated),
  4. el provider registra el workspace original para sandboxctl,
  5. sandboxctl status lista la sesión (root derivado del Hermes home),
  6. apply: rechazado no interactivo (sin --yes y con --yes), aplica solo vía
     terminal interactiva, y aplica EXACTAMENTE lo del diff (whole-workspace),
  7. discard no toca el workspace real y exige confirmación como apply,
  8. guardas: sudo bloqueado, ruta absoluta fuera bloqueada, ../ relativa bloqueada,
  9. symlink fuera de la copia bloqueado,
 10. file-tools gated (uses_host_filesystem == False),
 11. rechazo de clonar HOME / Hermes home / un path que contiene el sandbox root,
 12. SANDROOT derivado de get_hermes_home() + /sandbox,
 13. escape relativo con `..` EMBEBIDO (a/../../x, a/../../../etc/passwd) bloqueado,
 14. el claim "cannot self-approve" ya no existe (TTY = best-effort, no wall),
 15. fingerprint con sha256: cambio real con mtime+size preservados -> apply NEGADO,
 16. symlink que escapa en la copia -> apply bloqueado; symlink interno -> apply OK,
 17. discard: PREFLIGHT_ROOT de otro perfil rechazado, sin TTY rechazado, con TTY OK,
 18. PENDING.diff redacta secretos (TOKEN=, *_KEY=, *_URL=) para lectores cross-session,
 19. env filter ampliado: _PASS/_PWD/_KEY/_URL/PGPASSWORD/RCLONE_CONFIG_PASS no llegan al hijo,
 20. clonar ~/.ssh, ~/.aws, ~/.gnupg, /etc, /var rechazado; subdir normal bajo ~ OK,
 21. clone usa el original RESUELTO (symlink/`..` no cuelan el TOCTOU),
 22. sandboxctl --help documenta multi-perfil (HERMES_HOME),
 23. apply muestra "N más líneas" y cómo ver el diff completo,
 24. README aclara apply whole-workspace (rsync -a) y byte-exact no garantizado.
"""
import json
import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Paths relativos al propio test; el repo de Hermes se toma de HERMES_AGENT_REPO
# (o de un default razonable) para que el test corra en cualquier máquina.
PLUGIN_DIR = Path(__file__).resolve().parent.parent
REPO = Path(os.environ.get("HERMES_AGENT_REPO", str(Path.home() / ".hermes" / "hermes-agent")))
sys.path.insert(0, str(REPO))

# Sandbox temporal aislado: el plugin ya NO lee PREFLIGHT_ROOT/SANDBOX_FIRST_ROOT
# del entorno; deriva el root de get_hermes_home() + /sandbox. Apuntamos
# HERMES_HOME a un directorio temporal y ELIMINAMOS cualquier PREFLIGHT_ROOT
# residual para que el backend y sandboxctl usen exactamente el mismo root.
os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="sbx-home-")
os.environ.pop("PREFLIGHT_ROOT", None)
os.environ.pop("SANDBOX_FIRST_ROOT", None)

mod = {}
plugin_path = PLUGIN_DIR / "__init__.py"
exec(compile(plugin_path.read_text(), str(plugin_path), "exec"), mod)

Provider = mod["PreflightProvider"]
provider = Provider()
assert provider.is_available(), "bash no está disponible"

# Root derivado (punto 4): SANDROOT == get_hermes_home()/sandbox == $HERMES_HOME/sandbox.
SB_ROOT = Path(os.environ["HERMES_HOME"]) / "sandbox"
assert mod["SANDROOT"] == SB_ROOT, f"SANDROOT no derivado del Hermes home: {mod['SANDROOT']} != {SB_ROOT}"
print("PASS 0: SANDROOT derivado de get_hermes_home() + /sandbox")

sbctl = PLUGIN_DIR / "bin" / "sandboxctl"

pass_count = 1  # PASS 0 arriba


def bump(label):  # noqa: ANN001 - label puede ser "6a" o el int del contador
    global pass_count
    pass_count += 1
    print(f"PASS {label}")


def run_sbctl(*args, env=None, input_bytes=None):
    """Run sandboxctl in its own subprocess; non-interactive by default."""
    return subprocess.run(
        ["bash", str(sbctl), *args],
        capture_output=True,
        text=True,
        env=env or {**os.environ},
        input=input_bytes,
    )


def run_sbctl_tty(*args, answer: str = "s\n"):
    """Run sandboxctl with stdin/out on a real pty and feed one answer.

    The apply/discard contract requires a REAL terminal for confirmation:
    --yes is honored only when stdin is a TTY, and a non-TTY apply/discard is
    refused. This helper is the only way a test can legitimately confirm.
    """
    master, slave = pty.openpty()
    pid = os.fork()
    if pid == 0:  # child
        os.setsid()
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        os.close(master)
        os.close(slave)
        os.execvp("bash", ["bash", str(sbctl), *args])
    os.close(slave)
    time.sleep(0.3)  # let the prompt render before feeding the answer
    try:
        os.write(master, answer.encode())
    except OSError:
        pass
    out = b""
    while True:
        try:
            ready, _, _ = select.select([master], [], [], 8.0)
        except OSError:
            break
        if not ready:
            break
        try:
            data = os.read(master, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0
    try:
        os.close(master)
    except OSError:
        pass
    code = getattr(os, "waitstatus_to_exitcode", lambda s: s >> 8)(status)
    return code, out.decode(errors="replace")


def make_ws(files: dict[str, str] | None = None, *, prefix="ws-"):
    """Fresh workspace under /tmp with the given relative file contents."""
    ws = Path(tempfile.mkdtemp(prefix=prefix))
    for rel, content in (files or {}).items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return ws


# --- 1) workspace temporal con 2 archivos en subdir ---
ws = make_ws({"subdir/a.txt": "contenido A\n", "subdir/b.txt": "contenido B\n", "root.txt": "raiz\n"})

# --- 2) Environment del plugin ---
env = provider.create_environment(cwd=str(ws), timeout=15, task_id="demo-test")

# notamos el snap del workspace real
before = {p.relative_to(ws).as_posix(): p.read_bytes() for p in ws.rglob("*") if p.is_file() and p.name != "PENDING.diff"}

# --- 3) correr rm -rf subdir ---
res = env.execute("rm -rf subdir")
assert res["exit_code"] == 0, f"rm falló: {res!r}"

# --- 4) workspace REAL intacto ---
after = {p.relative_to(ws).as_posix(): p.read_bytes() for p in ws.rglob("*") if p.is_file() and p.name != "PENDING.diff"}
assert sorted(before) == sorted(after), "el workspace REAL cambió"
assert (ws / "subdir" / "a.txt").exists(), "a.txt borrado del real?!"
bump(1)

# --- copia si aislada (a.txt borrado ahí) ---
sandbox_copy = env.sandbox_path
assert not (sandbox_copy / "subdir" / "a.txt").exists(), "la copia del sandbox no reflejó el borrado"
assert (ws / "root.txt").exists(), "root.txt debería seguir en el real"
bump(2)

# --- 5) PENDING.diff lista los borrados ---
pending = env.sandbox_path / "PENDING.diff"
assert pending.exists(), "no hay PENDING.diff"
text = pending.read_text()
deleted = [l for l in text.splitlines() if l.startswith("-") and not l.startswith("---") and not l.startswith("--")]
assert deleted, f"PENDING.diff no lista los borrados:\n{text}"
assert any("contenido" in l for l in deleted), f"los borrados no muestran el contenido:\n{deleted}"
assert "subdir" in text, "el diff no menciona subdir"
bump(3)

# --- 6) sandboxctl apply: aplica todo el diff, con confirmación humana ---
orig_file = env.sandbox_path.parent / "original"
assert orig_file.exists() and orig_file.read_text().strip() == str(ws), "no se registró el original"
bump(4)

# status (el root que muestra sandboxctl debe coincidir con SB_ROOT)
st = run_sbctl("status")
assert "demo-test" in st.stdout, f"status no lista la sesión: {st.stdout} {st.stderr}"
assert SB_ROOT.as_posix() in st.stdout, f"status usa un root distinto al del backend: {st.stdout}"
bump(5)

# apply NO interactivo es rechazado, con y sin --yes
r_no = run_sbctl("apply", "demo-test")
assert r_no.returncode != 0, "apply no interactivo sin --yes debería ser rechazado"
assert "interactive" in (r_no.stdout + r_no.stderr).lower(), f"mensaje de rechazo: {r_no.stdout} {r_no.stderr}"
r_yes = run_sbctl("apply", "demo-test", "--yes")
assert r_yes.returncode != 0, "apply --yes no interactivo debería ser rechazado"
assert "--yes" in (r_yes.stdout + r_yes.stderr), f"mensaje de rechazo --yes: {r_yes.stdout} {r_yes.stderr}"
bump("6a")

# apply interactivo: el humano confirma de verdad (pty). Aplica TODO el diff.
code, out = run_sbctl_tty("apply", "demo-test", answer="s\n")
assert code == 0, f"apply interactivo falló: code={code} out={out}"
assert not (ws / "subdir" / "a.txt").exists(), "apply no aplicó el borrado a.txt"
assert not (ws / "subdir" / "b.txt").exists(), "apply no aplicó el borrado b.txt"
assert (ws / "root.txt").exists(), "apply borró root.txt sin que estuviera en el diff"
bump("6b")

# --- 7) discard: exige confirmación; no toca el real; limpió la sesión ---
env2 = provider.create_environment(cwd=str(ws), timeout=15, task_id="discard-test")
env2.execute("rm -f root.txt")
r_discard_ntty = run_sbctl("discard", "discard-test")
assert r_discard_ntty.returncode != 0, "discard sin TTY debería ser rechazado"
assert "interactive" in (r_discard_ntty.stdout + r_discard_ntty.stderr).lower(), f"mensaje discard: {r_discard_ntty.stdout} {r_discard_ntty.stderr}"
assert (SB_ROOT / "discard-test").exists(), "discard sin TTY borró la sesión igual"
code, out = run_sbctl_tty("discard", "discard-test", answer="s\n")
assert code == 0, f"discard interactivo falló: code={code} out={out}"
assert (ws / "root.txt").exists(), "discard tocó el workspace real"
assert not (SB_ROOT / "discard-test").exists(), "discard no borró la sesión"
bump(7)

# --- 8) guardas: sudo bloqueado; ruta absoluta fuera bloqueada; ../ relativa bloqueada ---
r_sudo = env.execute("sudo rm -rf /")
assert r_sudo["exit_code"] == 1 and "blocked" in r_sudo["output"].lower(), f"sudo no bloqueado: {r_sudo!r}"
bump("8a")

r_abs = env.execute("cat /etc/passwd")
assert r_abs["exit_code"] == 1 and "blocked" in r_abs["output"].lower(), f"ruta absoluta fuera no bloqueada: {r_abs!r}"
bump("8b")

r_rel = env.execute("echo pwn > ../escape.txt")
assert r_rel["exit_code"] == 1 and "relative" in r_rel["output"].lower(), f"../ relativa no bloqueada: {r_rel!r}"
assert not (env.sandbox_path.parent / "escape.txt").exists(), "la ../ relativa logró escribir fuera de la copia"
bump("8c")

# --- 9) symlink que escapa de la copia -> operación bloqueada ---
ws_sym = make_ws(prefix="ws-sym-")
outside = Path(tempfile.mkdtemp(prefix="outside-"))
(outside / "secreto.txt").write_text("secreto host\n")
(ws_sym / "link").symlink_to(outside, target_is_directory=True)  # apunta FUERA del ws
env_sym = provider.create_environment(cwd=str(ws_sym), timeout=15, task_id="symlink-test")
r_sym = env_sym.execute("cat link/secreto.txt")
assert r_sym["exit_code"] == 1, f"un comando cruzó por symlink: {r_sym!r}"
assert "symlink" in r_sym["output"].lower(), f"el guard no menciona symlink: {r_sym['output']}"
assert (outside / "secreto.txt").read_text() == "secreto host\n", "el symlink tocó el host"
ws_ok = make_ws(prefix="ws-ok-")
(ws_ok / "ok.txt").write_text("ok\n")
env_ok = provider.create_environment(cwd=str(ws_ok), timeout=15, task_id="ok-test")
assert env_ok.execute("echo ok")["exit_code"] == 0
bump(9)

# --- 10) file-tools gated: uses_host_filesystem == False ---
assert mod["PreflightEnvironment"].uses_host_filesystem is False, "file-tools deben operar dentro de la copia"
ws_ft = make_ws(prefix="ws-ft-")
env_ft = provider.create_environment(cwd=str(ws_ft), timeout=15, task_id="ft-test")
r_w = env_ft.execute("echo 'nuevo contenido' > nuevo.txt")
assert r_w["exit_code"] == 0, f"write en la copia falló: {r_w!r}"
assert not (ws_ft / "nuevo.txt").exists(), "write_file llegó al workspace REAL (bypass del gate)"
assert (env_ft.sandbox_path / "nuevo.txt").exists(), "el write no quedó en la copia"
ft_pending = (env_ft.sandbox_path / "PENDING.diff").read_text()
assert "nuevo.txt" in ft_pending, "el diff no refleja el write de file-tools"
bump(10)

# --- 11) rechazo de clonar HOME / Hermes home / path que contiene el sandbox root ---
def expect_forbidden(cwd: Path, label: str):
    try:
        provider.create_environment(cwd=str(cwd), timeout=15, task_id="forbidden")
    except ValueError as e:
        msg = str(e)
        assert "cd into a project" in msg, f"mensaje [{label}] no pide cd into a project: {msg}"
        print(f"  ({label}) {msg.split('.')[0]}.")
        return
    raise AssertionError(f"clonar {label} ({cwd}) NO fue rechazado")

expect_forbidden(Path.home(), "HOME")
expect_forbidden(Path(os.environ["HERMES_HOME"]), "Hermes home")
expect_forbidden(Path(os.environ["HERMES_HOME"]) / "sandbox", "sandbox root")
expect_forbidden(Path(os.environ["HERMES_HOME"]) / "sandbox" / "some-id", "dentro del sandbox root")
bump(11)

# --- 13) escape relativo con `..` EMBEBIDO ---
ws_e = make_ws(prefix="ws-emb-")
(ws_e / "a").mkdir()
env_e = provider.create_environment(cwd=str(ws_e), timeout=15, task_id="embed-test")

# write: `a/../../x.txt` no empieza con "." pero resuelve FUERA -> bloqueado
r1 = env_e.execute("echo PWN > a/../../pwned.txt")
assert r1["exit_code"] == 1, f"write a/../../x.txt no bloqueado: {r1!r}"
assert "relative" in r1["output"].lower(), f"mensaje no relativo: {r1['output']}"
assert not (env_e.sandbox_path.parent / "pwned.txt").exists(), "a/../../x.txt escribió FUERA de la copia"

# read: `cat a/../../../etc/passwd` -> bloqueado y sin contenido del host
r2 = env_e.execute("cat a/../../../etc/passwd")
assert r2["exit_code"] == 1, f"read a/../../../etc/passwd no bloqueado: {r2!r}"
assert "root:" not in r2["output"], "el comando leyó /etc/passwd del host"
assert "etc/passwd" in r2["output"] or "escapes" in r2["output"].lower(), f"mensaje raro: {r2['output']}"

# path normal dentro de la copia sigue funcionando
r3 = env_e.execute("echo hello > a/inside.txt")
assert r3["exit_code"] == 0, f"write normal dentro de la copia falló: {r3!r}"
assert (env_e.sandbox_path / "a" / "inside.txt").exists(), "el write normal no quedó en la copia"
assert not (ws_e / "a" / "inside.txt").exists(), "el write normal llegó al real"
bump(13)

# --- 14) el claim "cannot self-approve" ya NO existe en el código/docs (no tests) ---
forbidden_phrases = ("cannot self-approve", "can't self-approve", "cannot approve its own", "can not approve")
found = []
for p in PLUGIN_DIR.rglob("*"):
    if p.is_dir() or ".git" in p.parts or p.suffix in (".pyc",):
        continue
    if "tests" in p.parts or p.name == "_test_sandbox.py":
        continue  # el test debe poder NOMBRAR las frases para buscar su ausencia
    try:
        content = p.read_text(errors="replace")
    except OSError:
        continue
    low = content.lower()
    for phrase in forbidden_phrases:
        if phrase in low:
            found.append(f"{p.relative_to(PLUGIN_DIR)}: {phrase}")
assert not found, f"claims absolutos de self-approve todavía presentes: {found}"
bump(14)

# --- 15) fingerprint con sha256: cambio real con mtime+size preservados -> apply NEGADO ---
ws_fp = make_ws({"doc.txt": "AAAA"}, prefix="ws-fp-")
env_fp = provider.create_environment(cwd=str(ws_fp), timeout=15, task_id="fp-mut")
res = env_fp.execute("echo change > new.txt")
assert res["exit_code"] == 0, f"prep copy failed: {res!r}"

# mutar el archivo REAL preservando mtime+size (el fingerprint viejo solo
# mtime+size NO lo detectaría; con sha256 SÍ)
target = ws_fp / "doc.txt"
orig_stat = target.stat()
assert target.read_text() == "AAAA"
target.write_text("BBBB")  # mismo tamaño (4 bytes), contenido distinto
os.utime(target, ns=(orig_stat.st_atime_ns, orig_stat.st_mtime_ns))
code, out = run_sbctl_tty("apply", "fp-mut", answer="s\n")
assert code != 0, f"apply con cambio real mtime+size preservados NO fue rechazado: {out}"
assert "CHANGED" in out.upper() or "changed" in out.lower(), f"mensaje de rechazo no claro: {out}"
assert (ws_fp / "doc.txt").read_text() == "BBBB", "apply clobbered?? (doc.txt no debería volver)"
bump("15a")

# control: archivo sin cambios -> apply OK
ws_fp2 = make_ws(prefix="ws-fp2-")
env_fp2 = provider.create_environment(cwd=str(ws_fp2), timeout=15, task_id="fp-ok")
res = env_fp2.execute("echo new > new.txt")
assert res["exit_code"] == 0, f"prep fp-ok failed: {res!r}"
code, out = run_sbctl_tty("apply", "fp-ok", answer="s\n")
assert code == 0, f"apply sin cambios en el real NO debería fallar: code={code} out={out}"
assert (ws_fp2 / "new.txt").exists(), "apply fp-ok no aplicó new.txt"
bump("15b")

# --- 16) symlink que escapa en la copia -> apply bloqueado; symlink interno -> apply OK ---
ws_out = make_ws(prefix="ws-asym-")
outside2 = Path(tempfile.mkdtemp(prefix="outside2-"))
env_asym = provider.create_environment(cwd=str(ws_out), timeout=15, task_id="apply-sym-out")
res = env_asym.execute(
    f"python3 -c \"import os; os.symlink('{outside2}', 'outlink')\""
)
assert res["exit_code"] == 0, f"no se pudo crear symlink en la copia: {res!r}"
code, out = run_sbctl_tty("apply", "apply-sym-out", answer="s\n")
assert code != 0, f"apply con symlink escapando NO fue bloqueado: {out}"
assert "symlink" in out.lower(), f"mensaje de bloqueo sin 'symlink': {out}"
assert not (ws_out / "outlink").exists(), "el symlink escapando se copió al real"

ws_in = make_ws({"a.txt": "x\n"}, prefix="ws-isym-")
env_isym = provider.create_environment(cwd=str(ws_in), timeout=15, task_id="apply-sym-in")
res = env_isym.execute("ln -s a.txt inlink")
assert res["exit_code"] == 0, f"no se pudo crear symlink interno: {res!r}"
code, out = run_sbctl_tty("apply", "apply-sym-in", answer="s\n")
assert code == 0, f"apply con symlink interno NO debería fallar: code={code} out={out}"
assert (ws_in / "inlink").is_symlink(), "el symlink interno no se aplicó"
bump(16)

# --- 17) discard: PREFLIGHT_ROOT de otro perfil rechazado; sin TTY rechazado; con TTY OK ---
ws_dc = make_ws(prefix="ws-dc-")
env_dc = provider.create_environment(cwd=str(ws_dc), timeout=15, task_id="dc-root")
other_root = "/tmp/other-profile-sandbox"  # NO es el root de ESTE perfil
r_cross = run_sbctl("discard", "dc-root", env={**os.environ, "PREFLIGHT_ROOT": other_root})
assert r_cross.returncode != 0, "discard con PREFLIGHT_ROOT de otro perfil NO fue rechazado"
assert "refusing" in (r_cross.stdout + r_cross.stderr).lower(), f"mensaje cross-root: {r_cross.stdout} {r_cross.stderr}"
assert (SB_ROOT / "dc-root").exists(), "el discard cross-root borró la sesión local"
assert not Path(other_root).exists(), "se creó/borró algo en el root ajeno"
bump("17a")

r_dntty = run_sbctl("discard", "dc-root")
assert r_dntty.returncode != 0, "discard sin TTY no rechazado (17b)"
assert "interactive" in (r_dntty.stdout + r_dntty.stderr).lower(), f"mensaje 17b: {r_dntty.stdout} {r_dntty.stderr}"
assert (SB_ROOT / "dc-root").exists(), "discard sin TTY borró la sesión"
bump("17b")

code, out = run_sbctl_tty("discard", "dc-root", answer="s\n")
assert code == 0, f"discard normal con TTY falló: code={code} out={out}"
assert "discarded" in out.lower(), f"mensaje discard OK: {out}"
assert not (SB_ROOT / "dc-root").exists(), "discard TTY no borró la sesión"
bump("17c")

# --- 18) PENDING.diff redacta secretos ---
ws_sec = make_ws({
    ".env": (
        "TOKEN=supersecret-abc\n"
        "MY_SECRET_KEY=shhh-123\n"
        "DATABASE_URL=postgres://u:pass@db/x\n"
        "NORMAL=value\n"
    ),
}, prefix="ws-sec-")
env_sec = provider.create_environment(cwd=str(ws_sec), timeout=15, task_id="redact-test")
res = env_sec.execute("sed -i '1s/.*/TOKEN=changed-xyz/' .env")
assert res["exit_code"] == 0, f"sed falló: {res!r}"
diff_text = (env_sec.sandbox_path / "PENDING.diff").read_text()
assert "supersecret-abc" not in diff_text, "PENDING.diff muestra TOKEN= en claro"
assert "shhh-123" not in diff_text, "PENDING.diff muestra MY_SECRET_KEY= en claro"
assert "postgres://u" not in diff_text, "PENDING.diff muestra DATABASE_URL con credenciales"
assert "<redacted>" in diff_text, "PENDING.diff no marcó las líneas sensibles"
assert "NORMAL=value" in diff_text, "PENDING.diff sobre-redactó una línea inocua"

# sesión B (otro proceso) no puede leer el secreto por sandboxctl diff
rd = run_sbctl("diff", "redact-test")
assert rd.returncode == 0, f"sandboxctl diff falló: {rd.stderr}"
assert "supersecret-abc" not in rd.stdout, "sandboxctl diff filtró TOKEN= en claro"
assert "shhh-123" not in rd.stdout, "sandboxctl diff filtró MY_SECRET_KEY= en claro"

# unitario: la función de redacción cubre PGPASSWORD y valores sueltos
red = mod["_redact_diff_body"]
red_ok = red("-PGPASSWORD=postgres_password\n+export RCLONE_CONFIG_PASS=rcpass\n plain=ok")
assert "postgres_password" not in red_ok and "rcpass" not in red_ok, f"redacción falló: {red_ok!r}"
assert "plain=ok" in red_ok, f"redacción sobre-actúa: {red_ok!r}"
assert "<redacted>" in red_ok, f"sin marca de redacción: {red_ok!r}"
bump(18)

# --- 19) env filter ampliado ---
secret_env = {
    "MY_SECRET_KEY": "sek1",
    "PGPASSWORD": "pg1",
    "RCLONE_CONFIG_PASS": "rc1",
    "STRIPE_SECRET_KEY": "st1",
    "DATABASE_URL": "db1",
}
os.environ.update(secret_env)
ws_env = make_ws(prefix="ws-env-")
env_env = provider.create_environment(cwd=str(ws_env), timeout=15, task_id="env-test")
probe = (
    "python3 -c "
    "\"import json,os; print(json.dumps({k: os.environ.get(k) for k in "
    "['MY_SECRET_KEY','PGPASSWORD','RCLONE_CONFIG_PASS','STRIPE_SECRET_KEY',"
    "'DATABASE_URL','PATH','HOME'] if k in os.environ}))\""
)
res = env_env.execute(probe)
assert res["exit_code"] == 0, f"probe env falló: {res!r}"
seen = json.loads(res["output"].strip())
for name in secret_env:
    assert name not in seen, f"env secreto llegó al hijo: {name}={seen.get(name)}"
assert "PATH" in seen, "PATH (inocua) no llegó al hijo"
assert seen.get("HOME") == str(env_env.sandbox_path), f"HOME no apunta a la copia: {seen.get('HOME')}"
bump(19)

# --- 20) clonar ~/.ssh, ~/.aws, ~/.gnupg, /etc, /var rechazado; subdir normal bajo ~ OK ---
expect_forbidden(Path.home() / ".ssh", ".ssh")
expect_forbidden(Path.home() / ".aws", ".aws")
expect_forbidden(Path.home() / ".gnupg", ".gnupg")
expect_forbidden(Path("/etc"), "/etc")
expect_forbidden(Path("/var"), "/var")
home_sub = Path(tempfile.mkdtemp(prefix=".preflight-ok-", dir=Path.home()))
try:
    sub_env = provider.create_environment(cwd=str(home_sub), timeout=15, task_id="home-sub-ok")
    assert sub_env.execute("echo ok")["exit_code"] == 0
finally:
    shutil.rmtree(home_sub, ignore_errors=True)
bump(20)

# --- 21) clone usa el original RESUELTO (symlink/.. no cuelan el TOCTOU) ---
ws_real = make_ws(prefix="ws-real-")
link_dir = Path(tempfile.mkdtemp(prefix="ws-link-"))
link_path = link_dir / "alias"
link_path.symlink_to(ws_real, target_is_directory=True)
env_alias = provider.create_environment(cwd=str(link_path), timeout=15, task_id="alias-test")
registered = (env_alias.sandbox_path.parent / "original").read_text().strip()
assert registered == str(ws_real.resolve()), f"registro original no es el path RESUELTO: {registered} != {ws_real.resolve()}"
shutil.rmtree(link_dir, ignore_errors=True)
bump(21)

# --- 22) sandboxctl --help documenta multi-perfil (HERMES_HOME) ---
rh = run_sbctl("--help")
assert rh.returncode == 0, f"--help falló: {rh.stderr}"
assert "HERMES_HOME" in rh.stdout, "sandboxctl --help no documenta HERMES_HOME multi-perfil"
assert "best-effort" in rh.stdout.lower() or "BEST-EFFORT" in rh.stdout, "sandboxctl --help no aclara best-effort"
bump(22)

# --- 23) apply muestra "N más líneas" + cómo ver el diff completo ---
ws_big = make_ws({"big.txt": "\n".join(f"line {i}" for i in range(80)) + "\n"}, prefix="ws-big-")
env_big = provider.create_environment(cwd=str(ws_big), timeout=15, task_id="big-diff")
res = env_big.execute("sed -i 's/^line/Line/' big.txt")
assert res["exit_code"] == 0, f"sed big falló: {res!r}"
code, out = run_sbctl_tty("apply", "big-diff", answer="n\n")  # cancel: ver el mensaje sin aplicar
assert code != 0, "apply cancelado debería salir != 0"
assert "more lines" in out and "sandboxctl diff" in out, f"apply no avisó líneas omitidas: {out[-400:]}"
bump(23)

# --- 24) README aclara apply whole-workspace (rsync -a) ---
readme = (PLUGIN_DIR / "README.md").read_text()
assert "whole-workspace" in readme or "whole pending diff" in readme, "README no menciona whole-workspace"
assert "rsync -a" in readme, "README no menciona rsync -a"
assert "self-approve" in readme, "README debería declarar el límite de self-approve"
assert "cannot self-approve" not in readme.lower(), "README vuelve a sobre-prometer"
bump(24)

# --- cleanup de temporales grandes (opcional, no destructivo) ---
for d in (ws, ws_sym, ws_ok, ws_ft, ws_e, ws_fp, ws_fp2, ws_out, ws_in, ws_sec, ws_env, ws_big):
    shutil.rmtree(d, ignore_errors=True)

print(f"\nTODO PASS ✔ ({pass_count} PASS)")
