#!/usr/bin/env python3
"""Test funcional de preflight (backend + sandboxctl).

Cubre:
  1. el workspace REAL no cambia al ejecutar comandos en la copia,
  2. la copia refleja los cambios (borrados incluidos),
  3. PENDING.diff lista los borrados y los writes de file-tools (gated),
  4. el provider registra el workspace original para sandboxctl,
  5. sandboxctl status lista la sesión (root derivado del Hermes home),
  6. apply: rechazado no interactivo (sin --yes y con --yes), aplica solo vía
     terminal interactiva, y aplica EXACTAMENTE lo del diff (whole-workspace),
  7. discard no toca el workspace real,
  8. guardas: sudo bloqueado, ruta absoluta fuera bloqueada, ../ relativa bloqueada,
  9. symlink fuera de la copia bloqueado,
 10. file-tools gated (uses_host_filesystem == False),
 11. rechazo de clonar HOME / Hermes home / un path que contiene el sandbox root,
 12. SANDROOT derivado de get_hermes_home() + /sandbox.
"""
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
print(f"PASS 0: SANDROOT derivado de get_hermes_home() + /sandbox ({SB_ROOT})")

sbctl = PLUGIN_DIR / "bin" / "sandboxctl"


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

    The apply contract (punto 2) requires a REAL terminal for confirmation:
    --yes is honored only when stdin is a TTY, and a non-TTY apply is refused.
    This helper is the only way a test can legitimately confirm an apply.
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


# --- 1) workspace temporal con 2 archivos en subdir ---
ws = Path(tempfile.mkdtemp(prefix="ws-"))
(ws / "subdir").mkdir()
(ws / "subdir" / "a.txt").write_text("contenido A\n")
(ws / "subdir" / "b.txt").write_text("contenido B\n")
(ws / "root.txt").write_text("raiz\n")

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
print("PASS 1: workspace real NO cambió tras rm -rf subdir")

# --- copia si aislada (a.txt borrado ahí) ---
sandbox_copy = env.sandbox_path
assert not (sandbox_copy / "subdir" / "a.txt").exists(), "la copia del sandbox no reflejó el borrado"
assert (ws / "root.txt").exists(), "root.txt debería seguir en el real"
print("PASS 2: la copia del sandbox reflejó el borrado; el real intacto")

# --- 5) PENDING.diff lista los borrados ---
pending = env.sandbox_path / "PENDING.diff"
assert pending.exists(), "no hay PENDING.diff"
text = pending.read_text()
deleted = [l for l in text.splitlines() if l.startswith("-") and not l.startswith("---") and not l.startswith("--")]
assert deleted, f"PENDING.diff no lista los borrados:\n{text}"
assert any("contenido" in l for l in deleted), f"los borrados no muestran el contenido:\n{deleted}"
assert "subdir" in text, "el diff no menciona subdir"
print(f"PASS 3: PENDING.diff lista los borrados ({len(deleted)} línea(s) eliminadas)")

# --- 6) sandboxctl apply: aplica todo el diff, con confirmación humana ---
orig_file = env.sandbox_path.parent / "original"
assert orig_file.exists() and orig_file.read_text().strip() == str(ws), "no se registró el original"
print("PASS 4: el provider registró el workspace original para sandboxctl")

# status (el root que muestra sandboxctl debe coincidir con SB_ROOT)
st = run_sbctl("status")
assert "demo-test" in st.stdout, f"status no lista la sesión: {st.stdout} {st.stderr}"
assert SB_ROOT.as_posix() in st.stdout, f"status usa un root distinto al del backend: {st.stdout}"
print("PASS 5: sandboxctl status lista la sesión en el root derivado")

# apply NO interactivo es rechazado, con y sin --yes (punto 2)
r_no = run_sbctl("apply", "demo-test")
assert r_no.returncode != 0, "apply no interactivo sin --yes debería ser rechazado"
assert "interactive" in (r_no.stdout + r_no.stderr).lower(), f"mensaje de rechazo: {r_no.stdout} {r_no.stderr}"
r_yes = run_sbctl("apply", "demo-test", "--yes")
assert r_yes.returncode != 0, "apply --yes no interactivo debería ser rechazado (agente no puede auto-aprobarse)"
assert "--yes" in (r_yes.stdout + r_yes.stderr), f"mensaje de rechazo --yes: {r_yes.stdout} {r_yes.stderr}"
print("PASS 6a: apply no interactivo rechazado (sin --yes y con --yes)")

# apply interactivo: el humano confirma de verdad (pty). Aplica TODO el diff.
code, out = run_sbctl_tty("apply", "demo-test", answer="s\n")
assert code == 0, f"apply interactivo falló: code={code} out={out}"
assert not (ws / "subdir" / "a.txt").exists(), "apply no aplicó el borrado a.txt"
assert not (ws / "subdir" / "b.txt").exists(), "apply no aplicó el borrado b.txt"
assert (ws / "root.txt").exists(), "apply borró root.txt sin que estuviera en el diff"
print("PASS 6b: apply interactivo aplicó exactamente lo del diff (whole-workspace, borró a/b, conservó root.txt)")

# --- 7) discard no toca nada ---
env2 = provider.create_environment(cwd=str(ws), timeout=15, task_id="discard-test")
env2.execute("rm -f root.txt")
r_discard = run_sbctl("discard", "discard-test")  # discard never prompts; --yes is irrelevant here
assert (ws / "root.txt").exists(), "discard tocó el workspace real"
assert not (SB_ROOT / "discard-test").exists(), "discard no borró la sesión"
print("PASS 7: discard no tocó el workspace real y limpió la sesión")

# --- 8) guardas: sudo bloqueado; ruta absoluta fuera bloqueada; ../ relativa bloqueada ---
r_sudo = env.execute("sudo rm -rf /")
assert r_sudo["exit_code"] == 1 and "blocked" in r_sudo["output"].lower(), f"sudo no bloqueado: {r_sudo!r}"
print("PASS 8a: sudo bloqueado")

r_abs = env.execute("cat /etc/passwd")
assert r_abs["exit_code"] == 1 and "blocked" in r_abs["output"].lower(), f"ruta absoluta fuera no bloqueada: {r_abs!r}"
print("PASS 8b: ruta absoluta fuera de la copia bloqueada")

r_rel = env.execute("echo pwn > ../escape.txt")
assert r_rel["exit_code"] == 1 and "relative" in r_rel["output"].lower(), f"../ relativa no bloqueada: {r_rel!r}"
assert not (env.sandbox_path.parent / "escape.txt").exists(), "la ../ relativa logró escribir fuera de la copia"
print("PASS 8c: ruta relativa ../ fuera de la copia bloqueada")

# --- 9) symlink que escapa de la copia -> operación bloqueada ---
ws_sym = Path(tempfile.mkdtemp(prefix="ws-sym-"))
outside = Path(tempfile.mkdtemp(prefix="outside-"))
(outside / "secreto.txt").write_text("secreto host\n")
(ws_sym / "link").symlink_to(outside, target_is_directory=True)  # apunta FUERA del ws
env_sym = provider.create_environment(cwd=str(ws_sym), timeout=15, task_id="symlink-test")
r_sym = env_sym.execute("cat link/secreto.txt")
assert r_sym["exit_code"] == 1, f"un comando cruzó por symlink: {r_sym!r}"
assert "symlink" in r_sym["output"].lower(), f"el guard no menciona symlink: {r_sym['output']}"
assert (outside / "secreto.txt").read_text() == "secreto host\n", "el symlink tocó el host"
ws_ok = Path(tempfile.mkdtemp(prefix="ws-ok-"))
(ws_ok / "ok.txt").write_text("ok\n")
env_ok = provider.create_environment(cwd=str(ws_ok), timeout=15, task_id="ok-test")
assert env_ok.execute("echo ok")["exit_code"] == 0
print("PASS 9: symlink fuera de la copia bloqueado; el host intacto; copia normal OK")

# --- 10) file-tools gated (punto 1): uses_host_filesystem == False ---
assert mod["PreflightEnvironment"].uses_host_filesystem is False, "file-tools deben operar dentro de la copia"
ws_ft = Path(tempfile.mkdtemp(prefix="ws-ft-"))
env_ft = provider.create_environment(cwd=str(ws_ft), timeout=15, task_id="ft-test")
# simula un write_file: la herida cae en la COPIA, nunca en el real
r_w = env_ft.execute("echo 'nuevo contenido' > nuevo.txt")
assert r_w["exit_code"] == 0, f"write en la copia falló: {r_w!r}"
assert not (ws_ft / "nuevo.txt").exists(), "write_file llegó al workspace REAL (bypass del gate)"
assert (env_ft.sandbox_path / "nuevo.txt").exists(), "el write no quedó en la copia"
ft_pending = (env_ft.sandbox_path / "PENDING.diff").read_text()
assert "nuevo.txt" in ft_pending, "el diff no refleja el write de file-tools"
print("PASS 10: file-tools gated — writes pasan por la copia y caen en PENDING.diff")

# --- 11) rechazo de clonar HOME / Hermes home / path que contiene el sandbox root (punto 3) ---
def expect_forbidden(cwd: Path, label: str):
    try:
        provider.create_environment(cwd=str(cwd), timeout=15, task_id="forbidden")
    except ValueError as e:
        msg = str(e)
        assert "cd into a project" in msg, f"mensaje [{label}] no pide cd into a project: {msg}"
        print(f"PASS 11 ({label}): clonar {cwd} rechazado — {msg.split('.')[0]}.")
        return
    raise AssertionError(f"clonar {label} ({cwd}) NO fue rechazado")

expect_forbidden(Path.home(), "HOME")
expect_forbidden(Path(os.environ["HERMES_HOME"]), "Hermes home")
expect_forbidden(Path(os.environ["HERMES_HOME"]) / "sandbox", "sandbox root")
expect_forbidden(Path(os.environ["HERMES_HOME"]) / "sandbox" / "some-id", "dentro del sandbox root")

# --- 12) (punto 4 ya cubierto en PASS 0) cierre ---
print("\nTODO PASS ✔")
