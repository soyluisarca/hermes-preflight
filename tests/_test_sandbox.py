#!/usr/bin/env python3
"""Test funcional de preflight (MVP).

Verifica:
  1. crear workspace temporal con 2 archivos en un subdir,
  2. correr 'rm -rf subdir' a través del Environment del plugin,
  3. que el workspace REAL no cambió,
  4. que PENDING.diff lista los borrados,
  5. que apply solo cambia lo del diff (sandboxctl) y discard no toca nada.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path("/home/lac71/.hermes/hermes-agent")
PLUGIN_DIR = Path("/home/lac71/.hermes/plugins/preflight")
sys.path.insert(0, str(REPO))

# Sandbox temporal aislado (no tocamos ~/.hermes/sandbox del usuario).
os.environ["SANDBOX_FIRST_ROOT"] = tempfile.mkdtemp(prefix="sbx-test-")
os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="sbx-home-")

mod = {}
plugin_path = PLUGIN_DIR / "__init__.py"
exec(compile(plugin_path.read_text(), str(plugin_path), "exec"), mod)

Provider = mod["SandboxFirstProvider"]
provider = Provider()
assert provider.is_available(), "bash no está disponible"

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

# --- 6) sandboxctl apply: aplica solo lo del diff ---
orig_file = env.sandbox_path.parent / "original"
assert orig_file.exists() and orig_file.read_text().strip() == str(ws), "no se registró el original"
print("PASS 4: el provider registró el workspace original para sandboxctl")

sbctl = PLUGIN_DIR / "bin" / "sandboxctl"
# status
st = subprocess.run(["bash", str(sbctl), "status"], capture_output=True, text=True, env={**os.environ})
assert "demo-test" in st.stdout, f"status no lista la sesión: {st.stdout}"
print("PASS 5: sandboxctl status lista la sesión")

# apply (auto-responder 's' — apply NO es automático, lo confirmamos aquí sí)
apply_run = subprocess.run(
    ["bash", str(sbctl), "apply", "demo-test"],
    input="s\n", capture_output=True, text=True, env={**os.environ},
)
assert "Aplicado" in apply_run.stdout, f"apply falló: {apply_run.stdout} {apply_run.stderr}"
assert not (ws / "subdir" / "a.txt").exists(), "apply no aplicó el borrado a.txt"
assert (ws / "root.txt").exists(), "apply borró root.txt sin que estuviera en el diff"
print("PASS 6: apply aplicó exactamente lo del diff (borró a.txt/b.txt, conservó root.txt)")

# --- 7) discard no toca nada ---
# recreamos un borrado en una sesión nueva para probar discard limpio
env2 = provider.create_environment(cwd=str(ws), timeout=15, task_id="discard-test")
env2.execute("rm -f root.txt")
(sb_root := Path(os.environ["SANDBOX_FIRST_ROOT"]))
subprocess.run(["bash", str(sbctl), "discard", "discard-test"], capture_output=True, text=True, env={**os.environ})
assert (ws / "root.txt").exists(), "discard tocó el workspace real"
assert not (sb_root / "discard-test").exists(), "discard no borró la sesión"
print("PASS 7: discard no tocó el workspace real y limpió la sesión")

# --- 8) guardas: sudo bloqueado; ruta absoluta fuera bloqueada ---
r_sudo = env.execute("sudo rm -rf /")
assert r_sudo["exit_code"] == 1 and ("privilegios elevados" in r_sudo["output"].lower() or "bloqueado" in r_sudo["output"].lower())
print("PASS 8: sudo bloqueado")

# --- 9) symlink que escapa de la copia -> operación bloqueada ---
ws_sym = Path(tempfile.mkdtemp(prefix="ws-sym-"))
outside = Path(tempfile.mkdtemp(prefix="outside-"))
(outside / "secreto.txt").write_text("secreto host\n")
(ws_sym / "link").symlink_to(outside, target_is_directory=True)  # apunta FUERA del ws
env_sym = provider.create_environment(cwd=str(ws_sym), timeout=15, task_id="symlink-test")
r_sym = env_sym.execute("cat link/secreto.txt")
assert r_sym["exit_code"] == 1, f"un comando cruzó por symlink: {r_sym!r}"
assert "symlink" in r_sym["output"].lower(), f"el guard no menciona symlink: {r_sym['output']}"
# el host real queda intacto (nada se leyó/alteró a través del symlink)
assert (outside / "secreto.txt").read_text() == "secreto host\n", "el symlink tocó el host"
# y una copia sin symlink que escape se comporta normal
ws_ok = Path(tempfile.mkdtemp(prefix="ws-ok-"))
(ws_ok / "ok.txt").write_text("ok\n")
env_ok = provider.create_environment(cwd=str(ws_ok), timeout=15, task_id="ok-test")
assert env_ok.execute("echo ok")["exit_code"] == 0
print("PASS 9: symlink fuera de la copia bloqueado; el host intacto; copia normal OK")

print("\nTODO PASS ✔")
