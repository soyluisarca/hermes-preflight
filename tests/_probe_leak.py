#!/usr/bin/env python3
"""Probe de fuga: verifica que FAL_KEY / NOUS_API_KEY (y credenciales varias)
no lleguen al proceso hijo a traves del execute() de preflight."""
import os
import sys
import tempfile
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent
REPO = Path(os.environ.get("HERMES_AGENT_REPO", str(Path.home() / ".hermes" / "hermes-agent")))
sys.path.insert(0, str(REPO))

os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="sbx-leak-home-")
# Backend derives the sandbox root from get_hermes_home() + /sandbox; PREFLIGHT_ROOT
# is no longer read (config key replaces env overrides), so only HERMES_HOME isolates.
os.environ.pop("PREFLIGHT_ROOT", None)
os.environ.pop("SANDBOX_FIRST_ROOT", None)

# Simular credenciales en el entorno real.
os.environ["FAL_KEY"] = "leak"
os.environ["FAL_API_KEY"] = "leak"
os.environ["NOUS_API_KEY"] = "leak"

mod = {}
exec(compile((PLUGIN_DIR / "__init__.py").read_text(), "lt", "exec"), mod)
Provider = mod["PreflightProvider"]
provider = Provider()
assert provider.is_available(), "bash no disponible"

ws = Path(tempfile.mkdtemp(prefix="ws-leak-"))
env = provider.create_environment(cwd=str(ws), timeout=15, task_id="leak-probe")

checks = [
    # (nombre_interno, greps que deben dar 0)
    ("FAL_KEY", "FAL_KEY"),
    ("FAL_API_KEY", "FAL_API_KEY"),
    ("NOUS_API_KEY", "NOUS_API_KEY"),
]
bad = []
for label, needle in checks:
    r = env.execute(f"env | grep -c '{needle}'")
    count = (r.get("output") or "").strip().splitlines()[-1] if r.get("output") else "?"
    ok = r["exit_code"] in (0, 1) and count == "0"
    state = "OK (sin fuga)" if ok else f"FUGA! count={count}"
    print(f"{label:14s} -> env | grep -c {needle} : {state}")
    if not ok:
        bad.append(label)

# PRUEBA NEGATIVA: una variable normal SI debe pasar.
r = env.execute('test -n "$PATH" && echo PATH_PRESENT')
if "PATH_PRESENT" in r.get("output", ""):
    print("PATH              -> se conserva : OK (control)")
else:
    print("PATH              -> se conserva : FALLO!")
    bad.append("PATH")

print("\n" + ("TODO OK: sin fugas de credenciales" if not bad else f"PROBE FALLIDO: {bad}"))
sys.exit(1 if bad else 0)
