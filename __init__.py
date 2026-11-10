"""preflight: terminal backend que corre comandos en una copia desechable del workspace.

Cada comando se ejecuta en una copia local (reflink / copia completa) del workspace.
El workspace real NO se toca. Tras cada comando se acumula un diff en PENDING.diff.
Aplicar (rsync copia -> real) y descartar son acciones EXPLÍCITAS que nunca ocurren solas.
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

# Directorio raíz de sandboxes (raíz de PKG, no se expone por red ni al usuario).
SANDROOT = Path(os.getenv("SANDBOX_FIRST_ROOT", str(Path.home() / ".hermes" / "sandbox")))

# Nombres exactos de variables de entorno que nunca deben llegar al subproceso (secretos).
_STRIP_ENV_KEYS = frozenset({
    "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "SSH_AUTH_SOCK", "NPM_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
})

# Prefijos de variables sensibles que también se filtran (deny-list por prefijo).
_STRIP_ENV_PREFIXES = frozenset({"AWS_", "GCP_", "GCLOUD_", "DOCKER_", "AZURE_"})

# Patrón para detectar intentos de sudo (espacios/`-` variables, siempre rechazar).
_SUDO_RE = re.compile(r"(^|\s)(sudo|doas)(\s|$)", re.MULTILINE)


class SandboxFirstEnvironment:
    """Cumple el contrato duck-typed de BaseEnvironment (execute/cleanup).

    Contrato HONESTO (no declaramos lo que no hacemos):
      - NO es un contenedor. El comando corre en una COPIA local (reflink/copia)
        del workspace, pero el proceso es del host.
      - uses_host_filesystem = True: los file-tools del agente leen el workspace
        REAL, no la copia. El agente VE el real, EJECUTA en la copia y APLICA
        con aprobación explícita.
      - is_local = True: corre en la máquina local, no remota.
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
        # cwd dentro de la copia: si la ruta arranca en el original, la reencuadramos.
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

    # --- guardas de seguridad ---
    @staticmethod
    def _reject_sudo(command: str) -> str | None:
        if _SUDO_RE.search(command):
            return "Bloqueado por preflight: sudo/doas no está permitido en el sandbox."
        return None

    @staticmethod
    def _block_host_absolute_paths(command: str, sandbox_path: Path) -> list[str]:
        """Detección simple de rutas absolutas que apuntan FUERA de la copia.

        No es un sandbox real (el shell corre en el host), así que esta guarda es una
        red de seguridad honesta, no un muro infranqueable.
        """
        problems = []
        for tok in shlex.split(command):
            if not tok.startswith("/"):
                continue
            tok = tok.rstrip("/")
            if not tok:
                continue
            # /tmp dentro de la copia y la propia copia se permiten; el resto se marca.
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
        """Rechaza *writes* explícitos (redirección o >) a rutas absolutas fuera de la copia."""
        # Patrón grosero: redirecciones con ruta absoluta no perteneciente a la copia.
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
                    f"Bloqueado por preflight: redirección de escritura a ruta fuera de la "
                    f"copia ({target}). Nada se escribe fuera del sandbox."
                )
        return None

    def _block_symlink_escape(self) -> str | None:
        """Rechaza la operación si la copia contiene symlinks que escapan del sandbox.

        `cp -a` / `shutil.copytree(symlinks=True)` preservan los symlinks. Un symlink
        que apunte fuera (p. ej. /etc, ~/.ssh, una ruta del host real) permitiría a un
        comando leer/escribir fuera del sandbox a través de la ruta, saltándose la
        copia. Mientras haya uno en la copia, bloqueamos la operación.
        """
        try:
            sp_real = os.path.realpath(self.sandbox_path)
        except Exception:
            sp_real = str(self.sandbox_path)
        prefix = sp_real.rstrip("/") + os.sep
        escaping = []
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
            more = f" y {len(escaping)-5} más" if len(escaping) > 5 else ""
            return (
                "Bloqueado por preflight: la copia contiene symlink(s) que escapan "
                f"del sandbox ({shown}{more}). Elimínalos en el workspace real o usa un "
                "workspace sin symlinks hacia fuera; así garantizamos que ningún comando "
                "salga del sandbox por un symlink."
            )
        return None

    def execute(self, command: str, timeout: int | None = None, **kwargs):
        # 1) Guardas de seguridad.
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
                    "Bloqueado por preflight: ruta(s) absoluta(s) fuera de la copia del "
                    f"sandbox: {', '.join(paths)}"
                ),
                "exit_code": 1,
                "returncode": 1,
            }

        effective_timeout = timeout or self.timeout or 120

        # 2) Entorno filtrado: secretos exactos + deny-list por prefijo fuera.
        env = {
            k: v for k, v in os.environ.items()
            if k not in _STRIP_ENV_KEYS
            and not any(k.startswith(p) for p in _STRIP_ENV_PREFIXES)
        }
        env.setdefault("HOME", str(Path.home()))

        # 3) Corre en la copia.
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
                "output": (exc.stdout or "") + (exc.stderr or "") + f"\n[Command timed out after {effective_timeout}s]",
                "exit_code": 124,
                "returncode": 124,
            }

        output = (proc.stdout or "") + (proc.stderr or "")
        result = {"output": output, "exit_code": proc.returncode, "returncode": proc.returncode}

        # 4) Diff acumulado tras cada comando.
        try:
            self._write_pending_diff()
        except Exception as e:  # el diff jamás rompe la ejecución
            result["output"] += f"\n[aviso: no se pudo escribir PENDING.diff: {e}]"
        return result

    # --- diff acumulado ---
    def _diff_command(self):
        if (self.original_path / ".git").is_dir():
            # git diff --no-index trata las dos rutas como árboles independientes.
            return (
                f"git diff --no-index --no-color "
                f"-- {shlex.quote(str(self.original_path))} {shlex.quote(str(self.sandbox_path))}"
            )
        # diff -ruN: excluye la ruta del propio archivo de diff (usado fuera de git).
        return (
            f"diff -ruN -x PENDING.diff "
            f"{shlex.quote(str(self.original_path))} {shlex.quote(str(self.sandbox_path))}"
        )

    def _write_pending_diff(self):
        cmd = self._diff_command()
        proc = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
        body = (proc.stdout or "") + (proc.stderr or "")
        # diff sale con rc != 0 cuando hay diferencias (normal). No lo tratamos como error.
        header = (
            f"# PENDING.diff — preflight ({self.sandbox_path.name})\n"
            f"# ORIGINAL : {self.original_path}\n"
            f"# SANDBOX  : {self.sandbox_path}\n"
            f"# Acumulado tras el último comando ejecutado.\n"
            f"# Nada se ha aplicado aún al workspace real.\n"
            f"# Para aplicar: sandboxctl apply {self.sandbox_path.name}\n"
            f"# Para descartar: sandboxctl discard {self.sandbox_path.name}\n\n"
        )
        self._pending.write_text(header + body, encoding="utf-8")

    def cleanup(self):
        """Deja el sandbox intacto (no borra). El descarte es explícito (discard)."""


class SandboxFirstProvider(TerminalEnvironmentProvider):
    name = "preflight"
    display_name = "Preflight"

    # NO es un contenedor: el comando corre en una COPIA local (reflink/copia) del
    # workspace real. El proceso es del host; no hay aislamiento de kernel ni de red.
    # is_container=False es lo honesto — declaramos un "dry-run gate", no un sandbox.
    # los file-tools del agente siguen leyendo el workspace REAL (uses_host_filesystem).
    is_remote = False
    is_container = False

    def __init__(self):
        # import tardío para que el plugin cargue aunque el paquete raíz no esté importado
        pass

    @property
    def description(self):
        return "Dry-run gate con aprobación: corre cada comando en una copia, muestra el diff exacto y solo aplica lo que apruebas."

    @property
    def strip_env_keys(self):
        return frozenset(_STRIP_ENV_KEYS)

    @property
    def skip_container_guards(self):
        # No saltamos los guards de aprobación: queremos que el modelo apruebe antes de
        # acciones de riesgo. (El backend ya nunca aplica solo.)
        return False

    @property
    def default_cwd(self):
        # No hay una home idéntica por sesión; usamos el cwd que Hermes ya resuelve.
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
        # task_id sanitizado (solo [a-z0-9_-]) para no colarse en rutas.
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", str(task_id)) or "default"
        sandbox_dir = SANDROOT / safe_id / "workspace"
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        # Registra el workspace original (para sandboxctl apply/discard).
        SANDROOT.joinpath(safe_id, "original").write_text(str(original), encoding="utf-8")

        # Clonar el workspace. Estrategia: reflink (CoW) si el filesystem lo soporta;
        # fallback a copia completa. NO usamos hardlinks directos porque comparten inode:
        # un `echo x > archivo` en el sandbox tocaría el original. Reflink copia cero bytes
        # y aísla de verdad (el mismo "no copio bytes" que pedía la idea, pero seguro).
        self._clone(original, sandbox_dir)

        return SandboxFirstEnvironment(
            cwd=cwd, timeout=timeout, sandbox_path=sandbox_dir, original_path=original
        )

    @staticmethod
    def _clone(src: Path, dst: Path):
        # Workspace limpio: descarta cualquier contenido previo del mismo task_id.
        if dst.exists():
            for old in dst.iterdir():
                if old.is_dir() and not old.is_symlink():
                    shutil.rmtree(old, ignore_errors=True)
                else:
                    try:
                        old.unlink()
                    except OSError:
                        pass
        # 1) reflink de verdad (falla si el fs no lo soporta -> bucle con --reflink=auto).
        try:
            subprocess.run(
                ["cp", "-a", "--reflink=always", f"{src}/.", f"{dst}/"],
                check=True,
                capture_output=True,
            )
            return
        except Exception:
            pass
        # 2) copia normal (aislada, más lenta pero segura).
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
    ctx.register_terminal_environment_provider(SandboxFirstProvider())
