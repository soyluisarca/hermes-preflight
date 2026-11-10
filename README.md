# sandbox-first

**Dry-run gate con aprobación**, no un sandbox de aislamiento. Terminal backend para
Hermes que corre **cada comando en una copia desechable** del workspace, enseña qué
cambiaría (**diff exacto**), y **solo aplica** los cambios al workspace real si *tú*
lo apruebas explícitamente. Un dry-run universal: un `rm -rf`, una migración o un
script nunca tocan tus datos por accidente.

> Diseño en una línea: **el agente VE el workspace real, EJECUTA en la copia, y
> APLICA con tu aprobación.**

## El problema que resuelve

Hoy un agente ejecuta comandos reales y ya: un `rm -rf` mal apuntado es datos que se
van para siempre. No existe un "revísame antes" universal. Con **sandbox-first**, el
agente trabaja sobre una copia; si el comando sale mal, descartas la copia y el
workspace real queda intacto.

## Instalación

```bash
hermes plugins enable sandbox-first
hermes config set terminal.backend sandbox-first
```

(Asume backend en proceso — `plugins.isolation: in_process`, el default. Cambios de
config los hace el dueño del config, no este plugin.)

## Demo guionada (90s)

1. Activa el plugin y desactívalo a mano (0:00–0:10):
   ```
   hermes plugins enable sandbox-first
   hermes config set terminal.backend sandbox-first
   ```
2. En el workspace real, revisa el estado (0:10–0:15):
   ```
   sandboxctl status
   ```
3. Pide al agente `rm -rf subdir` (0:15–0:30). El agente lo corre **en la copia**.
4. Verifica que el workspace real NO cambió (0:30–0:40):
   ```
   ls subdir            # sigue ahí en el real
   sandboxctl status    # la sesión reporta cambios pendientes
   ```
5. Mira el diff (0:40–0:55):
   ```
   sandboxctl diff demo-test
   ```
   Ahí ves exactamente los archivos que se borrarían.
6. Decide (0:55–1:30): `sandboxctl apply demo-test` para aplicar (escribe `s`),
   o `sandboxctl discard demo-test` para tirar la copia sin tocar nada.

## Cómo funciona

- `create_environment()` crea `~/.hermes/sandbox/<id>/workspace` y clona el workspace
  con **reflink** (`cp --reflink=always`, copia de escritura-perezosa: costo cero de
  bytes en btrfs/xfs, copia completa como fallback). Descarta el contenido previo del
  mismo id para no arrastrar estado.
  > Nota de diseño: la idea pedía hardlinks (`cp -al`). No los usé como método
  > primario porque comparten inode: un `echo x > archivo` en el sandbox tocaría el
  > original *sin* pasar por `apply`. Reflink da el mismo "no copio bytes" y aísla de
  > verdad.
- `execute()` corre el comando en la copia, con env filtrado (secretos vía
  `strip_env_keys`), aplica guardas y devuelve `{output, exit_code}`.
- Tras cada comando, calcula el diff original ↔ copia (`git diff --no-index` si hay
  `.git`, `diff -ruN` si no) y lo acumula en `PENDING.diff` de la sesión.
- **Nada se aplica solo.** `apply`/`discard` son acciones explícitas, vía el script
  `bin/sandboxctl` (requiere confirmación por teclado).

## Diferencias vs. otras herramientas

|                        | sandbox-first                | bubblewrap                | runbox / Docker         |
|------------------------|------------------------------|---------------------------|-------------------------|
| Qué aísla              | La *copia* del workspace     | El proceso completo       | El proceso completo     |
| Contenedor / kernel    | No — proceso del host        | Sí (namespaces/bind)      | Sí (Docker)             |
| ¿Enseña qué cambiará?  | Sí, `diff` exacto antes de `apply` | No — aísla, no enseña       | No — export sin diff       |
| Antes de escribir      | Diff + aprobación explícita  | Sin gate de revisión      | Sin gate de revisión    |
| Re-flujo a lo real     | `apply`/`discard` explícitos | Ninguno (muere con el ctr)| `export` / copiar       |

bubblewrap **aísla pero no enseña**: corre en un contenedor y lo que pasa adentro
muere con él, sin mostrarte un diff ni darte una decisión previa. runbox exporta
imagenes de Docker pero sin un diff exacto que puedas revisar antes de aplicar.
sandbox-first es un **gate de decisión**: ves exactamente qué cambiará y decides
antes de que toque el workspace real.

## Guardas de seguridad

- Rechaza `sudo` / `doas`.
- Rechaza rutas absolutas que apunten **fuera** de la copia.
- Rechaza redirecciones de escritura (`>`, `2>`) a rutas fuera de la copia.
- Rechaza la operación si la copia contiene **symlinks que escapen** del sandbox
  (preservados por el clon; un symlink a `/etc` o `~/.ssh` saltaría la copia).
- **Entorno filtrado**: se eliminan del subproceso los secretos exactos
  (`OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) y una deny-list de
  prefijos sensibles (`SSH_AUTH_SOCK`, `AWS_*`, `GCP_*`/`GCLOUD_*`, `DOCKER_*`,
  `AZURE_*`, `NPM_TOKEN`, `GH_TOKEN`/`GITHUB_TOKEN`,
  `GOOGLE_APPLICATION_CREDENTIALS`).
- Sin red: el sandbox no hace streaming ni telemetría.
- `skip_container_guards = False`: el modelo sigue pasando por los guards de
  aprobación de Hermes.

## Limitaciones honestas

- **No es un sandbox real de kernel.** El shell corre en el host (el `cwd` es una
  copia). Los guards de rutas absolutas son una red de seguridad por patrones, no un
  contenedor: alguien con `sudo` (bloqueado) o un shell anidado más listo podría
  evadirlos. Para aislamiento contundente, Docker/Modal siguen siendo la opción.
- Reflink cae a copia completa en filesystems sin CoW (p. ej. EXT4): más lento en
  workspaces grandes, pero igual de seguro.
- `task_id` distinto implica copia distinta: los cambios no se comparten entre
  sesiones.
- En un repo git hay que map/revisar el `PENDING.diff` a ojo (el header lo orienta);
  el diff crudo incluye los nombres de ruta absolutos.
- El diff usa `git diff --no-index`; para `.git`, `PENDING.diff` se excluye solo en el
  modo `diff -ruN`.

## Archivos

```
~/.hermes/plugins/sandbox-first/
├── plugin.yaml          # id/versión/kind: backend
├── __init__.py          # Provider + Environment + register(ctx)
├── bin/sandboxctl       # status | diff | apply | discard
├── _test_sandbox.py     # test funcional (corre: python3 _test_sandbox.py)
└── README.md            # este archivo
```

## Verificación rápida

```bash
python3 ~/.hermes/plugins/sandbox-first/_test_sandbox.py
```

Debe terminar con `TODO PASS ✔`.
