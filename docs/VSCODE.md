# Desarrollo de KRONOS en VS Code

## Abrir el entorno

1. Inicia Docker Desktop.
2. En VS Code, abre la carpeta del proyecto.
3. Instala la extensión **Dev Containers** de Microsoft si falta.
4. Pulsa `Ctrl+Shift+P` y selecciona **Dev Containers: Reopen in Container**.
5. Comprueba que abajo a la izquierda aparece **Dev Container: KRONOS V2…**.

La construcción instala .NET, Python y Volatility en el contenedor. La carpeta de código está compartida con el anfitrión; los cambios en ella se conservan.

## Compilar y probar

- `Ctrl+Shift+B`: **KRONOS: Compilar en Dev Container**.
- `Ctrl+Shift+P` → **Tareas: Ejecutar tarea** → **KRONOS: Probar en Dev Container**.
- Terminal del contenedor: `sh scripts/test.sh`.

Las pruebas usan datos sintéticos, incluyendo la tabla RAM y el rechazo de una imagen inválida por el motor real. No analizan volcados del usuario ni ejecutan adquisiciones del anfitrión.

Si Docker no permite conectar con su motor, el entorno todavía no se ha abierto: conserva el mensaje de Dev Containers para diagnosticarlo.

## Usar la aplicación

Abre `KRONOS.lnk` o `artifacts/win-x64/Kronos.Desktop.exe` desde Windows. No es necesario abrir el editor para usarla. Mantén juntos todos los archivos de la publicación. El flujo de publicación Windows en GitHub Actions prepara un artefacto descargable con el motor incluido.

## Sincronizar la carpeta inicial, una sola vez

Si esta carpeta sigue mostrando todos los archivos como nuevos porque el conector subió los commits sin actualizar el Git local, ejecuta en el Dev Container la tarea **KRONOS: Sincronizar historial inicial con GitHub**.

El script `scripts/sync_git.py` verifica cada archivo frente a `origin/main`. Solo si coinciden y no hay commits locales, establece el historial con `git reset --mixed origin/main`, conservando los archivos. No descarta diferencias, no elimina archivos ni fuerza una subida. La sesión del agente tiene el Git local en solo lectura; esta operación debe ejecutarse desde tu entorno con acceso de escritura.
