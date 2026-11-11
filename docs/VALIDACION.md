# Estado y validación — 11 de noviembre de 2026

## Entregado

Solución C#/.NET 10.0.404 con Avalonia 11.3.22, núcleo independiente de la interfaz y pruebas. Publicación Windows x64 autocontenida en `artifacts/win-x64/`, ejecutable `Kronos.Desktop.exe`; acceso rápido `Iniciar-KRONOS.cmd`. Los archivos de ese directorio deben conservarse juntos. La publicación contiene runtime y bibliotecas nativas, avisos de licencias y manifiesto SHA-256 del paquete. El manifiesto documenta el paquete; no es una firma digital.

Crear/abrir casos V2, bloqueo de apertura concurrente, copia de archivos con hashes origen antes/después y copia, búsqueda del inventario, verificación de copias, registro de operaciones/errores, notas editables y exportación HTML/Markdown. Los reportes HTML escapan las entradas. Adaptadores para los módulos V1 de verificación Windows, correlación Python y adquisición Windows Triage sin RAM. No se ha ejecutado adquisición real.

## Comprobaciones realizadas

- Restauración NuGet en modo bloqueado y compilación Release: cero errores y cero advertencias. Archivos de bloqueo separados para desarrollo y publicación `win-x64`, para evitar que publicar invalide la restauración normal.
- Núcleo: 13 comprobaciones, incluyendo SHA-256 conocido de `abc`, origen intacto, copia íntegra, apertura concurrente rechazada, persistencia y reapertura, escape HTML, informe editable, copia alterada, archivo ausente, archivo no registrado, ruta fuera del caso, origen inexistente y cancelación sin registro parcial.
- Interfaz Avalonia headless: ventana y cuatro pestañas renderizadas, interacción con Verificar sin caso, mensaje de error y recuperación de botones; navegación por todas las pestañas. Esto no equivale a una prueba manual completa de selectores de archivos y diálogos del SO.
- Python: dos pruebas `unittest`. Base Chromium SQLite sintética, visita conocida, generación de observaciones/informe/cobertura, fuente sin cambios y detección de alteración; verificación SHA-256 de todas las copias V1 frente al manifiesto de procedencia.
- Ejecutable nativo Windows autocontenido: iniciado, ventana `KRONOS V2.0 — Laboratorio forense` identificada también mediante UI Automation, proceso respondiendo y cierre normal. No se efectuó captura del anfitrión.

## Docker y Dev Container

Se pudo consultar inicialmente Docker Desktop (`desktop-linux`, motor 29.9.3), listar contenedores vacíos y comprobar Compose v5.7.0. Ejecutar `docker run --rm alpine:3.16.3 ...` devolvió **permission denied** en `npipe:////./pipe/dockerDesktopLinuxEngine`; una consulta posterior también devolvió permiso denegado. Esto demuestra una restricción de acceso de esta sesión, no que el motor esté averiado o detenido.

Dev Container preparado con imagen SDK `10.0.404-noble` y digest fijado. Existencia y digest comprobados contra el registro Microsoft (HTTP 200); no se ha construido ni ejecutado el contenedor. El tag Debian inicialmente considerado no existía y se sustituyó por Ubuntu Noble antes de entregar. .NET y Avalonia tienen desactivada la telemetría de compilación en los scripts/Dev Container, evitando escrituras de Avalonia en el perfil del usuario.

La compilación y publicación Windows se completaron con SDK descargado en `.tools/dotnet`, dentro del proyecto, sin instalar un SDK global. La restauración en un PowerShell hijo sufrió una restricción de red; la ejecución directa pudo descargar los paquetes. El script de compilación también se ejecutó después correctamente con las dependencias disponibles.

## Pendiente y límites

- Construir el Dev Container y probar Linux/macOS en sus sistemas reales o VM; no se declara soporte verificado de esos entornos.
- Prueba manual completa de casos y selectores de archivos en Windows; adquisición V1 en una VM Windows autorizada. No se ha certificado acceso a hardware ni captura RAM.
- Analizadores avanzados de imágenes de disco/RAM, adquisición Linux/macOS, móviles y descifrado: pendientes, sin controles simulados.
- Python sigue siendo una dependencia externa del módulo de análisis V1. El núcleo V2 y sus informes funcionan sin Python. PowerShell V1 tiene sus límites originales.
- V1 y V2 mantienen formatos distintos: el resultado de captura es V1 y los análisis conservan su carpeta separada, referenciada en el historial V2. Las observaciones detalladas V1 se exploran en el informe interactivo existente.
- El historial JSON no está firmado ni sellado. Las copias del caso son archivos normales y deben custodiarse; Verificar detecta cambios respecto del inventario vigente. Importar un archivo abierto o cambiante puede fallar y no garantiza una instantánea de un sistema activo. No ejecutar archivos de evidencia ni atribuir autoría por coincidencias.

## Siguiente trabajo propuesto

Probar el flujo completo en VM Windows con actividad conocida, ejecutar la matriz Linux/macOS y construir el Dev Container cuando exista acceso a Docker. Después incorporar observaciones estructuradas al núcleo V2 y la visualización nativa de fuentes/cronología, con adaptadores de análisis que declaren cobertura y fallos.
