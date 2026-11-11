# KRONOS V2.0

**Proyecto de José Luis Cabañas (JLC / UlysesX12).**
Copyright © 2026 José Luis Cabañas. Todos los derechos reservados sobre las aportaciones propias.
Consulte [autoría y créditos](AUTHORS.md) y [condiciones de uso](LICENSE.md).
Dar crédito no concede por sí solo permiso de reutilización o distribución.

Primera versión funcional de escritorio en español, con C#/.NET 10 y Avalonia 11.3.22. Windows, macOS y Linux comparten núcleo e interfaz; la adquisición V1 sigue siendo exclusiva de Windows.

## Inicio en Windows

Si acabas de clonar desde GitHub, los binarios y el SDK local no se incluyen en el repositorio. Prepara primero la publicación siguiendo **Desarrollo reproducible**; necesitas el SDK indicado en `global.json` o un entorno de compilación compatible.

Abre `Iniciar-KRONOS.cmd` o `artifacts/win-x64/Kronos.Desktop.exe`. La publicación Windows incluye el runtime .NET y no requiere Docker, SDK ni Python para gestionar casos, importar/verificar archivos y generar informes. Los módulos V1 de análisis sí requieren Python 3 accesible (puede indicarse su ruta en la interfaz); la adquisición/verificación V1 usa Windows PowerShell.

1. Introduce un identificador y operador; pulsa **Crear caso** y selecciona la carpeta de destino. También puedes abrir un `case.kronos.json` existente.
2. En **Evidencias**, añade archivos existentes. Se copian a `evidence/` con identificadores propios, manteniendo en el inventario la ruta original. Se calcula SHA-256 del origen antes y después y de la copia; se rechazan diferencias. La importación no ejecuta ni interpreta esos archivos.
3. Usa el buscador para filtrar nombre/ruta/hash y **Verificar copias** para comparar el inventario con los archivos del caso. Los errores y resultados aparecen en **Resultados y actividad**.
4. En **Informe editable**, escribe notas y conclusiones, guarda y genera el borrador HTML y Markdown. El Markdown se puede editar con cualquier editor. Las notas también se guardan al cambiar de caso o cerrar.
5. En **Módulos y adquisición**, selecciona un caso V1 con su manifiesto para verificarlo o analizarlo. El análisis crea su propia carpeta y permite abrir el informe interactivo V1. La carpeta V1 se referencia en las operaciones; no se convierte automáticamente a un caso V2 ni se copia íntegramente.

Los casos se guardan como JSON legible, copias de evidencia, registro de operaciones y reportes. Se impide la apertura concurrente para escritura. Conserva y respalda la carpeta completa. El JSON y su historial son editables por quien tenga acceso: no son una firma, un sellado independiente ni garantía contra manipulación intencionada. Una interrupción entre copiar y registrar puede dejar un archivo no registrado, que la verificación debe detectar.

## Adquisición Windows

Disponible desde el módulo V1, con perfil Triage y RAM desactivada. Exige marcar autorización y elegir destino. Requiere abrir la aplicación como administrador; no eleva privilegios automáticamente. No se ejecuta durante las pruebas. No se incluye WinPmem. El resultado es un caso V1 separado, que después se puede verificar/analizar desde la misma interfaz. No seleccionar como destino una carpeta de evidencia sellada.

## Desarrollo reproducible

SDK fijado en `global.json`; paquetes NuGet fijados y archivos `packages.lock.json` incluidos. Abrir esta carpeta en VS Code y ejecutar **Dev Containers: Reopen in Container**. El contenedor instala .NET, Python y bibliotecas Linux para Avalonia. La ejecución gráfica dentro del contenedor requiere un servidor gráfico configurado por el desarrollador; la compilación y las pruebas headless no lo requieren.

```powershell
powershell -NoProfile -File scripts/build.ps1
powershell -NoProfile -File scripts/build.ps1 -Publish -Runtime win-x64
```

El script utiliza el SDK local `.tools/dotnet` si existe; en otro equipo requiere el SDK .NET 10.0.404. La preparación local de esta sesión no modifica el SDK del sistema. En Dev Container/Linux: `sh scripts/test.sh`. Para publicar desde Linux:

```sh
dotnet publish src/Kronos.Desktop -c Release -r linux-x64 --self-contained true -o artifacts/linux-x64 -p:NuGetLockFilePath=packages.linux-x64.lock.json
```

RIDs previstos: `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64`. Las publicaciones macOS requieren empaquetado y firma posteriores para distribución; Linux requiere bibliotecas gráficas del sistema. Compilar para un RID no demuestra que la aplicación se haya probado en ese sistema.

## Alcance de esta versión

Gestión nativa de casos, importación de archivos, hashes, búsqueda del inventario, operaciones, notas y exportación; adaptación de los módulos V1 para captura/verificación/análisis donde son compatibles. No incorpora motores estructurales para imágenes de RAM/disco, extracción móvil, recuperación de borrados ni descifrado. Una extensión `.mem`, `.raw` o `.img` no identifica contenido. Un hash de volcado RAM no implica igualdad con RAM viva. Las coincidencias de registros no identifican a una persona física. Revisar fuentes, cobertura y conclusiones antes de emitir dictamen.

Documentación: `docs/VALIDACION.md`, `docs/THIRD_PARTY_NOTICES.md`, `vendor/PROVENANCE.md` y `KRONOS_V2_CONTINUIDAD.md`.

## GitHub y validación en contenedor

`.github/workflows/validate.yml` prepara compilación y pruebas en Windows y Ubuntu, y un trabajo que construye la imagen de desarrollo y ejecuta las pruebas dentro de ella. Consulta los resultados de las ejecuciones en [GitHub Actions](https://github.com/UlysesX12/KRONOS-V2.0/actions); la configuración por sí sola no acredita que hayan pasado. `.gitattributes` conserva los módulos V1 byte a byte para mantener válidos los hashes de procedencia.

Para probar manualmente el contenedor desde un terminal con acceso a Docker:

```powershell
docker build -f .devcontainer/Dockerfile -t kronos-dev .
docker run --rm -v "${PWD}:/workspaces/kronos" -w /workspaces/kronos kronos-dev sh scripts/test.sh
```

Estas pruebas no requieren escritorio gráfico. La interfaz Avalonia se prueba en modo headless; abrir una ventana visible desde el contenedor requiere configurar acceso a un servidor gráfico. El contenedor aísla las dependencias, pero el montaje de esta carpeta permite que compilaciones y cambios de archivos se reflejen en el anfitrión. En esta sesión el SDK local y la publicación Windows se ejecutaron en el anfitrión; no se ha validado todavía la ejecución dentro de Docker.

## Más proyectos

Consulta el [catálogo de proyectos públicos](https://github.com/UlysesX12/WebSite/blob/main/docs/PROYECTOS.md).
