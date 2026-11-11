# KRONOS V2.0

**Proyecto de José Luis Cabañas (JLC / UlysesX12).** Copyright © 2026 José Luis Cabañas. Código propio bajo [Volatility Software License 1.0](LICENSE.md). [Autoría y créditos](AUTHORS.md).

Aplicación de escritorio en español para gestionar casos, importar evidencias, verificar SHA-256, analizar RAM Windows con Volatility 3 y preparar informes editables.

## Usar la aplicación en Windows

Abre **KRONOS.lnk** en la carpeta del proyecto, o **artifacts/win-x64/Kronos.Desktop.exe**. El acceso directo se genera al preparar la publicación Windows. La carpeta publicada contiene .NET, Python y Volatility; conserva todos sus archivos juntos. No requiere abrir VS Code, Docker, una consola ni crear un venv para usarla.

Si descargas solo el código desde GitHub, el ejecutable no viene en el repositorio. Las publicaciones preparadas por el flujo de GitHub Actions estarán en el artefacto **KRONOS-windows-x64** de una ejecución completada.

## Probar un volcado RAM

1. Rellena **Nombre del caso** y **Nombre del analista forense**, pulsa **Crear caso…** y elige dónde guardar el caso.
2. En **Análisis RAM**, pulsa **Importar volcado RAM…** y selecciona el archivo descargado, por ejemplo un `.mem`. KRONOS crea y verifica su copia; no la coloques manualmente en `evidence/`.
3. Selecciona la evidencia y pulsa **Analizar RAM Windows**.
4. Revisa los módulos **Información del sistema**, **Procesos**, **Líneas de comando** y **Conexiones de red**. Puedes buscar en las filas y añadir una fila a las notas con su fuente.
5. En **Informe editable**, completa las conclusiones, guarda las notas y genera HTML y Markdown.

La primera ejecución puede necesitar descargar símbolos. El progreso identifica el módulo en curso y permite cancelar. Una extensión no identifica el formato ni garantiza compatibilidad. [Guía del análisis RAM](docs/MEMORIA.md).

## Casos, resultados e integridad

- `case.kronos.json`: nombre del caso, analista, inventario, operaciones y análisis.
- `evidence/`: copias importadas, comparadas con el origen antes/después y con el destino mediante SHA-256.
- `analysis/`: resultados RAM separados de la evidencia, JSON, registros, resumen, manifiesto de salidas y caché de símbolos.
- `reports/`: informes HTML y Markdown editables.

**Verificar copias** compara los archivos con el inventario del caso. Al analizar RAM se comprueba SHA-256 antes y después; al cargar las tablas se verifica su manifiesto. El JSON y los manifiestos no están firmados ni sellados de forma independiente. Conserva y respalda la carpeta completa.

## Desarrollo: Dev Container

Abre esta carpeta en VS Code y usa **Dev Containers: Reopen in Container**. El entorno incluye .NET 10.0.404, Python y Volatility 3. No utiliza el SDK de Windows para desarrollar.

Dentro del contenedor, ejecuta **Tareas: Ejecutar tarea → KRONOS: Probar en Dev Container**. Para compilar, `Ctrl+Shift+B`. [Guía de VS Code](docs/VSCODE.md).

La ventana de la aplicación Windows se prueba con el ejecutable publicado. Las pruebas del contenedor usan Avalonia headless y no abren una ventana Windows.

## Alcance

El análisis RAM integrado utiliza Volatility 3, versión **2.28.2** mediante módulos Windows. La cobertura depende de la imagen, los símbolos y cada módulo; un módulo correcto con cero filas no demuestra ausencia de actividad. El informe distingue módulos correctos, fallidos, no ejecutados y cancelados.

Los módulos de adquisición y análisis de carpetas de artefactos Windows siguen disponibles en **Módulos y adquisición**. La adquisición requiere autorización explícita y privilegios adecuados, con captura RAM desactivada. Importar y analizar un volcado existente no adquiere la RAM del equipo anfitrión.

Pendientes: adquisición RAM integrada, motores de imágenes de disco, análisis Linux/macOS, extracción móvil y descifrado. Las coincidencias no atribuyen autoría.

Consulta [validación y límites](docs/VALIDACION.md) y [dependencias y licencias](docs/THIRD_PARTY_NOTICES.md).

## Más proyectos

[Catálogo de proyectos públicos](https://github.com/UlysesX12/WebSite/blob/main/docs/PROYECTOS.md).
