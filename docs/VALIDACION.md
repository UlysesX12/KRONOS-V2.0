# Validación de la versión actual

KRONOS incluye gestión de casos, copia y verificación de evidencias, análisis RAM Windows con Volatility 3, tabla de resultados con búsqueda, notas con referencias de fuente e informes HTML/Markdown.

## Pruebas automatizadas

- Núcleo: SHA-256 conocido, origen intacto, copia verificada, persistencia, apertura concurrente, nombres con espacios/tildes, exportación, alteraciones, ausencias, archivos ajenos, rutas fuera del caso y cancelación.
- RAM: orquestación de cuatro módulos mediante datos sintéticos, referencias JSON Pointer, límite de vista previa, salidas vacías, resultados parciales, rechazo de evidencia alterada, detección de JSON alterado, cancelación, historial e informes.
- Motor real: Volatility instalado y runtime Python empaquetado rechazan un archivo de ceros sintéticos como imagen compatible; no se transforma ese error en resultados válidos.
- Interfaz headless: cinco pestañas, recuperación tras un error y tabla RAM que muestra filas verificadas de un caso sintético guardado.
- Módulos de artefactos: base Chromium SQLite sintética, generación de resultados, fuente intacta y detección de alteración.
- Sincronización Git: repositorios temporales, historial inicial, conservación de archivos, rechazo de diferencias y protección de commits existentes.

Estas pruebas no extraen información de volcados del usuario ni realizan adquisiciones del anfitrión. La prueba funcional de su volcado se realiza desde la interfaz.

## Entorno y ejecución

Desarrollo previsto en Dev Container, con SDK y dependencias fijados. GitHub Actions configura pruebas en Windows, Ubuntu y Docker. Los resultados efectivos de cada revisión se consultan en [Actions](https://github.com/UlysesX12/KRONOS-V2.0/actions); configurar una prueba no significa que ya haya pasado.

La publicación Windows x64 es autocontenida e incorpora Python embebido y el motor RAM. Los avisos de licencia se conservan. Los hashes de dependencias Python están fijados en `engines/memory/requirements.lock`; el archivo del runtime embebido se comprueba mediante SHA-256 durante el empaquetado.

## Limitaciones

El análisis RAM se limita a los módulos Windows integrados y depende de los símbolos disponibles y del soporte real de Volatility. No se garantiza recuperar todo ni atribuir autoría por coincidencias. El rendimiento no mejora automáticamente por integrar el motor en una interfaz.

La ventana Windows, los selectores del sistema y un volcado compatible requieren prueba manual. Las pruebas headless no certifican toda la interacción gráfica ni el acceso a hardware. No se ha certificado adquisición RAM, dispositivos físicos, extracción móvil, imágenes de disco ni análisis de RAM Linux/macOS.

El historial del caso no está firmado. Una interrupción abrupta puede dejar un análisis en curso o un archivo de evidencia no registrado; conserva el caso completo y verifica su integridad antes de emitir conclusiones.
