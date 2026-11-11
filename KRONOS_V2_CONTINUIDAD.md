# KRONOS V2.0 — Continuidad del proyecto

> Actualización 11/11/2026: este documento conserva el contexto anterior a la implementación. La primera versión V2 ya está implementada en este workspace. Consultar `README.md` y `docs/VALIDACION.md` para el estado, pruebas, ejecutable y limitaciones actuales. Los apartados históricos que indican «no implementado» describen la sesión anterior.

## Objetivo del usuario
Construir una aplicación forense de escritorio integrada, con interfaz sencilla e interactiva. Debe gestionar el caso desde la adquisición o importación hasta la verificación, análisis e informe técnico pericial editable. El usuario quiere evitar instalar y manejar herramientas separadas. No quiere solamente una interfaz para lanzar scripts.

## Ubicaciones
- Proyecto nuevo: `F:\develop\KRONOS V2.0` (creado por el usuario).
- Código original: `F:\develop\KRONOS_1.0_JLC_USB_20261020_195425_578`.
- Conservar los originales. Incorporar copias al nuevo proyecto cuando exista acceso autorizado, documentando su procedencia.

## Dirección técnica acordada en la conversación
- Escritorio para Windows, macOS y Linux/Ubuntu; por ello se propuso C# + .NET + Avalonia en lugar de WPF, que solo funciona en Windows.
- VS Code como editor. Visual Studio está instalado pero no es necesario.
- Desarrollo y compilación en Dev Container sobre Docker para evitar instalar SDK y dependencias en el anfitrión.
- Publicaciones por sistema y arquitectura, con runtime incluido cuando proceda. El usuario final no debe necesitar Docker.
- Núcleo compartido para casos, hashes, evidencias, resultados e informes; adquisición específica por sistema.
- Reutilizar inicialmente PowerShell para adquisición Windows y los módulos Python existentes. No asumir que funcionan en otros sistemas.
- Analizadores propios y/o componentes redistribuibles incluidos: la elección concreta no está cerrada. Respetar licencias y documentar dependencias. No prometer equivalencia inmediata con Autopsy/Volatility.

## Funciones deseadas a largo plazo
- Detectar host, SO, RAM instalada, almacenamiento y dispositivos conectados según permisos y compatibilidad.
- Adquirir archivos, almacenamiento y RAM mediante métodos compatibles.
- Importar y analizar imágenes de memoria y disco y extracciones móviles, no solamente adquirirlas.
- Analizar procesos, conexiones, sistemas de archivos, metadatos, navegadores, eventos, cronologías y bases de datos de aplicaciones como WhatsApp, dentro del soporte real.
- Buscar, filtrar, explorar resultados, consultar su fuente y marcar hallazgos para informes.
- Relacionar evidencias sin convertir coincidencias en atribuciones automáticas de autoría.
- Documentar operador, dispositivo, método, herramientas/versiones, tiempos/zona horaria, operaciones, incidencias, cobertura, hashes y verificaciones.
- Informe técnico pericial editable con fuentes, metodología, resultados, limitaciones y anexos; conclusiones revisadas por el profesional.

## Límites técnicos que deben mantenerse explícitos
- Detectar un dispositivo no implica poder extraerlo completamente; móvil bloqueado/cifrado y permisos condicionan el acceso.
- Una extensión .mem/.raw/.img no identifica de forma fiable el contenido.
- Comparar origen estable y copia cuando corresponda. El hash del volcado RAM no demuestra igualdad con una segunda lectura de RAM viva.
- En formatos contenedores/comprimidos verificar los datos adquiridos con el procedimiento adecuado; no comparar sin más hash de contenedor y dispositivo.
- No prometer análisis total, recuperación de todo lo borrado ni descifrado universal. Mostrar módulos ejecutados, fallos y fuentes no compatibles.
- Contenedores no sustituyen al SO anfitrión para probar captura de RAM o acceso a dispositivos. Pruebas en VM y después hardware real.
- GUI multiplataforma no convierte los scripts Windows en módulos multiplataforma.

## Auditoría ya realizada del código original
Archivos presentes:
- `Kronos.ps1` (47653 bytes): captura/triage en vivo Windows, requiere administrador. Parámetros CaseId, Operator, OutputRoot, CollectionProfile Triage/Extended, MemoryMode Ask/Acquire/Skip, límites de eventos/navegador y Python opcional.
- `Kronos.Verify.ps1` (2875 bytes): verifica tamaños, SHA-256, rutas válidas, duplicados, ausencias y archivos fuera del manifiesto del caso. No requiere administrador.
- `Kronos.Browser.py` (6140 bytes): interpreta copias SQLite Chromium, genera CSV; biblioteca estándar de Python.
- `Kronos.Correlate.py` (24960 bytes): análisis de caso, CSV externos opcionales y salida separada de la evidencia; informe HTML, observaciones, coincidencias y cobertura.
- `KRONOS_GUIA_FACIL.txt`: ejecución manual USB/PowerShell/Python, flujo y límites.
- `KRONOS_USB_SHA256_20261020_195425_578.csv`: manifiesto del paquete original.

Captura actual:
- Recoge artefactos Windows, historial Chromium, Jump Lists, eventos y datos del sistema; genera informe HTML, metadatos y manifiesto SHA-256.
- RAM: invoca `tools\winpmem_mini_x64.exe` con validación de firma o hash esperado. El ejecutable NO estaba presente en la carpeta revisada. Calcula hash del volcado.
- Hashes del caso sobre archivos de destino; no existe comparación sistemática SHA-256 origen/copia.
- No se encontraron motores de imagen completa de disco, extracción móvil ni análisis estructural de imágenes de memoria/disco.
- No se encontró AGENTS.md en el listado revisado. Comprobar instrucciones aplicables de nuevo en el proyecto destino.

## Primera versión propuesta (todavía no implementada)
1. Solución .NET/Avalonia y Dev Container reproducible con versiones verificadas.
2. Interfaz en español: crear/abrir casos, añadir evidencias, estado/progreso y resultados.
3. Registro de evidencias existentes y SHA-256 sin modificar el original; documentar verificación y errores.
4. Integrar captura, verificación y análisis actuales donde sean compatibles.
5. Abrir informes y carpetas desde la interfaz.
6. Declarar como pendientes los motores avanzados; no presentar botones simulados como funciones reales.
7. Pruebas relevantes con datos sintéticos conocidos y compilación verificada.

## Laboratorio disponible
- Usuario indica Docker Desktop, VS Code y Dev Container abiertos (no se ha inspeccionado la configuración del contenedor).
- VirtualBox instalado, VM Kali y Ubuntu Server existentes.
- Se propuso añadir VM Windows 11 de evaluación para interfaz/captura Windows. El usuario todavía no ha confirmado su creación. Windows Server no hace falta para comenzar.
- Ubuntu Server puede servir como fuente de pruebas sin escritorio; Kali como entorno Linux gráfico si está configurado.
- Usar instantáneas y actividad sintética conocida. Pruebas de VM no bastan para certificar soporte de hardware físico.

## Estado al cerrar esta sesión
- NO se ha creado todavía la solución V2, ni Dev Container, ni interfaz. Solo inspección y planificación, y este documento de continuidad.
- Esta sesión tiene escritura únicamente en la carpeta antigua, no en `F:\develop\KRONOS V2.0`.
- `Get-ChildItem` del destino no mostró contenido; no inferir más sin comprobarlo.
- `docker ps` y `docker version` fallaron con permiso denegado en `npipe:////./pipe/dockerDesktopLinuxEngine`. No se puede afirmar que Docker esté parado o roto: puede ser restricción de esta sesión.
- Continuar en sesión cuyo workspace sea el proyecto nuevo y comprobar acceso Docker antes de instalar o configurar nada.

## Instrucción de continuación
El usuario ya ha indicado que el proyecto debe desarrollarse en KRONOS V2.0 y quiere comenzar. Leer este documento, inspeccionar workspace e instrucciones, comprobar Docker y avanzar con la primera versión sin volver a preguntar decisiones ya acordadas. Mantener comunicación en español. No realizar adquisiciones reales sobre el anfitrión como parte de las pruebas sin autorización específica.
