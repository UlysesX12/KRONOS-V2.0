# Laboratorio forense integrado

En Windows abre `KRONOS.lnk`. Crea o abre un caso y entra en **Laboratorio forense**. Importa el archivo, selecciona la evidencia y la herramienta, y pulsa **Ejecutar herramienta**. No es necesario instalar estas herramientas por separado en la publicación Windows x64.

| Herramienta | Entrada | Resultado y límites |
| --- | --- | --- |
| Volatility 3 2.28.2, pestaña Análisis RAM | RAM Windows compatible | Perfil básico de 4 módulos o ampliado de 14: sistema, procesos, comandos, red, árbol, exploración de procesos, SID, sesiones, entorno, archivos, colmenas, UserAssist, DLL y Malfind. Depende de los símbolos; Malfind es un indicio, no un veredicto. |
| Foremost 1.5.7-kronos1 | Volcado o imagen RAW sin compresión | Recuperación por firmas JPG, PNG, GIF, PDF, ZIP y OLE. Los candidatos pueden estar incompletos, fragmentados o ser falsos positivos. No monta el disco. |
| FLOSS 3.2.0 | Ejecutable compatible | Cadenas estáticas, de pila, ajustadas y descodificadas según soporte del motor. No inicia el ejecutable como programa; utiliza análisis y emulación. Desactivada la carga/guardado de workspaces VIV. No acredita malicia. |
| ALEAPP 2026.4.5 | Extracción Android ZIP/TAR/TAR.GZ | Interpreta artefactos compatibles. Conserva TSV, LAVA, informes originales, registros y estados por plugin. No adquiere teléfonos ni evade bloqueos. |
| iLEAPP 2026.4.6 | Extracción de sistema de archivos iOS ZIP/TAR/TAR.GZ | Igual, con plugins iOS. Esta integración no procesa copias iTunes cifradas, ni adquiere ni desbloquea dispositivos. |
| Navegadores | SQLite Chromium `History`, Firefox `places.sqlite`, Safari `History.db` | Visitas con fuente e ID de registro y consulta `q` de URLs de GitHub. Solo base principal: no reconstruye WAL, borrados ni navegación privada. |
| ZIP | Archivo ZIP | Nombres, tamaños, compresión, CRC, marca de cifrado y rutas peligrosas del directorio central. Sin ejecutar ni extraer. No obtiene contraseñas ni certifica seguridad del contenido. |
| Cadenas | Archivo, ejecutable, RAM o imagen | ASCII/UTF-16LE imprimibles, mínimo 6 caracteres, con offsets. Hasta 100000 cadenas de hasta 4096 bytes. Son indicios: una URL en RAM no acredita una visita. |
| Discos RAW | Imagen de disco o volumen RAW | GPT con sectores 512/4096 y CRC32, MBR primario con sector 512 y firmas NTFS/FAT/exFAT/ext/XFS/BitLocker/LUKS. No enumera archivos, interpreta EWF/VHD/VMDK, recorre EBR, reconstruye RAID/LVM ni descifra. |

## Leer y encadenar resultados

La tabla ocupa el área central. Busca texto y haz doble clic para ver una fila completa. **Añadir fila a notas** incorpora la referencia al JSON, el motor, la evidencia y los valores. Revisa la interpretación y guarda las notas antes de generar el informe.

En Foremost, selecciona una fila de **Archivo recuperado por firma** y pulsa **Importar archivo recuperado**. KRONOS verifica la salida contra el manifiesto, crea una nueva copia de evidencia y registra el vínculo con la evidencia original. Después puedes seleccionar ZIP, navegador o FLOSS según el archivo recuperado. No se ejecutan los candidatos recuperados.

El estado **REVISAR COBERTURA** de LEAPP es deliberado: que termine el proceso no demuestra que todos sus plugins hayan encontrado o interpretado datos. La tabla incluye estados de los plugins e incidencias. Un resultado vacío tampoco demuestra ausencia de actividad. Los informes HTML originales contienen datos no confiables: la aplicación muestra sus exportaciones como texto y no los abre automáticamente.

## Disco de un PC o servidor

Esta versión trabaja con una **imagen forense RAW previamente adquirida**, sin conectar o capturar automáticamente discos físicos. Puede inventariar particiones y ejecutar Foremost sobre la imagen. Todavía no ofrece un explorador completo del sistema de archivos ni reconstrucción de almacenamiento de servidores. No basta con cambiar `.E01` a `.img`: debe exportarse o convertirse con una herramienta compatible, documentando el proceso y los hashes.

## Preguntas de investigación

| Pregunta | Dónde buscar y qué falta comprobar |
| --- | --- |
| Sistema operativo | RAM: Información del sistema. Firmas de disco no identifican por sí solas la versión del SO. |
| Usuario o sesión | RAM ampliada: sesiones, SID y entorno. No atribuyen por sí solos la identidad física de la persona. |
| PID de FTK, Notepad y Edge | Procesos, árbol y comandos. Revisar padre/hijos y tiempos antes de identificar el proceso principal. |
| Procesos sospechosos | Comparar pslist/psscan, árbol, DLL, comandos y Malfind; confirmar con otras fuentes. |
| Historial y búsquedas GitHub | Base de historial recuperada y adaptador de navegador, o LEAPP para móviles. Las cadenas RAM son solo indicios. |
| IP y conexiones | Netscan, PID y estados recuperados. No todas las direcciones pertenecen al dispositivo ni todas las filas representan conexiones establecidas. |
| ZIP importante | Recuperar con Foremost si aparece completo, importar como derivado y consultar inventario ZIP. Contraseña y análisis completo del contenido cifrado pendientes. |
| Imágenes | Foremost, sus archivos recuperados, hashes y auditoría. Revisar visualmente e integridad del formato; no todas las imágenes sobreviven al carving. |
| Motivo académico o afición | Interpretación profesional apoyada en artefactos y contexto; no se infiere como un hecho automático. |
| Proceso sospechoso con red | Cruzar PID, tiempos y estado en la misma evidencia RAM. La reutilización de PID y artefactos residuales exigen revisión. |

## Integridad, recursos y publicación

Cada ejecución registra hashes de evidencia antes/después, versión y SHA-256 del ejecutable/adaptador, argumentos, registros, tabla normalizada, cobertura, resumen y manifiesto de archivos de salida. Al mostrar tablas o importar recuperados se verifican sus hashes. El caso y sus manifiestos no están firmados independientemente.

Se pueden cancelar los procesos; se conservan incidencias y salidas parciales. Cada proceso tiene 30 minutos y un límite supervisado de 10 GiB/100000 archivos de salida (se comprueba aproximadamente cada 1,5 segundos; no es una cuota de disco). La vista previa muestra hasta 10000 filas y rechaza JSON superior a 128 MiB. Una extracción móvil grande puede agotar esos límites.

LEAPP usa un temporal corto para evitar fallos Windows con rutas largas. Al terminar se transfieren las salidas al caso, con verificación SHA-256 si cruzan de volumen. Sus reportes originales pueden conservar rutas absolutas del temporal ya retirado; consulta los artefactos conservados y sus referencias relativas. Si falla la transferencia, el error conserva la ubicación del temporal para recuperarlo.

`scripts/package-forensics.py` descarga exclusivamente versiones oficiales fijadas y comprueba SHA-256, compila el port Windows de Foremost desde el código incluido y genera `tools.json`. No instala herramientas globales. Los binarios son para Windows x64; el Dev Container ejecuta las pruebas de núcleo y adaptadores, y la publicación Windows valida los cuatro motores portátiles. No se incorpora la distribución CAINE ni se atribuye a KRONOS la autoría de sus herramientas.

Fuentes de formatos del lector RAW: [especificación GPT de UEFI](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html) y [superbloque ext4 de Linux](https://kernel.org/doc/html/next/filesystems/ext4/super.html). Herramientas y licencias: [avisos de terceros](THIRD_PARTY_NOTICES.md).
