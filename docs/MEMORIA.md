# Análisis RAM en KRONOS

## Preparar el caso

El campo **Nombre del caso** admite espacios y tildes, hasta 120 caracteres. Ejemplo: `Prueba de memoria Windows`. En **Nombre del analista forense** escribe quién realiza el análisis.

Pulsa **Crear caso…** y elige una carpeta de destino. KRONOS crea la estructura del caso. Para continuar otro día usa **Abrir caso…** y selecciona su archivo `case.kronos.json`.

## Importar y analizar

En **Análisis RAM**, pulsa **Importar volcado RAM…** y selecciona el archivo original. No lo copies manualmente en la carpeta del caso. KRONOS copia sus bytes y verifica SHA-256 del origen antes y después y de la copia. El nombre interno de la copia no determina su formato.

Selecciona la evidencia y pulsa **Analizar RAM Windows**. El análisis utiliza la copia del caso en modo de lectura y comprueba su hash al comenzar y al terminar.

## Módulos

| Módulo | Resultado |
| --- | --- |
| Información del sistema | Datos del núcleo y de la imagen que el motor pueda interpretar. Si falla, no se ejecutan los módulos dependientes. |
| Procesos | Procesos enumerados por `windows.pslist.PsList`. |
| Líneas de comando | Información recuperada por `windows.cmdline.CmdLine`. |
| Conexiones de red | Artefactos de red recuperados por `windows.netscan.NetScan`. No representan conexiones actuales del equipo donde ejecutas KRONOS. |

Las pestañas Equipo, Procesos, Comandos y Red muestran el número de filas. Al abrir un análisis se muestran primero los procesos. La tabla permite buscar texto, PID y direcciones IP. Se cargan como máximo 10.000 filas en la vista previa; el JSON completo se conserva. Las salidas mayores de 128 MiB no se cargan en la vista previa y se documentan como incidencia.

Haz doble clic en una fila para ver todos sus campos y copiar el texto. Selecciona una fila y pulsa **Añadir fila a notas** para conservar sus valores, plugin, ruta del JSON y JSON Pointer de origen. Completa tu interpretación en **Informe editable**.

## Símbolos y conexión

La publicación Windows x64 incluye Python 3.14.10 y Volatility 3, paquete 2.28.2, con pefile 2024.8.26. El Dev Container incluye su propio entorno del motor.

El motor puede necesitar descargar símbolos de Microsoft mediante identificadores técnicos del núcleo. No se envía el archivo de memoria. La opción **Sin conexión** restringe el análisis a los símbolos ya disponibles. Los símbolos para Windows no siempre pueden resolverse automáticamente; se registra el error real.

## Progreso y cancelación

El estado identifica la fase y el módulo. El tiempo depende del tamaño y estructura del volcado, del almacenamiento, del motor y de los símbolos. **Cancelar** detiene el proceso del módulo y conserva los registros y resultados parciales, con su estado. Cada proceso tiene un límite de 10 minutos.

## Salidas y verificaciones

Los resultados se guardan en una carpeta nueva `analysis/memory_…/`, separada de `evidence/`. Contiene JSON por módulo, registros, configuración de ejecución, versión, resumen y manifiesto de las salidas. El resumen enlaza la evidencia por su ID y sus hashes. La caché y los símbolos se mantienen en `analysis/cache` y `analysis/symbols`.

La tabla verifica el manifiesto y el JSON antes de mostrar resultados. Estos hashes documentan integridad respecto del inventario vigente; no son un sellado independiente.

## Límites

El soporte inicial es para imágenes compatibles de Windows. Renombrar un archivo a `.mem` no lo convierte en un volcado válido. Las conexiones, procesos y comandos recuperados son artefactos de la imagen; no se ejecutan. Un módulo correcto no acredita análisis completo, y cero filas no demuestra ausencia. Las conclusiones y la atribución corresponden al profesional.
