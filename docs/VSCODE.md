# Probar KRONOS desde VS Code

## En esta carpeta de Windows

Abre `Abrir-KRONOS-VSCode.cmd` desde el Explorador. Crea una ventana de VS Code con el SDK local de `.tools/dotnet` disponible para el editor y sus extensiones. Su perfil se guarda en `.tools/vscode-local`; no instala un SDK global ni cambia la configuración del resto de VS Code. Si se solicita confianza, revisa la carpeta y autoriza el código del proyecto para habilitar tareas y depuración.

En esa ventana:

1. **Ver las pruebas:** `Ctrl+Shift+P` → **Tasks: Run Task / Tareas: Ejecutar tarea** → **KRONOS: Probar**. El terminal muestra el resultado del núcleo, la interfaz headless y los módulos Python. El código de salida debe ser 0.
2. **Ver la aplicación:** en el mismo menú, **KRONOS: Abrir aplicacion Windows**. Se compila y abre la ventana de KRONOS en Windows. Para depurar, abre Ejecutar y depurar, selecciona **KRONOS: Interfaz Windows (F5)** y pulsa F5. Requiere la extensión C# de Microsoft.
3. **Compilar:** `Ctrl+Shift+B`, tarea predeterminada **KRONOS: Compilar**.

Esta opción usa Windows para el editor, las pruebas y la ventana gráfica. El SDK y las dependencias quedan en la carpeta del proyecto; no es ejecución dentro de Docker. Las tareas no ejecutan adquisiciones del anfitrión.

## Probar dentro de Docker

Con Docker Desktop abierto, ejecuta la tarea **KRONOS: Probar dentro de Docker**. Construye la imagen de desarrollo y ejecuta las pruebas dentro del contenedor. No abre la interfaz gráfica.

Para editar también dentro del contenedor: **Dev Containers: Reopen in Container**. Cuando abajo a la izquierda aparezca el nombre del Dev Container, ejecuta la tarea **KRONOS: Probar**. Dentro de Linux usa `sh scripts/test.sh`. El SDK ya está en la imagen. Abrir una ventana gráfica desde Linux requiere configurar un servidor gráfico.

Si Docker devuelve `permission denied` o un error de conexión al motor, las pruebas del contenedor no han comenzado; conserva la salida del terminal para diagnosticar ese acceso.

## Cambios pendientes de Git

Los cambios visibles en la carpeta inicial no equivalen a archivos que falten en GitHub: el conector publicó los commits sin actualizar el `.git` local. La carpeta inicial quedó con una rama sin commits.

En un terminal de VS Code con permisos normales del usuario, ejecuta la tarea **KRONOS: Sincronizar historial GitHub Windows**. Añade el remoto si falta, descarga `main` y verifica que cada archivo remoto coincide con el archivo local mediante sus hashes Git y atributos. Solo si todos coinciden, establece el historial local con `git reset --mixed origin/main`, que conserva los archivos de trabajo. No borra archivos, no fuerza una subida y no descarta diferencias. Si ya existen commits locales o hay diferencias, no restablece el historial.

Este paso requiere acceso de escritura a `.git` y conexión con GitHub. La sesión del agente tiene `.git` en solo lectura y no puede completarlo directamente. Las credenciales, si GitHub las solicita, se introducen en el gestor de credenciales del usuario, nunca en archivos del proyecto.
