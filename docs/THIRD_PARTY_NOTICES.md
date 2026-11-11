# Dependencias y licencias

KRONOS V2 es un proyecto de José Luis Cabañas (JLC / UlysesX12). El código propio se distribuye bajo [Volatility Software License 1.0](../LICENSE.md), con el texto íntegro en [licenses/VolatilitySoftwareLicense-1.0.txt](../licenses/VolatilitySoftwareLicense-1.0.txt).

- **Volatility 3, paquete 2.28.2:** Volatility Foundation. VSL 1.0. https://github.com/volatilityfoundation/volatility3. No se modifica el motor; KRONOS integra su ejecución y procesa sus salidas.
- **pefile 2024.8.26:** MIT. Aviso incluido en `licenses/pefile-LICENSE.txt`.
- **Python:** PSF y licencias asociadas. https://docs.python.org/3/license.html. La publicación Windows x64 incorpora el paquete embebido oficial Python 3.14.10, conservando su `LICENSE.txt` y avisos de las dependencias.
- **.NET 10:** Microsoft y colaboradores, MIT y avisos del runtime. https://github.com/dotnet/runtime/blob/main/LICENSE.TXT y https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT.
- **Avalonia 11.3.22 y DataGrid 11.3.13:** MIT. https://github.com/AvaloniaUI/Avalonia/blob/master/licence.md. Headless se usa en pruebas. Las versiones transitivas están en los archivos de bloqueo NuGet.
- **SkiaSharp y HarfBuzzSharp:** MIT para bindings y licencias propias de las bibliotecas nativas. https://github.com/mono/SkiaSharp y https://github.com/harfbuzz/harfbuzz. Los avisos disponibles en NuGet se copian durante la publicación.
- **Windows PowerShell:** componente del sistema para los módulos de adquisición/verificación Windows; no redistribuido.
- **Módulos originales KRONOS de artefactos:** copyright JLC. Se conservan sus avisos y hashes de procedencia en `vendor/PROVENANCE.md`.
- **FLOSS 3.2.0:** Mandiant y colaboradores, Apache 2.0; texto en `licenses/FLOSS-LICENSE.txt`. https://github.com/mandiant/flare-floss/tree/v3.2.0. Binario oficial sin modificar.
- **ALEAPP 2026.4.5 e iLEAPP 2026.4.6:** Alexis Brignoni y colaboradores, MIT; licencias y atribuciones originales en `licenses/ALEAPP-LICENSE.txt`, `licenses/iLEAPP-LICENSE.txt` y sus archivos `*-ATTRIBUTIONS.md`. https://github.com/abrignoni/ALEAPP y https://github.com/abrignoni/iLEAPP. Binarios oficiales sin modificar; retienen las licencias de los componentes que incorporan.
- **Foremost 1.5.7-kronos1:** autores originales indicados en sus fuentes, incluido el aviso de trabajo del Gobierno de EE. UU. y ausencia de garantía. Fuente y cambios de compatibilidad en `vendor/foremost`, procedencia y condiciones en `vendor/foremost/KRONOS-PATCHES.md`. https://foremost.sourceforge.net/.
- **Zig 0.15.2:** solo compilador local de publicación, verificado por hash. No se instala globalmente ni se distribuye como parte de KRONOS.

Las licencias de terceros no se sustituyen por la de KRONOS ni se atribuye su autoría al titular del proyecto. La VSL no concede derechos sobre las marcas de Volatility Foundation.
