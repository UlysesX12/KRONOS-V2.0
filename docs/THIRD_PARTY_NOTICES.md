# Dependencias

- .NET 10 / runtime distribuible: Microsoft y colaboradores. MIT y avisos de componentes incluidos en el runtime: https://github.com/dotnet/runtime/blob/main/LICENSE.TXT y https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT.
- Avalonia 11.3.22, Desktop, Fluent y dependencias Avalonia: MIT, https://github.com/AvaloniaUI/Avalonia/blob/master/licence.md. Headless solo se usa en pruebas. Versiones transitivas exactas en `packages.lock.json`.
- SkiaSharp y HarfBuzzSharp: MIT para bindings, con licencias propias de bibliotecas nativas; https://github.com/mono/SkiaSharp y https://github.com/harfbuzz/harfbuzz. Los avisos disponibles en los paquetes NuGet se copian a `licenses/` durante la publicación PowerShell.
- Python 3: dependencia externa de los módulos V1, no se redistribuye con el ejecutable Windows. https://docs.python.org/3/license.html.
- Windows PowerShell: componente del sistema Windows, no redistribuido.
- Scripts KRONOS V1: copyright JLC, avisos originales conservados. Véase `vendor/PROVENANCE.md`.

Las aportaciones propias a KRONOS están sujetas al aviso de derechos reservados de `LICENSE.md`, con créditos en `AUTHORS.md`. Este aviso no modifica las licencias de los componentes de terceros. Revisar sus avisos y condiciones al preparar una distribución externa.
