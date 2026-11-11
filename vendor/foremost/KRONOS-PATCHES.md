# Foremost: procedencia y cambios para Windows

Fuente original: https://foremost.sourceforge.net/pkg/foremost-1.5.7.tar.gz

SHA-256 del archivo original: `502054ef212e3d90b292e99c7f7ac91f89f024720cd5a7e7680c3d1901ef5f34`.

Se conservan los avisos originales, incluido el trabajo del Gobierno de EE. UU. conforme a 17 USC 105, los créditos y el aviso de ausencia de garantía. No se atribuye Foremost a JLC ni se sustituyen sus condiciones por las de KRONOS. La distribución original está enlazada arriba; aquí se incluyen sus fuentes y configuración, sin el manual gzip.

Cambios de compatibilidad de KRONOS, noviembre 2026, versión `1.5.7-kronos1`:

- `main.h`: offset de 64 bits y `_ftelli64`/`_fseeki64` en el port Windows para superar 2 GiB.
- `ole.h`: tipo explícito `uint16_t` para campos OLE de 16 bits.
- `dir.c`: corrección de `fprint` a `fprintf`.
- `extract.c`: texto de fecha como argumento de `%s`, sin interpretarlo como formato.

Compilación mediante Zig 0.15.2 fijado y verificado por `scripts/package-forensics.py`, destino `x86_64-windows-gnu`. Zig solo se usa para construir; no se distribuye con la aplicación. El código original contiene otras advertencias del compilador: este port no representa una auditoría exhaustiva de seguridad ni garantiza recuperar archivos completos.
