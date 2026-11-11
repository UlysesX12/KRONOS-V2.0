"""Punto de entrada de KRONOS para Volatility 3, sin modificar el motor."""
# Copyright (c) 2026 Jose Luis Cabanas (JLC / UlysesX12).
# Distribuido bajo Volatility Software License 1.0; vease LICENSE.md.
import importlib.metadata
import sys

if __name__ == '__main__':
    if sys.argv[1:] == ['--kronos-version']:
        print(importlib.metadata.version('volatility3'))
    else:
        from volatility3.cli import main
        main()
