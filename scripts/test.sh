#!/usr/bin/env sh
set -eu
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export AVALONIA_TELEMETRY_OPTOUT=1
cd "$(dirname "$0")/.."
dotnet restore Kronos.sln --locked-mode
dotnet build Kronos.sln -c Release --no-restore
dotnet run --project tests/Kronos.SmokeTests -c Release --no-build
dotnet run --project tests/Kronos.DesktopTests -c Release --no-build
python3 tests/test_legacy.py
python3 tests/test_sync_git.py
