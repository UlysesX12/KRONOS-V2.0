FROM mcr.microsoft.com/dotnet/sdk:10.0.404-noble@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb
RUN apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends python3 python3-venv git libx11-6 libice6 libsm6 libfontconfig1 libglib2.0-0t64 libgl1 libxrender1 libxi6 libxcursor1 libxrandr2 && rm -rf /var/lib/apt/lists/*
COPY engines/memory/requirements.lock /tmp/kronos-memory-requirements.lock
RUN python3 -m venv /opt/kronos-memory && /opt/kronos-memory/bin/python -m pip install --only-binary=:all: --require-hashes -r /tmp/kronos-memory-requirements.lock
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV AVALONIA_TELEMETRY_OPTOUT=1
WORKDIR /workspaces/kronos
