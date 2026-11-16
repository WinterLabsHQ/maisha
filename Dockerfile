# Turnkey Maisha: the CLI + MCP server with the free analyzers (cppcheck's MISRA
# addon + clang-tidy) and gcc (for the `compiler` analyzer) already installed, so
# `docker run` gives a working MISRA/CERT/BARR-C compliance stack with zero host setup.
FROM python:3.12-slim

# Free analyzers so the image is self-contained (native analyzer needs nothing).
# gcc backs the `compiler` analyzer (-fsyntax-only warning pass).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cppcheck clang-tidy gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Install only what the package needs to build/install (keeps the image lean).
# The [mcp] extra is included so `maishac serve` works inside the image.
COPY pyproject.toml README.md LICENSE /src/
COPY maishac /src/maishac
RUN pip install --no-cache-dir "/src[mcp]"

# Run as an unprivileged user (uid/gid 1000).
RUN groupadd --gid 1000 maisha \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin maisha

# Mount your project here: `docker run -v "$PWD:/work" ghcr.io/winterlabshq/maisha scan src/`
#
# VOLUME PERMISSIONS: Maisha keeps its memory in <project>/.maishac/ , so the
# mounted directory must be WRITABLE by the container user. With the default
# uid 1000 that works when your host user is also uid 1000. Otherwise run with
# your own ids so files written to the mount belong to you, not to root:
#   docker run --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/winterlabshq/maisha scan src/
# For a read-only mount (`-v "$PWD:/work:ro"`) point the memory elsewhere or scan
# with a writable copy; the scan cannot record findings into a read-only tree.
WORKDIR /work
USER maisha
ENTRYPOINT ["maishac"]
CMD ["--help"]
