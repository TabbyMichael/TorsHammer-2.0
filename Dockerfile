# Tor's Hammer 2.0 — authorized slow-requests vulnerability testing tool.
# Build:  docker build -t torshammer .
# Run:    docker run --rm torshammer --help
# The base tag is pinned to a minor/patch release (not the floating
# python:3.12-slim) so rebuilds are reproducible; bump deliberately.
FROM python:3.12.11-slim-bookworm AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . && python -m compileall /usr/local/lib/python3.12/site-packages/torshammer

FROM python:3.12.11-slim-bookworm

# Build-time provenance (docker build --build-arg VERSION=2.0.0 --build-arg REVISION=$(git rev-parse HEAD))
ARG VERSION=2.0.0
ARG REVISION=unknown

LABEL org.opencontainers.image.title="torshammer"
LABEL org.opencontainers.image.description="Slow-requests DoS/vulnerability testing tool (authorized use only)"
LABEL org.opencontainers.image.licenses="GPL-2.0-or-later"
LABEL org.opencontainers.image.version=$VERSION
LABEL org.opencontainers.image.revision=$REVISION
LABEL org.opencontainers.image.source="https://github.com/TabbyMichael/TorsHammer-2.0"

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/torshammer /usr/local/bin/torshammer

# Non-root user: the tool must never run privileged by default.
RUN useradd --create-home --shell /usr/sbin/nologin tester
USER tester
WORKDIR /home/tester

ENTRYPOINT ["torshammer"]
CMD ["--help"]