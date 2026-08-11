# Job base image for the Forgejo Actions runner.
# Ubuntu (so actions/setup-python can provision Pythons) + Node 20
# (runtime required by JS actions such as checkout/setup-python) + git.
# Built locally with podman; no external registry needed.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates git curl xz-utils \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && node --version && git --version
