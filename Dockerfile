# syntax=docker/dockerfile:1
# Bosun engine + web UI. Runs as nonroot on a distroless base (no shell, no package manager).
# Base images are pinned by digest; Dependabot/Renovate bumps them.

FROM node:26-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY web/ ./
RUN npm run build

FROM rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml LICENSE bosun.toml.example ./
COPY crates/ crates/
COPY --from=web /src/web/dist /src/web/dist
ENV BOSUN_WEB_DIST=/src/web/dist
RUN cargo build --release --locked -p bosun \
 && install -D -m 0755 target/release/bosun /out/bosun \
 && install -d -m 0700 /out/data

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.title="Bosun" \
      org.opencontainers.image.description="Free, low-footprint intercepting proxy and DAST toolkit" \
      org.opencontainers.image.source="https://github.com/MacLeodTech/Bosun" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/bosun /usr/local/bin/bosun
COPY --from=build --chown=65532:65532 /out/data /data
COPY --chown=65532:65532 docker/bosun.toml /etc/bosun/bosun.toml
ENV BOSUN_CONFIG=/etc/bosun/bosun.toml BOSUN_DATA_DIR=/data
USER 65532:65532
VOLUME ["/data"]
# 8080 proxy, 8090 web UI/API.
EXPOSE 8080 8090
ENTRYPOINT ["/usr/local/bin/bosun"]
CMD ["serve"]
