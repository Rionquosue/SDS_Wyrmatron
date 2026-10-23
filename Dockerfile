# syntax=docker/dockerfile:1
# Cross-compiles on the build platform with cargo-zigbuild instead of
# emulating the target, then copies the static musl binary into Alpine.
ARG RUST_IMAGE=rust:1.97.0-alpine3.24@sha256:ec9c91e77119ce498cd1e87d96d77e0f75b2cee21655a29bc2bf75a51a2b20a4
ARG ALPINE_IMAGE=alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS build
ARG TARGETARCH
RUN apk add --no-cache musl-dev binutils python3 py3-pip \
 && pip install --no-cache-dir --break-system-packages ziglang==0.17.0 \
 && cargo install --locked cargo-zigbuild@0.24.0
WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && cargo zigbuild --release --locked --target "$target" \
 && mkdir -p /out \
 && cp "target/$target/release/wyrmatron" /out/wyrmatron \
 # The binary must be static: no dynamic section, no interpreter.
 && if readelf -d /out/wyrmatron | grep -q NEEDED || readelf -l /out/wyrmatron | grep -q INTERP; then \
      echo "wyrmatron is not statically linked" >&2; exit 1; \
    fi

FROM ${ALPINE_IMAGE}
RUN apk add --no-cache ca-certificates \
 && addgroup -g 10001 wyrmatron \
 && adduser -D -H -u 10001 -G wyrmatron wyrmatron \
 && mkdir -p /data /work /etc/wyrmatron \
 # New named volumes inherit this ownership.
 && chown wyrmatron:wyrmatron /data /work
COPY --from=build /out/wyrmatron /usr/local/bin/wyrmatron
USER 10001:10001
ENV WYRMATRON_CONFIG=/etc/wyrmatron/config.toml
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
 CMD ["/usr/local/bin/wyrmatron", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/wyrmatron"]
CMD ["serve"]
