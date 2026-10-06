# syntax=docker/dockerfile:1.7

FROM rust:1.99.0-bookworm AS builder
WORKDIR /src
COPY . .
# target/ is a cache mount, so it vanishes after this RUN: copy the binaries
# out in the same step.
# Touch our sources first: cargo decides freshness by mtime, and a cached
# target/ can hold fingerprints newer than the copied files, silently shipping
# a stale binary. Dependencies stay cached; only our crates rebuild.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find crates -type f -exec touch {} + \
 && cargo build --release --locked \
      --bin recognito-broker \
      --bin recognito-controller \
 && mkdir -p /out \
 && cp target/release/recognito-broker target/release/recognito-controller /out/

# cc-debian12 ships glibc, libgcc and the CA bundle; both binaries verify TLS
# against the platform trust store.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /out/recognito-broker /out/recognito-controller /usr/local/bin/
# Numeric, not `nonroot`: with runAsNonRoot the kubelet must be able to prove
# the user is not root, and it cannot from a name.
USER 65532:65532
# Manifests set `command` explicitly; this default only makes `docker run` useful.
ENTRYPOINT ["/usr/local/bin/recognito-broker"]
