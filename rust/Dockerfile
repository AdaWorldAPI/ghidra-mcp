# The Rust MCP bridge — the "new" half of the old/new swap.
#
# Old:  docker build -f docker/Dockerfile .        (Java server + Python bridge)
# New:  docker build -f rust/Dockerfile .          (Java server + Rust bridge)
#
# Both front the SAME Ghidra Java server and discover the SAME ~251 tools
# from its /mcp/schema. Nothing about the Java side changes; this image
# swaps only the bridge process. That is the point — a bridge that
# hard-coded tools would have to chase the Java side forever and would not
# be swappable.

# ── builder ──────────────────────────────────────────────────────────────
FROM rust:1.98.1-bookworm AS builder
WORKDIR /src

# Dependency layer first, so a source edit does not re-fetch the tree.
COPY rust/ghidra-mcp-rs/Cargo.toml ./ghidra-mcp-rs/
RUN mkdir -p ghidra-mcp-rs/src && echo "fn main() {}" > ghidra-mcp-rs/src/main.rs \
    && echo "" > ghidra-mcp-rs/src/lib.rs \
    && cargo build --release --manifest-path ghidra-mcp-rs/Cargo.toml 2>/dev/null || true

COPY rust/ghidra-mcp-rs/ ./ghidra-mcp-rs/
RUN cargo build --release --manifest-path ghidra-mcp-rs/Cargo.toml \
    && strip ghidra-mcp-rs/target/release/ghidra-mcp-rs || true

# ── runtime ──────────────────────────────────────────────────────────────
# Slim glibc, no Python, no JVM. The Java server is a SEPARATE container
# (docker/Dockerfile) or a separate host process; this image is the bridge
# alone, which is what makes it swappable for the Python one.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --uid 10001 bridge
COPY --from=builder /src/ghidra-mcp-rs/target/release/ghidra-mcp-rs /usr/local/bin/ghidra-mcp-rs

# Durable token storage. MUST be a mounted volume in any real deployment:
# the whole point of redb over an in-process dict is that a restart is not
# indistinguishable from a credential compromise, and a container-local
# path throws that away on every redeploy.
RUN mkdir -p /data && chown bridge:bridge /data
VOLUME ["/data"]
ENV GHIDRA_MCP_TOKEN_DB=/data/tokens.redb

# Where the Ghidra Java server lives. Default is the loopback the Java side
# itself defaults to; override for a container-to-container deployment.
ENV GHIDRA_MCP_URL=http://127.0.0.1:8089/

# Bind. PORT is read at runtime and deliberately NOT pinned here — the
# platform injects it (the same convention every other Dockerfile in this
# org's stack uses).
ENV MCP_BIND=0.0.0.0

# NOT set, deliberately, and each absence is a decision:
#   GHIDRA_MCP_AUTH_TOKEN  — the Java server refuses a non-loopback bind
#                            without it; baking a default would defeat that.
#   GHIDRA_MCP_ALLOW_SCRIPTS — arbitrary code execution. Off is the only
#                            correct default for a network-reachable
#                            decompiler; sealing the channel authenticates
#                            WHO calls, never WHAT the endpoint will run.

USER bridge
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ghidra-mcp-rs"]
