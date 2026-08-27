# The Rust MCP bridge — an old/new swap, not a rewrite

## The swap

| | old | new |
|---|---|---|
| build | `docker build -f docker/Dockerfile .` | `docker build -f rust/Dockerfile .` |
| bridge | Python, FastMCP | Rust, `rmcp` 3.1.4 |
| Java server | unchanged | unchanged |
| tools | from `/mcp/schema` | from `/mcp/schema` |

Both bridges front the **same** Ghidra Java server and discover the **same**
tools from its self-describing `/mcp/schema`. Neither hand-maintains a tool
list. A tool added on the Java side appears in both with no change to
either — which is exactly what makes them swappable, and why this crate
adds no tools of its own.

## What the Rust side adds

**PKCE (RFC 7636, S256 only).** The Python OAuth reference
(`ada-oauth2-fastmcp`) has the right shape — RFC 8414 discovery,
`/oauth/authorize`, `/oauth/token`, `authorization_code` + `refresh_token` —
and `grep -ri code_challenge` over it returns nothing. An MCP client is a
**public client**: it cannot hold a secret, so PKCE is the only thing binding
an authorization code to the party that requested it. RFC 9700 makes it
mandatory; the MCP authorization spec requires it.

`plain` is refused rather than merely discouraged. It is legal per RFC 7636
§4.2 and defends against nothing — the challenge *is* the verifier — so
accepting it lets an attacker downgrade by simply asking. That is worse than
no PKCE: it looks protected and is not.

**Durable tokens.** `redb` (pure Rust) rather than `_tokens = {}`. An
in-process dict means every restart invalidates every token — a deploy is
indistinguishable from a credential compromise — and a second replica shares
nothing. Authorization codes are redeemed with an atomic remove-in-write-txn,
so single-use survives concurrent redemption; a check-then-delete pair loses
exactly the race an attacker holding an intercepted code wants.

**Constant-time bearer comparison** (`subtle`). The Java side already
compares its token in constant time; the bridge must not be the weak half.

## What it deliberately does not do

- **No tools.** They live on the Java side; see above.
- **No `GHIDRA_MCP_ALLOW_SCRIPTS` default.** Arbitrary code execution stays
  off. Sealing the channel authenticates *who* is calling; it says nothing
  about *what* the endpoint will run. Transport security and capability
  scoping are independent, and conflating them is the classic mistake.
- **No baked auth token.** The Java server refuses a non-loopback bind
  without `GHIDRA_MCP_AUTH_TOKEN`; a default in the image would defeat that
  guard.

## Status — honest

| piece | state |
|---|---|
| `pkce.rs` | **done**, 7 tests incl. the RFC 7636 Appendix B vector |
| `schema.rs` | **done**, 5 tests — `/mcp/schema` → MCP tool defs |
| `store.rs` | **written**, compiles; no tests yet |
| OAuth2 endpoints | **not written** — discovery/authorize/token handlers |
| `rmcp` server wiring | **not written** — `ToolRoute::new_dyn` + `StreamableHttpService` |
| Dockerfile | **written, never built** — no Docker daemon in this environment |

The `rmcp` API needed for the wiring is censused and confirmed: dynamic tool
registration is natively supported (`ToolRoute::new_dyn(Tool, closure)` takes
a runtime JSON schema, so the `#[tool]` proc-macro path — which could not see
a schema fetched at runtime — is not required), and
`StreamableHttpService` mounts into axum as an ordinary tower service. The
dependency tree carries zero `-sys` crates.

**The Dockerfile has never been built.** There is no Docker daemon in the
environment it was written in, so it is reviewed-but-unrun — the same
honest caveat `tesseract-rs` records for its own images. First real
`docker build` should be treated as the test it has not yet had.
