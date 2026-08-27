//! Rust MCP bridge for GhidraMCP.
//!
//! A **drop-in swap** for the Python bridge, not a rewrite. Both bridges
//! front the same Ghidra Java server, both discover their tools from that
//! server's `/mcp/schema`, and both expose them over MCP. Choosing between
//! them is a Dockerfile line.
//!
//! What this one adds, and the Python one does not have:
//!
//! - **PKCE** (RFC 7636, S256 only). The Python implementation has the
//!   OAuth2 shape but no `code_challenge` anywhere. An MCP client is a
//!   public client; without PKCE nothing binds an authorization code to the
//!   party that requested it.
//! - **Durable tokens.** `redb` instead of an in-process dict, so a restart
//!   is not indistinguishable from a credential compromise and a second
//!   replica is possible at all.
//! - **Constant-time bearer comparison.** The Java side already compares
//!   its token in constant time; this side must not be the weak half.
//!
//! What it deliberately does not add: any tool. Tools live on the Java
//! side and arrive through the schema. A bridge that hard-coded tools would
//! have to chase the Java side forever and would stop being a swap.

pub mod pkce;
pub mod schema;
pub mod store;
