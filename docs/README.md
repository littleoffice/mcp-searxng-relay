# Documentation

Reference documentation for mcp-searxng-relay. The project overview, features and quick start are in the [top-level README](../README.md).

| Document | Contents |
|---|---|
| [Installation](installation.md) | Requirements, Docker Compose, building the image, Kubernetes, Claude Desktop |
| [Configuration](configuration.md) | Every environment variable; tokens, OAuth, session modes, rate limiting, engine scoping |
| [MCP tools](tools.md) | Parameters, output shapes and examples for each tool |
| [Architecture](architecture.md) | One search-then-read turn, step by step |
| [Security model](security-model.md) | Prompt injection, hidden-text removal, SSRF, authentication, hardening |
| [Prompt fencing](prompt-fencing.md) | Fence layout, the signed preamble, the signing key |
| [Operations](operations.md) | Caches, health checks, graceful shutdown, HTTP timeouts, TLS |
| [Logging and metrics](observability.md) | Startup banner, log fields, Prometheus series |
| [Caches](caching.md) | Inventory of every cache and bounded store, and how to size them |
| [Fence verification contract](fence-verification.md) | Normative wire format and verification procedure for verifiers |
| [Supply-chain statement](supply-chain.md) | Dependencies, build provenance, reproducibility, known gaps |
| [Security policy](SECURITY.md) | Supported versions and how to report a vulnerability |
