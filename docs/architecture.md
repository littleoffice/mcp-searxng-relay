# Architecture

The component overview and what each trust boundary enforces are in the [README](../README.md#architecture). This page follows one request through them.

## Communication

One search-then-read turn, with the optional verifying gateway in place. Without
a gateway, the client's arrows go straight to the relay and the verify step
simply does not happen.

```mermaid
sequenceDiagram
    autonumber
    participant M as MCP client
    participant G as fence-gateway
    participant R as mcp-searxng-relay
    participant S as SearXNG
    participant W as Web

    Note over G,R: once, at gateway start
    G->>R: GET /fence/public-key
    R-->>G: {publicKey, fingerprint, version}
    Note right of G: pin fingerprint, or TOFU

    M->>G: initialize
    G->>R: initialize (Authorization: Bearer …)
    R-->>G: Mcp-Session-Id
    G-->>M: capabilities

    M->>G: tools/call searxng_web_search
    G->>R: forward
    R->>S: GET /search?format=json&tokens=…
    S->>W: query enabled engines
    W-->>S: results
    S-->>R: JSON + unresponsive_engines
    Note right of R: WARN if degraded<br/>mcp_searches_degraded_total++
    R->>R: wrapFence(rating=untrusted, type=content)
    R-->>G: preamble + signed fence element
    G->>G: verify Ed25519 over<br/>domain ‖ len(C) ‖ C ‖ M
    alt signature valid
        G-->>M: result forwarded
    else invalid, -policy reject
        G-->>M: isError, content withheld
        Note right of G: fence.rejected → audit log
    end

    M->>G: tools/call searxng_read_url
    G->>R: forward
    R->>R: SSRF check at dial time,<br/>re-checked per redirect
    R->>W: GET url
    W-->>R: HTML / PDF / Office / image
    R->>R: extract → Markdown, cache,<br/>record in session history
    R-->>G: signed fence (escaped)
    G-->>M: verified content

    M->>G: tools/call searxng_session_sources
    G->>R: forward
    R-->>G: signed fence (encoding="cdata")
    Note over G: CDATA body is byte-exact —<br/>recover by concatenating sections,<br/>never by entity-unescaping
    G-->>M: verified source ledger
```

The last exchange is the one a verifier is most likely to get wrong, and the
reason [`docs/fence-verification.md`](fence-verification.md) exists: that
response carries `encoding="cdata"`, and a verifier that assumes the
entity-escaped form recovers different bytes than were signed and rejects a
perfectly good fence.

The diagram draws one fence per response for readability. Under the default
format 1.1 each of those responses carries two: the awareness preamble in its
own signed `rating="trusted"` fence, then the content fence — so the gateway
can enforce that no unsigned bytes reached the model at all. Under
`FENCE_PREAMBLE=prose` (format 1.0, for gateways that predate 1.1) the
preamble travels as unsigned prose ahead of the single fence instead. See
[Fenced awareness preamble](prompt-fencing.md#fenced-awareness-preamble), and the wire contract for what a
verifier must check across the pair.
