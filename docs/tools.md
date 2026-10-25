# MCP tools

Parameters, output shapes and examples for the four tools the relay serves.

## Contents

- [`searxng_web_search`](#searxng_web_search)
- [`searxng_read_url`](#searxng_read_url)
- [`searxng_url_metadata`](#searxng_url_metadata)
- [`searxng_session_sources`](#searxng_session_sources)

## `searxng_web_search`

Execute a web search and return titles, URLs, and snippets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | **yes** | — | The search query |
| `num_results` | number | no | `10` | Number of results to return (max 20) |
| `pageno` | number | no | `1` | Result page number (max 100) |
| `categories` | string | no | general | Comma-separated SearXNG categories: `news`, `science`, `files`, `images`, etc. |
| `language` | string | no | `all` | Language code e.g. `en`, `de`, `fr` |
| `time_range` | string | no | — | Filter by recency: `day`, `month`, or `year` |
| `safesearch` | number | no | `0` | Safe-search level: `0` = off, `1` = moderate, `2` = strict |
| `engines` | string | no | instance default | Comma-separated SearXNG engine names to query, e.g. `wikipedia,github`. Names match the engine attribution on prior results, so an agent can re-query the backend that surfaced a promising hit. Input is lowercased and whitespace-trimmed; names the instance doesn't run are silently ignored by SearXNG (a query naming only unknown engines returns no results rather than an error) |

**Example — recent news in English:**
```json
{
  "query": "fusion energy breakthrough",
  "categories": "news",
  "language": "en",
  "time_range": "month",
  "num_results": 5
}
```

**Output shape.** Each result is rendered as a text block of the form:

    Title: Example article title
    URL: https://example.com/article
    Snippet: First sentence or two of the page…
    Engines: google, bing, duckduckgo

The `Engines` line is omitted when SearXNG didn't return the field (older SearXNG versions, or results from a single-engine configuration). The list reflects the engines that returned this URL, in the order SearXNG provides them. No score is computed on top — the agent is free to read engine count as a corroboration signal or ignore it.

## `searxng_read_url`

Fetch a URL and return its content. Handles HTML (converted to structured Markdown), PDF (text extracted via `pdf_oxide`), Office documents (DOCX, XLSX, PPTX, plus legacy DOC, XLS, PPT — converted to Markdown via `office_oxide`), plain text (charset-decoded), and images (JPEG, PNG, GIF, WebP returned as MCP `ImageContent` blocks for vision-model consumption — SVG is intentionally excluded, since it is more useful to the model as text than as a base64-encoded binary blob). Caches results by default; image responses bypass the text cache.

Long documents are paginated. Each response returns a window of at most 100,000 characters of the extracted text; when there is more, the response ends with a notice like `[content truncated — showing chars 0-100000 of 348211; call searxng_read_url again with start_index=100000 to continue]`. The full extracted text (up to `MAX_EXTRACTED_CHARS`) is cached on the first fetch, so follow-up pages are cache hits and cost no upstream request. Offsets in the notice are exact — the agent echoes them back verbatim; the server snaps any offset that would split a multibyte character and guarantees each page advances, so following continuation hints always terminates.

PDF text is delimited by `--- [PDF page N of M] ---` marker lines, one per page, so agents can answer "what's on page 47", cite page numbers, and orient themselves inside any pagination window. The markers are advisory: they sit inside the untrusted content fence, and a malicious PDF can embed lookalike text (see [SECURITY.md](SECURITY.md)). Office documents get no page markers — DOCX has no intrinsic pages (pagination is computed at render time, not stored in the file), so the Markdown headings preserved by the converter are the navigational anchors there; PPTX slides and XLSX sheets surface as heading breaks.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | string | **yes** | — | The URL to fetch (http/https only) |
| `force_refresh` | boolean | no | `false` | Bypass the cache and fetch a fresh copy |
| `start_index` | integer | no | `0` | Offset into the extracted text to start from. Use the value from a previous response's truncation notice |
| `max_chars` | integer | no | `100000` | Characters of extracted text to return in this response (ceiling: 100000) |

Both pagination parameters are ignored for image URLs, which are returned whole as image content blocks.

**Example — force a fresh fetch:**
```json
{
  "url": "https://example.com/article",
  "force_refresh": true
}
```

**Example — continue reading a long document from where the last response stopped:**
```json
{
  "url": "https://example.com/big-report.pdf",
  "start_index": 100000
}
```

## `searxng_url_metadata`

Fetch only the structured metadata for a URL — title, author, publish date, language, site name, description, image, categories, and tags — without returning the page body. For PDFs, `page_count` is also returned, so an agent can gauge whether a candidate is a 3-page memo or a 400-page report before committing to a full read (it is deliberately absent for Office documents: DOCX has no intrinsic page count, since pagination is computed at render time). Roughly an order of magnitude cheaper in tokens than `searxng_read_url`, and intended as a triage step before committing to read a candidate URL in full. Results are cached and the cache is shared with `searxng_read_url`: a metadata fetch followed by a content fetch (or vice versa) costs one upstream HTTP request, not two.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | string | **yes** | — | The URL to fetch metadata for (http/https only) |
| `force_refresh` | boolean | no | `false` | Bypass the cache and fetch a fresh copy |

**Example — triage three candidates before reading one in full:**
```json
{ "url": "https://example.com/article-a" }
{ "url": "https://example.com/article-b" }
{ "url": "https://example.com/article-c" }
```

**Output shape.** A JSON object with the curated metadata fields. Fields the extractor could not populate are omitted rather than rendered as empty strings or `null`, so the response is variable-shape; at minimum `url` is always present:

```json
{
  "url": "https://example.com/article",
  "title": "Example article title",
  "author": "Jane Doe",
  "description": "First paragraph or meta-description.",
  "site_name": "Example.com",
  "date": "2026-03-12T14:23:00Z",
  "language": "en",
  "image": "https://example.com/article/cover.jpg",
  "categories": ["technology"],
  "tags": ["distributed-systems", "go"]
}
```

**When to use this vs `searxng_read_url`.** Use `searxng_url_metadata` to triage which of several candidate URLs is worth reading in full, for citation building, and for date/author/site verification when the body itself is not needed. Use `searxng_read_url` once you've committed to reading a specific URL. The two tools share a cache, so triaging with metadata first and then reading the chosen URLs in full does not double the upstream load.

## `searxng_session_sources`

Return the URLs this relay has fetched for the calling identity, newest first, byte-exact.

The problem it addresses is not retrieval — it is transcription. A model composing a final answer containing ten URLs is reproducing them from context that scrolled past thousands of tokens earlier, token by token, with nothing to check against. That step happens after the last tool call, in a message no MCP server ever sees, so nothing on the wire can validate it. This tool moves the correct bytes back to the position immediately before the answer is written, which is the only place a server can help. The same list answers the second failure — a plausible-looking URL for a page that was never fetched at all — because a URL absent from the list was not fetched.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `since_seq` | integer | no | `0` | Return only entries with a sequence number above this. Pass the highest `seq` from a previous call to see only what has been fetched since |

**Output shape.** A JSON object, one row per distinct URL rather than per fetch:

```json
{
  "note": "URLs below are byte-exact as fetched by this relay …",
  "total_fetches": 12,
  "returned": 9,
  "elided": 0,
  "sources": [
    {
      "url": "https://www.example.com/psu/flex-atx-350w",
      "requested_url": "https://example.com/psu/flex-atx-350w",
      "title": "FlexATX 350W review",
      "read": "full",
      "outcome": "ok",
      "chars_read": 18422,
      "total_chars": 18422,
      "fetched_at": "2026-08-18T09:14:02Z",
      "tool": "searxng_read_url",
      "seq": 12,
      "fetches": 2
    }
  ]
}
```

`read` is the field that distinguishes a source an agent may claim to have read from one it merely looked at: `full` (the whole extracted text), `partial` (one pagination window of a longer document), `metadata` (`searxng_url_metadata` only — the body was never returned), `image`, or `none` (the fetch failed). Failed fetches appear with `outcome: "error"` and the error text; omitting them would make a 404 indistinguishable from a URL never tried. `requested_url` appears only when a redirect moved the URL, and the post-redirect `url` is the one to cite — it is the only URL in the exchange the model never saw and so cannot reconstruct at all.

**Repeat fetches fold into one row.** A URL fetched more than once — triaged with metadata and then read, paged through a window at a time, or re-read after the cache expired — keeps a single row, and `fetches` counts the calls behind it. The row then reports the *deepest* read ever reached for that URL and the high-water mark of `chars_read` / `total_chars`: a later metadata-only call does not un-read a page already read in full, and a re-fetch that fails does not erase the copy that was returned. The recency fields (`seq`, `fetched_at`, `tool`, `from_cache`) always describe the most recent fetch, which is what `since_seq` and the newest-first ordering are asking about.

**History scope.** Per caller (identity + session ID), in-memory, the 50 most recent *sources* (`MCP_HISTORY_ENTRIES`). Slots hold sources rather than fetches — a six-window read of one long document costs one slot, not six — so the cap is a count of things you might cite, not of tool calls. Sources dropped to make room are reported as an `elided` count; `total_fetches` keeps counting calls, so it legitimately exceeds the number of rows. Keying on identity as well as session matters: under `MCP_STATELESS=true` the conversation half is client-asserted (and empty for a client that sends no `Mcp-Session-Id`), and in the documented sessionless configuration it is empty for everyone — keying on it alone would let one caller read another's fetched URLs. In stateless mode a client rotating that header also mints cache keys freely and can push other callers' ledgers out of the 1,000-entry cache; that is a degradation rather than a leak, and `mcp_history_callers_evicted_total` is what makes it visible. History does not survive a restart and does not cross replicas — it only needs to outlive the conversation, and shared storage would widen it to "everything this identity ever fetched", which makes the list worse for its purpose rather than better. For multi-replica deployments, configure session affinity at the ingress.

**Fence encoding.** This response is wrapped in a `<sec:fence>` carrying `encoding="cdata"`. The ordinary escaped fence turns every `&` into `&amp;`, which for a payload whose entire purpose is byte-exact URLs is a self-inflicted corruption channel — and query-string-dense URLs hit it on nearly every entry. The signature still covers the pre-encoding bytes exactly as on the escaped path; `encoding` is inside the canonical signed form, so a verifier can tell how to recover them and an attacker cannot flip it. The rating stays `untrusted`: the relay authors the assertion ("I fetched X at T") but not the values — titles come from fetched pages — and marking it trusted would let any site launder text into a trusted fence by being fetched once.
