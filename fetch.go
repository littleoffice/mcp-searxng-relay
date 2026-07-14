package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	officeoxide "github.com/yfedoseev/office_oxide/go"
	pdfoxide "github.com/yfedoseev/pdf_oxide/go"
	"golang.org/x/net/html/charset"
)

// ── URL fetch result ──────────────────────────────────────────────────────────

// urlFetchResult carries the outcome of a URL fetch.
//
// For text responses (HTML / PDF / plain): text is populated, and metadata
// carries the structured-metadata view the urlMetadata tool returns directly.
// For image responses: imageData / imageMimeType are populated, text is empty,
// and metadata is minimal (just URL) — images have no article-style metadata.
type urlFetchResult struct {
	text          string
	metadata      URLMetadata
	imageData     []byte
	imageMimeType string
	// truncated: text was cut at the MaxExtractedChars extraction cap.
	// Distinct from response-window truncation, which is applied later by
	// paginateContent and is recoverable via start_index.
	truncated bool
}

func (r urlFetchResult) isImage() bool { return r.imageData != nil }

// ── Tool: read URL ────────────────────────────────────────────────────────────

type fetchInput struct {
	URL          string `json:"url" jsonschema:"the URL to fetch"`
	ForceRefresh bool   `json:"force_refresh,omitempty" jsonschema:"bypass the cache and fetch a fresh copy (default: false)"`
	StartIndex   int    `json:"start_index,omitempty" jsonschema:"offset into the extracted text to start from (default: 0). When a response ends with a truncation notice, pass the start_index it suggests to continue reading. Ignored for image URLs"`
	MaxChars     int    `json:"max_chars,omitempty" jsonschema:"maximum characters of extracted text to return in this response (default and maximum: 100000). Ignored for image URLs"`
}

func (s *Server) toolReadURL(
	ctx context.Context,
	req *mcp.CallToolRequest,
	in fetchInput,
) (*mcp.CallToolResult, any, error) {
	if in.URL == "" {
		return nil, nil, fmt.Errorf("url argument is required")
	}
	s.metrics.FetchTotal.Add(1)

	result, err := s.readURL(ctx, in.URL, in.ForceRefresh)
	if err != nil {
		s.metrics.FetchErrors.Add(1)
		s.metrics.recordFetchByDomain(domainOf(in.URL), false)
		slog.Error("fetch failed",
			"url", in.URL, "error", err,
			"identity", identityFromContext(ctx),
			"session_id", sessionIDOf(req))
		return nil, nil, err
	}
	s.metrics.recordFetchByDomain(domainOf(in.URL), true)

	if result.isImage() {
		// ImageContent.Data takes raw bytes; the SDK base64-encodes during
		// JSON marshalling. No need to encode here.
		// Image responses are NOT fence-wrapped: the wrapper is a text-level
		// trust boundary, and binary image data has no equivalent injection
		// risk. Vision-model interpretation is out of scope for prompt fencing.
		slog.Info("fetch completed",
			"url", in.URL, "kind", "image",
			"identity", identityFromContext(ctx),
			"session_id", sessionIDOf(req))
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.ImageContent{
				Data:     result.imageData,
				MIMEType: result.imageMimeType,
			}},
		}, nil, nil
	}

	// Apply the response window.  The cache holds the full extracted text
	// (up to MaxExtractedChars); windowing happens here at response time,
	// so follow-up pages are cache hits and cost no upstream request.
	windowed, start, end, err := paginateContent(
		result.text, in.StartIndex, in.MaxChars,
		result.truncated, s.config.MaxExtractedChars)
	if err != nil {
		return nil, nil, err
	}

	fenced, err := s.wrapFence(windowed, FenceTypeContent, FenceUntrusted, in.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap fence: %w", err)
	}
	slog.Info("fetch completed",
		"url", in.URL, "kind", "text",
		"start_index", start, "end_index", end,
		"total_chars", len(result.text),
		"identity", identityFromContext(ctx),
		"session_id", sessionIDOf(req))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fenced}},
	}, nil, nil
}

// ── Response-window pagination ────────────────────────────────────────────────

// paginateContent cuts a window out of the full extracted text and appends
// the notices the agent needs to navigate the rest.
//
// Contract with the agent:
//
//   - Offsets are 0-based indices into the extracted text, exactly as
//     produced by extraction and stored in the cache. The agent never needs
//     to interpret them — it echoes back the start_index a truncation notice
//     suggests. (Internally they are byte offsets into UTF-8 text, snapped
//     to rune boundaries so a window never splits an encoded rune.)
//   - A window that ends before the end of the text always carries a notice
//     naming the exact continuation offset.
//   - Forward progress is guaranteed: the window always contains at least
//     one full rune, so following continuation hints always terminates even
//     for adversarially small max_chars values.
//   - extractionTruncated is only surfaced when the window reaches the end
//     of the kept text — before that it would be noise the agent can't act
//     on yet.
//
// start beyond the end of the text is an error (with the total included so
// the agent can recover); this can legitimately happen when the cache entry
// expired between pages and re-extraction yielded shorter content.
func paginateContent(text string, startIndex, maxChars int, extractionTruncated bool, extractionCap int) (windowed string, start, end int, err error) {
	total := len(text)

	start = startIndex
	if start < 0 {
		start = 0
	}
	if start > 0 {
		if start >= total {
			return "", 0, 0, fmt.Errorf(
				"start_index %d is beyond the end of the extracted content (%d chars total); the page may have changed since the previous fetch",
				start, total)
		}
		// Snap backwards to a rune boundary in case the agent invented an
		// offset rather than echoing one of ours.
		for start > 0 && !utf8.RuneStart(text[start]) {
			start--
		}
	}

	window := maxChars
	if window <= 0 || window > maxRenderedChars {
		window = maxRenderedChars
	}

	end = start + window
	if end >= total {
		end = total
	} else {
		for end > start && !utf8.RuneStart(text[end]) {
			end--
		}
		if end == start {
			// window was smaller than the first rune at start; include it
			// whole so the continuation offset always advances.
			_, size := utf8.DecodeRuneInString(text[start:])
			end = start + size
		}
	}

	body := text[start:end]
	var notes []string
	if end < total {
		notes = append(notes, fmt.Sprintf(
			"[content truncated — showing chars %d-%d of %d; call searxng_read_url again with start_index=%d to continue]",
			start, end, total, end))
	} else if start > 0 {
		notes = append(notes, fmt.Sprintf(
			"[showing chars %d-%d of %d — end of content]", start, end, total))
	}
	if end == total && extractionTruncated {
		notes = append(notes, fmt.Sprintf(
			"[note: the source document was longer than the server's extraction cap (%d chars); the remainder was not extracted. The operator can raise MAX_EXTRACTED_CHARS to capture more]",
			extractionCap))
	}
	if len(notes) > 0 {
		body = body + "\n\n" + strings.Join(notes, "\n")
	}
	return body, start, end, nil
}

// ── Tool: URL metadata ────────────────────────────────────────────────────────

type urlMetadataInput struct {
	URL          string `json:"url"                   jsonschema:"the URL to fetch metadata for"`
	ForceRefresh bool   `json:"force_refresh,omitempty" jsonschema:"bypass the cache and fetch a fresh copy (default: false)"`
}

// toolURLMetadata returns only the structured metadata for a URL: title,
// author, publish date, language, site name, description, categories, tags,
// and image.  The body is not returned — that is what searxng_read_url is
// for.  Typical usage: triage 10 search hits at ~10x less token cost than
// fetching their bodies, then call searxng_read_url for the 2-3 worth
// actually reading.
//
// Sharing the cache and the underlying readURL pipeline with the content
// tool means a metadata fetch followed by a content fetch (or vice versa)
// produces one upstream HTTP request, not two.
func (s *Server) toolURLMetadata(
	ctx context.Context,
	req *mcp.CallToolRequest,
	in urlMetadataInput,
) (*mcp.CallToolResult, any, error) {
	if in.URL == "" {
		return nil, nil, fmt.Errorf("url argument is required")
	}
	s.metrics.MetadataTotal.Add(1)

	result, err := s.readURL(ctx, in.URL, in.ForceRefresh)
	if err != nil {
		s.metrics.MetadataErrors.Add(1)
		s.metrics.recordFetchByDomain(domainOf(in.URL), false)
		slog.Error("metadata fetch failed",
			"url", in.URL, "error", err,
			"identity", identityFromContext(ctx),
			"session_id", sessionIDOf(req))
		return nil, nil, err
	}
	s.metrics.recordFetchByDomain(domainOf(in.URL), true)

	// Make sure URL is always populated — for non-HTML content types
	// the extractor never runs, so result.metadata may be zero apart
	// from what readURL set.
	payload := result.metadata
	if payload.URL == "" {
		payload.URL = in.URL
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	fenced, err := s.wrapFence(string(jsonBytes), FenceTypeData, FenceUntrusted, in.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap fence: %w", err)
	}
	slog.Info("metadata fetch completed",
		"url", in.URL,
		"has_title", payload.Title != "",
		"has_date", payload.Date != nil,
		"identity", identityFromContext(ctx),
		"session_id", sessionIDOf(req))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fenced}},
	}, nil, nil
}

// ── Shared fetch pipeline ─────────────────────────────────────────────────────

func (s *Server) readURL(ctx context.Context, targetURL string, forceRefresh bool) (urlFetchResult, error) {
	// Cache check — skipped when force_refresh is set.
	// The cache stores text + metadata together so that the read-url and
	// url-metadata tools share a single upstream fetch.  Image fetches
	// always bypass the text cache.
	if !forceRefresh {
		if entry, ok := s.cache.Get(targetURL); ok {
			if time.Now().Before(entry.expiresAt) {
				slog.Debug("cache hit", "url", targetURL)
				s.metrics.CacheHits.Add(1)
				return urlFetchResult{text: entry.content, metadata: entry.metadata, truncated: entry.truncated}, nil
			}
			s.cache.Remove(targetURL)
		}
		s.metrics.CacheMisses.Add(1)
	} else {
		slog.Debug("force refresh, bypassing cache", "url", targetURL)
		s.cache.Remove(targetURL)
		s.metrics.CacheForceRefresh.Add(1)
		s.metrics.CacheMisses.Add(1)
	}
	slog.Debug("cache miss, fetching", "url", targetURL)

	// Validate scheme before doing anything.
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return urlFetchResult{}, fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return urlFetchResult{}, fmt.Errorf("only http/https URLs are permitted")
	}

	// Use fetchClient (SSRF-safe DialContext + redirect validation).
	// Intentionally does NOT forward SearXNG basic-auth credentials to
	// arbitrary third-party hosts.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return urlFetchResult{}, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/*;q=0.8,*/*;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	resp, err := s.fetchClient.Do(req)
	if err != nil {
		return urlFetchResult{}, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return urlFetchResult{}, fmt.Errorf("URL returned HTTP %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")

	// Choose the body size limit based on content type.
	// Images get their own cap (MaxImageBytes) — large enough for high-res
	// photos that vision models can process, but separate from the PDF cap
	// so operators can tune them independently. Office documents get a
	// third cap so a slide deck full of embedded media doesn't compete
	// with the PDF budget.
	var bodyLimit int64
	switch {
	case isImage(contentType, targetURL):
		bodyLimit = s.config.MaxImageBytes
	case isPDF(contentType, targetURL):
		bodyLimit = s.config.MaxPDFBytes
	case officeFormat(contentType, targetURL) != "":
		bodyLimit = s.config.MaxOfficeBytes
	default:
		bodyLimit = s.config.MaxBodyBytes
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	if err != nil {
		return urlFetchResult{}, fmt.Errorf("failed to read response body: %w", err)
	}

	// ── Image path ────────────────────────────────────────────────────────────
	// Return raw bytes; the caller passes them to mcp.ImageContent.Data, which
	// the SDK base64-encodes during JSON marshalling.
	// Image results are never written to the text cache — the LRU is sized for
	// extracted text and storing large binary blobs would evict useful entries.
	if isImage(contentType, targetURL) {
		mimeType := imageMIMEType(contentType, targetURL)
		s.metrics.FetchImage.Add(1)
		slog.Info("image fetched", "url", targetURL,
			"mime_type", mimeType,
			"bytes", len(body))
		return urlFetchResult{
			imageData:     body,
			imageMimeType: mimeType,
			metadata:      URLMetadata{URL: targetURL},
		}, nil
	}

	// ── Text paths ────────────────────────────────────────────────────────────
	var content string
	var truncated bool
	metadata := URLMetadata{URL: targetURL}

	switch {
	case isPDF(contentType, targetURL):
		s.metrics.FetchPDF.Add(1)
		var pageCount int
		content, truncated, pageCount, err = extractPDF(body, s.config.MaxExtractedChars)
		if err != nil {
			return urlFetchResult{}, fmt.Errorf("failed to extract PDF text: %w", err)
		}
		metadata.PageCount = pageCount
	case officeFormat(contentType, targetURL) != "":
		// Office documents (DOCX/XLSX/PPTX + legacy DOC/XLS/PPT) render to
		// Markdown rather than flat text. The structural fidelity (headings,
		// tables, lists) is a meaningful uplift for retrieval/RAG callers,
		// and the Markdown path falls back to plain text inside the
		// extractor if it errors on a given file.
		//
		// Unlike the PDF path, no page/slide markers are inserted here.
		// office_oxide's Go binding exposes only whole-document extraction
		// (PlainText/ToMarkdown/ToIRJSON, no per-slide or per-sheet call),
		// and re-rendering markdown from the IR JSON ourselves would
		// duplicate the library's renderer for little gain.  The markdown
		// headings ToMarkdown already emits are the honest navigational
		// anchor anyway: DOCX has no intrinsic pages (page breaks are
		// computed by the renderer, not stored in the file), while PPTX
		// slides and XLSX sheets surface as heading breaks.
		format := officeFormat(contentType, targetURL)
		s.metrics.FetchOffice.Add(1)
		content, truncated, err = extractOffice(body, format, s.config.MaxExtractedChars)
		if err != nil {
			return urlFetchResult{}, fmt.Errorf("failed to extract %s text: %w", format, err)
		}
	case isPlainText(contentType):
		// Plain-text responses can declare a non-UTF-8 charset just like HTML
		// (e.g. text/plain; charset=ISO-8859-1).  Decode before stringifying
		// so the model doesn't get malformed UTF-8.
		s.metrics.FetchPlain.Add(1)
		body = toUTF8(body, contentType)
		content, truncated = clampChars(strings.TrimSpace(string(body)), s.config.MaxExtractedChars)
	default:
		// Decode to UTF-8 before HTML parsing so non-Latin pages render correctly.
		// Same toUTF8 helper is used for plain text above.
		s.metrics.FetchHTML.Add(1)
		body = toUTF8(body, contentType)

		contentNode, extractedMeta, extractErr := extractHTMLDocument(body, targetURL)
		if extractErr != nil {
			// Extraction failure is non-fatal: log and proceed with what
			// we have.  The metadata at minimum carries the URL.
			slog.Debug("html extraction failed",
				"url", targetURL, "error", extractErr)
		}
		content, truncated = renderMarkdown(contentNode, s.config.MaxExtractedChars)
		metadata = extractedMeta
	}

	slog.Info("url fetched", "url", targetURL,
		"content_type", contentType,
		"bytes_raw", len(body),
		"chars_extracted", len(content),
		"extraction_truncated", truncated)

	s.cache.Add(targetURL, cacheEntry{
		content:   content,
		metadata:  metadata,
		expiresAt: time.Now().Add(s.cacheTTL),
		truncated: truncated,
	})
	return urlFetchResult{text: content, metadata: metadata, truncated: truncated}, nil
}

// ── Encoding detection ────────────────────────────────────────────────────────

// maxCharsetExpansion is the maximum factor by which a charset conversion
// can expand the input when decoding to UTF-8. No known encoding exceeds 4x.
const maxCharsetExpansion = 4

// toUTF8 converts body to UTF-8 using the charset declared in the
// Content-Type header or sniffed from the HTML <meta> tag.
// If detection fails or the content is already UTF-8, body is returned as-is.
// The decoded output is capped at len(body)*maxCharsetExpansion bytes to
// prevent unbounded memory growth from pathological encodings.
func toUTF8(body []byte, contentType string) []byte {
	encoding, _, _ := charset.DetermineEncoding(body, contentType)
	decoded, err := io.ReadAll(
		io.LimitReader(encoding.NewDecoder().Reader(bytes.NewReader(body)), int64(len(body))*maxCharsetExpansion),
	)
	if err != nil {
		return body
	}
	return decoded
}

// ── PDF extraction ────────────────────────────────────────────────────────────

// isPDF returns true when the response looks like a PDF, either by MIME type
// or by file extension when the server omits a Content-Type.
func isPDF(contentType, rawURL string) bool {
	if strings.Contains(contentType, "application/pdf") {
		return true
	}
	u, err := url.Parse(rawURL)
	if err == nil && strings.HasSuffix(strings.ToLower(u.Path), ".pdf") {
		return true
	}
	return false
}

// isPlainText returns true when the Content-Type indicates plain text,
// such as raw files, READMEs, and .txt URLs.
func isPlainText(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "text/plain")
}

// pdfPageMarker is the navigational anchor inserted between PDF pages.  Its
// format is part of the tool's response contract: the read tool's description
// tells agents to look for these lines, so treat changes as breaking.
//
// The marker is server-generated but sits inside untrusted extracted content
// — a malicious PDF can embed text that imitates it.  Everything inside the
// content fence is untrusted by definition (see docs/SECURITY.md), so the
// markers are advisory: good enough for navigation and citation, not an
// integrity claim.  We deliberately do not rewrite lookalike lines in the
// page text; mutating untrusted content creates worse problems (silent
// corruption of quoted material) than the spoof it would prevent.
func pdfPageMarker(page, total int) string {
	return fmt.Sprintf("--- [PDF page %d of %d] ---", page, total)
}

// extractPDF extracts text from a PDF byte slice using pdf_oxide, page by
// page, inserting a pdfPageMarker line before each page so agents can answer
// "what's on page N" and cite page numbers.  Output is capped at maxChars;
// the boolean reports whether the cap cut anything.  pageCount is returned
// for the page_count metadata field regardless of truncation.
//
// Per-page extraction (ExtractText) uses the same tagged-PDF reading-order
// logic as the whole-document call it replaced, so text quality is
// unchanged; the loop just adds one FFI call per page at sub-millisecond
// per-document extraction speeds.  The Rust core guarantees zero panics and
// zero timeouts across all inputs, so no subprocess, goroutine wrapper, or
// recover() block is needed.  Scanned/image-only pages return sparse or
// empty output under their marker — OCR is out of scope.
func extractPDF(body []byte, maxChars int) (text string, truncated bool, pageCount int, err error) {
	doc, err := pdfoxide.OpenFromBytes(body)
	if err != nil {
		return "", false, 0, fmt.Errorf("could not open PDF: %w", err)
	}

	defer func() { _ = doc.Close() }()

	pageCount, err = doc.PageCount()
	if err != nil {
		return "", false, 0, fmt.Errorf("could not read PDF page count: %w", err)
	}

	var sb strings.Builder
	for i := 0; i < pageCount; i++ {
		// Stop extracting once the cap is already exceeded: on a
		// multi-hundred-page document with a small cap there is no point
		// paying FFI calls for pages that clampChars will discard anyway.
		// clampChars below still enforces the exact byte budget.
		if maxChars > 0 && sb.Len() > maxChars {
			truncated = true
			break
		}
		pageText, pageErr := doc.ExtractText(i)
		if pageErr != nil {
			return "", false, 0, fmt.Errorf("could not extract text from PDF page %d: %w", i+1, pageErr)
		}
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString(pdfPageMarker(i+1, pageCount))
		sb.WriteString("\n\n")
		sb.WriteString(strings.TrimSpace(pageText))
	}

	result, clamped := clampChars(strings.TrimSpace(sb.String()), maxChars)
	return result, truncated || clamped, pageCount, nil
}

// ── Office extraction ────────────────────────────────────────────────────────

// officeFormat returns the office_oxide format hint ("docx", "xlsx", "pptx",
// "doc", "xls", "ppt") for an office document response, or an empty string
// when the response is not a supported Office format.
//
// The check is Content-Type first, then URL extension fallback — same shape
// as isPDF/isImage. Modern OOXML files (.docx/.xlsx/.pptx) are ZIP archives
// with stable, registered MIME types; legacy Office (.doc/.xls/.ppt) are
// CFB/OLE containers whose MIME types are equally well-known. Servers do
// occasionally serve them as application/octet-stream or with no Content-Type
// at all, hence the extension fallback.
func officeFormat(contentType, rawURL string) string {
	// Strip parameters (e.g. "application/...; charset=...") before matching.
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return "docx"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return "xlsx"
	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return "pptx"
	case "application/msword":
		return "doc"
	case "application/vnd.ms-excel":
		return "xls"
	case "application/vnd.ms-powerpoint":
		return "ppt"
	}

	// Fall back to URL file extension when the server omits or mislabels
	// the Content-Type. This matches isPDF's behaviour and catches static
	// files served from S3/CDN endpoints that hand back octet-stream.
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := strings.ToLower(u.Path)
	switch {
	case strings.HasSuffix(path, ".docx"):
		return "docx"
	case strings.HasSuffix(path, ".xlsx"):
		return "xlsx"
	case strings.HasSuffix(path, ".pptx"):
		return "pptx"
	case strings.HasSuffix(path, ".doc"):
		return "doc"
	case strings.HasSuffix(path, ".xls"):
		return "xls"
	case strings.HasSuffix(path, ".ppt"):
		return "ppt"
	}
	return ""
}

// extractOffice extracts text from an Office document using office_oxide.
// Format is one of "docx", "xlsx", "pptx", "doc", "xls", "ppt" and is
// supplied by the caller (already resolved via officeFormat).
//
// Markdown is the primary output because the structural cues — headings,
// tables, list nesting — are exactly what retrieval/RAG callers want, and
// for XLSX in particular a Markdown table is dramatically more useful than
// the same data flattened to plain text. PlainText is a fallback: if the
// Markdown renderer trips on an unusual document, we still return something
// useful rather than failing the whole fetch.
//
// The Rust core provides the same panic-free, timeout-bounded guarantees
// as pdf_oxide — adversarial input returns an error rather than crashing
// the server process.
func extractOffice(body []byte, format string, maxChars int) (string, bool, error) {
	doc, err := officeoxide.OpenFromBytes(body, format)
	if err != nil {
		return "", false, fmt.Errorf("could not open %s document: %w", format, err)
	}
	defer func() { _ = doc.Close() }()

	text, err := doc.ToMarkdown()
	if err != nil {
		// Markdown failure is unusual but not fatal — fall back to plain
		// text. If that also fails, surface the underlying error so the
		// fetch tool returns a clear diagnostic rather than an empty body.
		var ptErr error
		text, ptErr = doc.PlainText()
		if ptErr != nil {
			return "", false, fmt.Errorf("could not extract %s text (markdown: %v; plain: %w)", format, err, ptErr)
		}
	}

	result, truncated := clampChars(strings.TrimSpace(text), maxChars)
	return result, truncated, nil
}

// ── Image detection ───────────────────────────────────────────────────────────

// isImage returns true when the response is a raster image type that vision
// models can process (JPEG, PNG, GIF, WebP).
//
// SVG is intentionally excluded — it is XML markup and is more useful to the
// model as plain text than as a base64-encoded binary blob.
// The check falls back to the URL file extension when the server omits a
// Content-Type, mirroring the same pattern used by isPDF.
func isImage(contentType, rawURL string) bool {
	return imageMIMEType(contentType, rawURL) != ""
}

// imageMIMEType returns the canonical MIME type for image responses, or an
// empty string if the content is not a supported image type.
// It first checks the Content-Type header, then falls back to the URL
// file extension.
func imageMIMEType(contentType, rawURL string) string {
	// Strip parameters (e.g. "image/jpeg; charset=...") before matching.
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "image/jpeg":
		return "image/jpeg"
	case "image/png":
		return "image/png"
	case "image/gif":
		return "image/gif"
	case "image/webp":
		return "image/webp"
	}

	// Fall back to URL file extension.
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path := strings.ToLower(u.Path)
	switch {
	case strings.HasSuffix(path, ".jpg"), strings.HasSuffix(path, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".gif"):
		return "image/gif"
	case strings.HasSuffix(path, ".webp"):
		return "image/webp"
	}
	return ""
}

// domainOf returns the lower-cased hostname for a URL, or "unknown" if the
// URL can't be parsed or has no host. Used as the label value for per-domain
// fetch metrics; defensive against junk input so a malformed URL can't break
// /metrics output.
func domainOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return strings.ToLower(u.Hostname())
}
