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

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
}

func (r urlFetchResult) isImage() bool { return r.imageData != nil }

// ── Tool: read URL ────────────────────────────────────────────────────────────

type fetchInput struct {
	URL          string `json:"url" jsonschema:"the URL to fetch"`
	ForceRefresh bool   `json:"force_refresh,omitempty" jsonschema:"bypass the cache and fetch a fresh copy (default: false)"`
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

	fenced, err := s.wrapFence(result.text, FenceTypeContent, FenceUntrusted, in.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap fence: %w", err)
	}
	slog.Info("fetch completed",
		"url", in.URL, "kind", "text",
		"identity", identityFromContext(ctx),
		"session_id", sessionIDOf(req))
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fenced}},
	}, nil, nil
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
				return urlFetchResult{text: entry.content, metadata: entry.metadata}, nil
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
	// so operators can tune them independently.
	var bodyLimit int64
	switch {
	case isImage(contentType, targetURL):
		bodyLimit = s.config.MaxImageBytes
	case isPDF(contentType, targetURL):
		bodyLimit = s.config.MaxPDFBytes
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
	metadata := URLMetadata{URL: targetURL}

	switch {
	case isPDF(contentType, targetURL):
		s.metrics.FetchPDF.Add(1)
		content, err = extractPDF(body)
		if err != nil {
			return urlFetchResult{}, fmt.Errorf("failed to extract PDF text: %w", err)
		}
	case isPlainText(contentType):
		// Plain-text responses can declare a non-UTF-8 charset just like HTML
		// (e.g. text/plain; charset=ISO-8859-1).  Decode before stringifying
		// so the model doesn't get malformed UTF-8.
		s.metrics.FetchPlain.Add(1)
		body = toUTF8(body, contentType)
		content = truncateBytes(strings.TrimSpace(string(body)), "\n\n[content truncated]", maxRenderedChars)
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
		content = renderMarkdown(contentNode)
		metadata = extractedMeta
	}

	slog.Info("url fetched", "url", targetURL,
		"content_type", contentType,
		"bytes_raw", len(body),
		"chars_extracted", len(content))

	s.cache.Add(targetURL, cacheEntry{
		content:   content,
		metadata:  metadata,
		expiresAt: time.Now().Add(s.cacheTTL),
	})
	return urlFetchResult{text: content, metadata: metadata}, nil
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

// extractPDF extracts plain text from a PDF byte slice using pdf_oxide.
// The Rust core guarantees zero panics and zero timeouts across all inputs,
// so no subprocess, goroutine wrapper, or recover() block is needed.
// Scanned/image-only PDFs return sparse or empty output — OCR is out of scope.
func extractPDF(body []byte) (string, error) {
	doc, err := pdfoxide.OpenFromBytes(body)
	if err != nil {
		return "", fmt.Errorf("could not open PDF: %w", err)
	}

	defer func() { _ = doc.Close() }()

	text, err := doc.ExtractAllText()
	if err != nil {
		return "", fmt.Errorf("could not extract PDF text: %w", err)
	}

	result := strings.TrimSpace(text)
	return truncateBytes(result, "\n\n[content truncated]", maxRenderedChars), nil
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
