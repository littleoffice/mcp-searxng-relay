package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Images reach a vision model without a fence, so searxng_read_url returns
// them only where FETCH_ALLOW_IMAGES turns them on.

// pngBytes is the 8-byte PNG signature, enough for a Content-Type test.
var pngBytes = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// lastAccept holds the Accept header the origin last saw.  The race detector
// cannot see the socket between handler and test, so it is locked.
type lastAccept struct {
	mu sync.Mutex
	v  string
}

func (a *lastAccept) get() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}

func newImageServer(t *testing.T, allowImages bool) (*Server, string, *lastAccept) {
	t.Helper()
	accept := &lastAccept{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept.mu.Lock()
		accept.v = r.Header.Get("Accept")
		accept.mu.Unlock()
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(pngBytes)
	}))
	t.Cleanup(origin.Close)
	u, _ := url.Parse(origin.URL)
	acl, err := newFetchACL([]string{u.Host}, nil)
	if err != nil {
		t.Fatalf("newFetchACL: %v", err)
	}
	s := NewServer(Config{
		CacheMaxEntries:   4,
		CacheTTL:          time.Minute,
		MaxExtractedChars: 1000,
		MaxImageBytes:     1000,
		HistoryEntries:    4,
		FetchACL:          acl,
		AllowImages:       allowImages,
	})
	return s, origin.URL + "/picture.png", accept
}

func TestReadURL_ImagesOffByDefault(t *testing.T) {
	s, target, accept := newImageServer(t, false)
	_, _, err := s.toolReadURL(context.Background(), nil, fetchInput{URL: target})
	if !errors.Is(err, errImageDisabled) {
		t.Fatalf("err = %v, want errImageDisabled", err)
	}
	if strings.Contains(accept.get(), "image/") {
		t.Errorf("Accept header still asks for images: %q", accept.get())
	}
	if got := reasonCount(&s.metrics, "image_disabled"); got != 1 {
		t.Errorf("image_disabled reason = %d, want 1", got)
	}
}

func TestReadURL_ImagesWhenAllowed(t *testing.T) {
	s, target, accept := newImageServer(t, true)
	res, _, err := s.toolReadURL(context.Background(), nil, fetchInput{URL: target})
	if err != nil {
		t.Fatalf("toolReadURL: %v", err)
	}
	img, ok := res.Content[0].(*mcp.ImageContent)
	if !ok || img.MIMEType != "image/png" {
		t.Fatalf("content = %#v, want a PNG image block", res.Content[0])
	}
	if !strings.Contains(accept.get(), "image/") {
		t.Errorf("Accept header does not ask for images: %q", accept.get())
	}
}

func TestReadURLDescription_MentionsImagesOnlyWhenOn(t *testing.T) {
	if d := buildReadURLDescription(false, provenanceEnforce); strings.Contains(d, "image blocks") {
		t.Errorf("description offers images while they are off: %q", d)
	}
	if d := buildReadURLDescription(true, provenanceOff); !strings.Contains(d, "image blocks") {
		t.Errorf("description omits images while they are on: %q", d)
	}
}
