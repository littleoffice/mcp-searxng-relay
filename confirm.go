package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── Asking the user ───────────────────────────────────────────────────────────
//
// A tool asks the user through a multi round-trip request (SEP-2322): it
// returns an input-required result carrying an elicitation and an opaque
// state, the client asks the user and retries the call with the answer and
// the state.  On protocol versions before 2026-07-28 the SDK does the same
// round trip itself, eliciting from inside the call, so one code path serves
// both.  Calling ServerSession.Elicit from a tool handler is refused on the
// newer protocol, which is why the relay does not.
//
// The state is the relay's, and the client merely carries it, so it is
// authenticated: an HMAC under a per-process key over a nonce, an expiry and
// what was asked about (caller, tool and URL).  A retry whose state does not
// match the call it arrives with, has expired, or was used before is refused,
// so a confirmation covers exactly the fetch the user was shown, once.

const (
	// confirmID names the one input request a confirmation carries.
	confirmID = "confirm"
	// confirmTTL is how long a confirmation request stays answerable.
	confirmTTL = 10 * time.Minute
)

// confirmations issues and redeems confirmation states.  The zero value is
// ready to use; the key is drawn on first use.
type confirmations struct {
	once sync.Once
	key  []byte

	mu   sync.Mutex
	used map[string]time.Time // nonce -> expiry, for single use
}

func (c *confirmations) init() {
	c.once.Do(func() {
		c.key = make([]byte, 32)
		if _, err := rand.Read(c.key); err != nil {
			panic("confirmation key: " + err.Error())
		}
	})
}

func (c *confirmations) mac(nonceExp []byte, binding string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte("mcp-searxng-relay confirm v1\x00"))
	m.Write(nonceExp)
	m.Write([]byte(binding))
	return m.Sum(nil)
}

// issue returns a state for a confirmation about binding.
func (c *confirmations) issue(binding string) string {
	c.init()
	nonceExp := make([]byte, 24)
	_, _ = rand.Read(nonceExp[:16])
	binary.BigEndian.PutUint64(nonceExp[16:], uint64(time.Now().Add(confirmTTL).Unix()))
	return base64.RawURLEncoding.EncodeToString(nonceExp) + "." +
		base64.RawURLEncoding.EncodeToString(c.mac(nonceExp, binding))
}

// redeem reports whether state was issued for binding, is unexpired, and has
// not been redeemed before.
func (c *confirmations) redeem(state, binding string) bool {
	c.init()
	a, b, ok := strings.Cut(state, ".")
	if !ok {
		return false
	}
	nonceExp, err1 := base64.RawURLEncoding.DecodeString(a)
	sig, err2 := base64.RawURLEncoding.DecodeString(b)
	if err1 != nil || err2 != nil || len(nonceExp) != 24 || !hmac.Equal(sig, c.mac(nonceExp, binding)) {
		return false
	}
	now := time.Now()
	exp := time.Unix(int64(binary.BigEndian.Uint64(nonceExp[16:])), 0)
	if now.After(exp) {
		return false
	}
	nonce := string(nonceExp[:16])
	c.mu.Lock()
	defer c.mu.Unlock()
	for n, e := range c.used {
		if now.After(e) {
			delete(c.used, n)
		}
	}
	if _, seen := c.used[nonce]; seen {
		return false
	}
	if c.used == nil {
		c.used = make(map[string]time.Time)
	}
	c.used[nonce] = exp
	return true
}

// canElicit reports whether the client behind req declared elicitation
// support.  A client that did not, such as a fence gateway, cannot be asked.
func canElicit(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil {
		return false
	}
	p := req.Session.InitializeParams()
	return p != nil && p.Capabilities != nil && p.Capabilities.Elicitation != nil
}

// isConfirmationRetry reports whether req is the retry of a call that asked
// the user, carrying the answer.
func isConfirmationRetry(req *mcp.CallToolRequest) bool {
	return req != nil && req.Params != nil && (req.Params.RequestState != "" || req.Params.InputResponses != nil)
}

// confirmationAnswer returns the user's answer in a retry: whether they
// accepted, and the form content.  A missing or malformed answer is a decline.
func confirmationAnswer(req *mcp.CallToolRequest) (accepted bool, content map[string]any) {
	res, ok := req.Params.InputResponses[confirmID].(*mcp.ElicitResult)
	if !ok || res == nil {
		return false, nil
	}
	return res.Action == "accept", res.Content
}

// askResult is the input-required result that asks the user message, with
// state to be echoed back.
func askResult(message string, schema map[string]any, state string) *mcp.CallToolResult {
	if schema == nil {
		schema = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{
			confirmID: &mcp.ElicitParams{Mode: "form", Message: message, RequestedSchema: schema},
		},
		RequestState: state,
	}
}
