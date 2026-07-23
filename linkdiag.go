//go:build ignore

// linkdiag4 — narrows the prune selector.
//
// linkdiag3 showed a broad PruneSelector fixes content selection on The
// Register.  Broad selectors regress other sites, so this bisects it: each
// clause is tested alone, then the semantic-only subset, then the full set.
// The goal is the smallest selector that scores 1.00 everywhere.
//
// Also reports body-link counts so the residual "7 links vs 11 expected" gap
// can be checked once the right body is being selected.
//
//	go run linkdiag4.go '<register-article-url>' '<heise-article-url>' [more...]
//
// Use real ARTICLE urls, not section or index pages — the relevance score is
// derived from the URL slug and is meaningless for an index.
package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/markusmobius/go-trafilatura"
	"golang.org/x/net/html"
)

const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/126.0 Safari/537.36"

// Landmark elements. NOTE: <header> is NOT safe — <article><header><h1>…
// is standard HTML5 and pruning it decapitates the article (observed on
// heise). <footer> carries the same risk for tag/author blocks. Both are
// tested separately below rather than assumed.
const semanticSafe = `nav, aside, [role="complementary"]`

// Class-matching clauses: higher risk, tested individually.
var clauses = []struct{ name, sel string }{
	{"aside only", `aside`},
	{"nav only", `nav`},
	{"header only (RISKY)", `header`},
	{"footer only", `footer`},
	{"role=complementary", `[role="complementary"]`},
	{"most-popular classes", `[class*="most-popular"], [class*="mostpopular"], [class*="most_read"]`},
	{"sidebar classes", `[class*="sidebar"], [id*="sidebar"]`},
	{"related classes", `[class*="related"], [id*="related"]`},
	{"trending classes", `[class*="trending"]`},
	{"promo/teaser classes", `[class*="promo"], [class*="teaser"]`},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run linkdiag4.go <article-url> [<article-url>...]")
		os.Exit(2)
	}
	for _, t := range os.Args[1:] {
		run(t)
	}
	fmt.Println("\nPick the smallest selector that scores well AND keeps h1=yes")
	fmt.Println("on every URL. Any row with h1=NO is disqualified regardless of")
	fmt.Println("its score — it means the article lost its headline.")
}

func run(target string) {
	parsed, err := url.Parse(target)
	if err != nil {
		fmt.Println("bad url:", err)
		return
	}
	kw := slugKeywords(parsed)

	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("\n%s\n  fetch failed: %v\n", parsed.Host, err)
		return
	}
	defer resp.Body.Close()
	raw, err := html.Parse(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Println("parse failed:", err)
		return
	}

	fmt.Printf("\n===============================================================\n")
	fmt.Printf("%s%s\n", parsed.Host, parsed.Path)
	fmt.Printf("keywords: %s\n", strings.Join(kw, " "))
	fmt.Printf("===============================================================\n")
	headline := firstH1(raw)
	if headline == "" {
		fmt.Println("WARNING: no <h1> found — headline column unavailable")
	} else {
		fmt.Printf("h1: %s\n", headline)
	}
	fmt.Printf("%-26s %7s %6s %6s %3s  %s\n", "prune selector", "chars", "links", "score", "h1", "opening text")

	type row struct{ name, sel string }
	rows := []row{{"(none — current)", ""}}
	for _, c := range clauses {
		rows = append(rows, row{c.name, c.sel})
	}
	rows = append(rows,
		row{"SAFE LANDMARKS", semanticSafe},
		row{"safe + most-popular", semanticSafe + `, [class*="most-popular"], [class*="mostpopular"], [class*="most_read"]`},
		row{"safe + sidebar", semanticSafe + `, [class*="sidebar"], [id*="sidebar"]`},
		row{"FULL (regressed heise)", `nav, aside, footer, header, [role="complementary"], [class*="most-popular"], [class*="mostpopular"], [class*="most_read"], [class*="sidebar"], [class*="related"], [class*="trending"], [class*="promo"], [class*="teaser"], [id*="sidebar"], [id*="related"]`},
	)

	for _, r := range rows {
		opts := trafilatura.Options{
			OriginalURL:     parsed,
			ExcludeComments: true,
			Deduplicate:     true,
			EnableFallback:  true,
			IncludeLinks:    true,
			PruneSelector:   r.sel,
		}
		res, err := trafilatura.ExtractDocument(cloneDoc(raw), opts)
		if err != nil || res == nil {
			fmt.Printf("%-26s   ERROR %v\n", r.name, err)
			continue
		}
		text := strings.Join(strings.Fields(res.ContentText), " ")
		h1ok := "-"
		if headline != "" {
			h1ok = "NO"
			if strings.Contains(norm(text), norm(headline)) {
				h1ok = "yes"
			}
		}
		fmt.Printf("%-26s %7d %6d %6.2f %3s  %s\n",
			r.name, len(text), countAnchors(res.ContentNode), score(text, kw), h1ok, sample(text, 60))
	}
}

func slugKeywords(u *url.URL) []string {
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	best := ""
	for _, p := range parts {
		p = strings.TrimSuffix(p, ".html")
		if strings.Count(p, "-") >= strings.Count(best, "-") && len(p) > len(best) {
			best = p
		}
	}
	stop := map[string]bool{"the": true, "and": true, "for": true, "that": true,
		"with": true, "new": true, "its": true, "from": true, "has": true, "are": true}
	var out []string
	for _, w := range regexp.MustCompile(`[-_]+`).Split(strings.ToLower(best), -1) {
		if len(w) > 2 && !stop[w] && !regexp.MustCompile(`^\d+$`).MatchString(w) {
			out = append(out, w)
		}
	}
	return out
}

func score(text string, kw []string) float64 {
	if len(kw) == 0 {
		return -1
	}
	low := strings.ToLower(text)
	hit := 0
	for _, k := range kw {
		if strings.Contains(low, k) {
			hit++
		}
	}
	return float64(hit) / float64(len(kw))
}

// firstH1 returns the text of the first <h1> in the document — the headline
// a correct extraction must retain. A far sharper regression signal than
// slug keywords: losing it means the article was decapitated.
func firstH1(root *html.Node) string {
	var out string
	forEach(root, func(n *html.Node) {
		if out != "" || n.Type != html.ElementNode || n.Data != "h1" {
			return
		}
		var sb strings.Builder
		forEach(n, func(x *html.Node) {
			if x.Type == html.TextNode {
				sb.WriteString(x.Data)
				sb.WriteString(" ")
			}
		})
		out = strings.Join(strings.Fields(sb.String()), " ")
	})
	return out
}

func norm(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func cloneDoc(n *html.Node) *html.Node {
	var buf strings.Builder
	_ = html.Render(&buf, n)
	out, _ := html.Parse(strings.NewReader(buf.String()))
	return out
}

func forEach(n *html.Node, fn func(*html.Node)) {
	fn(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		forEach(c, fn)
	}
}

func countAnchors(root *html.Node) (n int) {
	if root == nil {
		return 0
	}
	forEach(root, func(x *html.Node) {
		if x.Type == html.ElementNode && x.Data == "a" {
			n++
		}
	})
	return
}

func sample(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
