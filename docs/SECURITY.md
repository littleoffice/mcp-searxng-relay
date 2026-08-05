# Security Policy

This document describes how to report security issues in `mcp-searxng-relay` and
what to expect once you do. For the project's dependency, build-provenance, and
development-process statement — the "what am I actually trusting if I run this"
question — see [supply-chain.md](supply-chain.md).

This project is maintained by a single individual: the holder of the GitHub
account with admin rights on the repository. References to "the maintainer"
below mean that person. The codebase is primarily AI-generated and
human-reviewed; [supply-chain.md](supply-chain.md#development-process) describes
that process in full, and it is relevant context for how security reports are
handled — every fix, like every other change, is reviewed, built, and tested by
the maintainer before release.

## Supported versions

`1.0.0` is the first public release. The latest released version receives
security fixes. There is no backport window for older releases — if a fix
ships, it ships in a new release, and the expectation is that operators move
forward to it.

If you are running an untagged build from `main`, treat it as unsupported for
security purposes — pin to a release.

## Reporting a vulnerability

**Do not open a public issue for security problems.** Public issues are visible
to everyone, including before a fix exists.

Report privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the advisory form with as much detail as you can — affected version,
   reproduction steps, and the impact you believe it has.

This routes the report privately to the maintainer and gives both sides a shared
space to coordinate a fix and a disclosure timeline.

### What happens next

This is a single-maintainer project. It is honest to be plain about what that
means rather than promise a service level that cannot be backed:

- There is **no committed response time**. There is no team, no rotation, and no
  on-call.
- GitHub notifies the maintainer when a report is filed, so reports are *seen* —
  they do not vanish into an unwatched inbox.
- The maintainer will review and respond as soon as they are reasonably able,
  and will keep you informed once they have engaged with the report.
- You will be credited in the published advisory unless you ask not to be.

If that uncertainty is a problem for your environment, it is better to know
before adoption than after — and worth weighing against the fact that the
project is small enough that a report goes directly to the person who can act
on it, with no triage layer in between.

## Disclosure policy

The project follows coordinated disclosure:

1. You report the issue privately.
2. The maintainer confirms it and develops a fix.
3. A disclosure date is agreed with you. The aim is for disclosure to be
   reasonably prompt once a fix exists — the goal is to protect users, not to
   sit on findings — but no specific timeline is committed to in advance.
4. The fix ships in a tagged release, and a GitHub Security Advisory is
   published describing the issue, the affected versions, and the fix, crediting
   the reporter.

If an issue is already being exploited in the wild, the maintainer will move
faster and may disclose alongside the fix rather than waiting.

## Scope

**In scope** — report these here:

- The Go source code in this repository.
- The `Dockerfile` and the container image it produces, including the default
  configuration values baked into it.
- Cases where the documentation steers an operator toward an unsafe
  configuration, or where an unsafe configuration is too easy to reach by
  accident. Even if the configuration itself is "operator error," a footgun in
  the docs or defaults is a project bug.

**Out of scope** — please report these to the relevant upstream project
instead:

- **SearXNG itself.** This project is a client of SearXNG, not a fork of it.
  Vulnerabilities in SearXNG go to <https://github.com/searxng/searxng>.
- **Third-party dependencies** — the MCP Go SDK, `go-trafilatura`,
  `golang-lru`, `pdf_oxide`, `office_oxide`, `golang.org/x/net`, and their
  transitive dependencies. Report those to their respective projects. A
  heads-up here is still appreciated so the maintainer can pin or patch on
  this side, but the fix belongs upstream. The full dependency list is in
  [supply-chain.md](supply-chain.md).
- **Deployment-specific issues** arising from configurations the documentation
  explicitly warns against — for example, running the HTTP transport without a
  TLS-terminating reverse proxy in a non-local deployment, or exposing
  `/metrics` to untrusted networks. If the docs told you not to do it, that is
  not a project vulnerability. (But see the in-scope note above: if the docs
  *didn't* warn clearly enough, that gap is in scope.)

## Existing security posture

The project already addresses several classes of risk by design. A reviewer
evaluating it for a sensitive environment may find the following useful
starting points:

- **SSRF protection** for the URL-fetch tool — private and reserved IP ranges
  are rejected at TCP-dial time, and redirect chains are re-validated at every
  hop. See the "Security notes" section of the main `README.md`.
- **Bearer-token authentication** with a multi-token table and per-identity
  audit logging.
- **Cross-origin / CSRF protection** on the HTTP transport, applied by the
  go-sdk wrapper introduced as the fix for CVE-2026-33252. Browser-originated
  POSTs with cross-origin `Sec-Fetch-Site` / `Origin` headers, and POSTs
  without `Content-Type: application/json`, are rejected before reaching the
  MCP handler. Non-browser API clients (curl, Go `http.Client`, AI-agent
  traffic) are unaffected.
- **Per-caller rate limiting** on the HTTP transport, keyed by identity when
  authenticated and falling back to source IP otherwise. Defends against
  runaway agents and brute-force token guessing. Configurable per deployment;
  see the main `README.md` for the variables and tuning notes.
- **Prompt fencing** of all tool output, implementing the scheme from
  arXiv:2511.19727, with an honest statement of what that does and does not
  provide in the README. The Ed25519 signing key is per-process by default;
  deployments that run an external verifier can pin a persistent key via
  `FENCE_SIGNING_KEY` / `FENCE_SIGNING_KEY_FILE`, moving the trust anchor to
  the operator's own secret store.
- **PDF page markers are advisory.** The `--- [PDF page N of M] ---` lines
  inserted between extracted PDF pages are server-generated, but they sit
  inside untrusted extracted content: a malicious PDF can embed lookalike
  text to misrepresent where content appears in the document. The markers
  are navigational aids under the same trust status as everything else
  inside the content fence — not an integrity claim. The extractor
  deliberately does not rewrite lookalike lines in page text, because
  silently mutating untrusted content (and any material an agent later
  quotes from it) is a worse failure mode than the spoof it would prevent.
- **Dependency hygiene** — a deliberately small dependency tree, a pinned build
  toolchain, and a minimal `scratch`-based runtime image. Detailed in
  [supply-chain.md](supply-chain.md).

Pointing at these is not a claim that the project is free of vulnerabilities —
it is not, no project is. It is context for where the considered effort has
gone, so a reviewer knows what has already been thought about and what has not.
