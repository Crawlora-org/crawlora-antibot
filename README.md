# crawlora-antibot

**Detect which anti-bot / WAF protects a website — and how hard it is to scrape — from one passive request.**

`crawlora-antibot` is a small, dependency-free CLI (and Go library) that fingerprints a URL and tells you:

- **which protection vendor** fronts it (Cloudflare, Akamai, DataDome, PerimeterX/HUMAN, Imperva, Kasada, AWS WAF, …),
- **the CAPTCHA type** if one is present (reCAPTCHA v2/v3/Enterprise, Turnstile, hCaptcha, FunCaptcha, GeeTest, …),
- **why a request was stopped** (bot challenge vs 403 vs CAPTCHA vs 402 pay-per-crawl vs rate-limit vs geo vs login wall), and
- **a difficulty estimate** — roughly what tooling you'd need (plain HTTP → matched TLS → headless browser → stealth + residential → closed-VM).

It is a **detector, not a bypass.** It does one passive `GET`, reads the response, and classifies it. It never logs in, submits a form, solves a challenge, or tries to defeat anything.

> Detection runs **locally and open**, from public response fingerprints. For the *measured* difficulty — actually trying to reach the page across HTTP → browser → stealth tiers — add `--difficulty`, which calls [Crawlora](https://crawlora.net)'s hosted engine.

This powers, and is the open companion to, the public [**Anti-Bot Adoption Index**](https://crawlora.net/anti-bot-index).

> **Status:** pre-1.0. Signatures and the difficulty heuristic will keep evolving.

## Install

```sh
# from source (Go 1.23+)
go install github.com/Crawlora-org/crawlora-antibot@latest

# or clone + build
git clone https://github.com/Crawlora-org/crawlora-antibot
cd crawlora-antibot && go build -o crawlora-antibot .
```

Prebuilt binaries (Linux/macOS/Windows) are published via [GitHub Releases](https://github.com/Crawlora-org/crawlora-antibot/releases). (A Homebrew formula is coming.)

## Usage

```sh
crawlora-antibot [flags] <url> [url...]
```

```text
$ crawlora-antibot www.cloudflare.com
https://www.cloudflare.com
  status         200
  protection     Cloudflare
                 - Cloudflare (waf, high)  [header:cf-ray, server~cloudflare, cookie:__cf_bm]
  block reason   ok
  difficulty     medium (3/10, T2) — heuristic
  approach       A managed WAF/CDN is present but answered passively. A matched browser-like
                 TLS fingerprint usually gets through; a plain client may be blocked.
  (run with --difficulty for the live measured tier)
```

`--json` emits **NDJSON** (one compact object per line) — pipe straight into `jq -c` or a data pipeline.

**Batch / pipelines.** Pass many URLs as args, or pipe a list on stdin (one URL per line; blank lines and `#`-comments ignored). URLs are probed in parallel (`--concurrency`, default 8):

```sh
cat domains.txt | crawlora-antibot -json --concurrency 16 > results.ndjson
printf 'cloudflare.com\nreuters.com\n' | crawlora-antibot
```

### Measured difficulty (optional, hosted)

The local result is a **heuristic** from a single passive request, so it deliberately *over-estimates* (a vendor being present ≠ it actively blocking you). For the **measured** tier — what actually gets through — add `--difficulty`:

```sh
export CRAWLORA_API_KEY=...           # get one at https://crawlora.net
crawlora-antibot --difficulty example.com
#   difficulty     medium (3/10, T2) — heuristic      ← local guess
#   ── measured (Crawlora API) ──
#   difficulty     easy (1/10)  scrapeable=true        ← live measurement
#   recommended    direct
```

`--deep` runs the exhaustive sweep instead of stopping at the first transport that works.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output JSON (NDJSON — one object per line). |
| `--difficulty` | `false` | Also fetch the live **measured** difficulty from the Crawlora API (needs a key). |
| `--deep` | `false` | Exhaustive measured sweep (implies `--difficulty`). |
| `--api-key` | `$CRAWLORA_API_KEY` | Crawlora API key. |
| `--api-base` | `$CRAWLORA_API_BASE` or `https://api.crawlora.net/api/v1` | API base URL. |
| `--timeout` | `15s` | Per-request timeout for the local probe. |
| `--user-agent` | Chrome UA | User-Agent for the local probe. |
| `--concurrency` | `8` | URLs probed in parallel (batch mode). |
| `--version` | | Print version and exit. |

## How detection works

A single `GET` with a real Chrome User-Agent (follows redirects, 15s timeout, body capped at 80 KB). The response is matched against a database of **public, documented fingerprints** — the same kind of markers open tools like [`wafw00f`](https://github.com/EnableSecurity/wafw00f) and [`microlinkhq/is-antibot`](https://github.com/microlinkhq/is-antibot) use:

- **Header names** — `cf-ray` (Cloudflare), `x-datadome` (DataDome), `x-iinfo` (Imperva), `x-amzn-waf-action` (AWS WAF), `x-kpsdk-ct` (Kasada), `akamai-grn` (Akamai edge).
- **Set-Cookie name prefixes** — `__cf_bm`/`cf_clearance` (Cloudflare), `_abck`/`bm_sz` (Akamai Bot Manager), `datadome`, `_px*` (PerimeterX), `incap_ses_` (Imperva).
- **Body / script markers** — trusted only on a *challenge-shaped* response, so a vendor name in ordinary page text doesn't false-positive.

It deliberately distinguishes **Akamai Bot Manager** (`_abck`/`bm_*`) from plain **Akamai edge/CDN** (`akamai-grn`, `Server: AkamaiGHost`), and does **not** treat an F5 `BIGipServer*` load-balancer cookie as bot defense.

Detection is **passive and reproducible**, so it's a *lower bound*: homepages are more open than the deep pages you actually scrape, and a datacenter IP sees more challenges than a residential one. Use `--difficulty` for a real measurement of a specific URL.

## Use as a library

```go
import "github.com/Crawlora-org/crawlora-antibot/detect"

res := detect.Inspect(ctx, "https://www.example.com", detect.ProbeOptions{})
fmt.Println(res.PrimaryVendor, res.DifficultyBand, res.BlockReason)
```

## Scope & ethics

This tool **detects** protection on **public** pages to help you plan an authorized scrape — it does not bypass anything. Respect each site's Terms of Service and `robots.txt`, only collect data you're authorized to access, and never use it against pages behind a login.

## License

[MIT](LICENSE). Built by [Crawlora](https://crawlora.net).
See the open [Anti-Bot Adoption Index](https://crawlora.net/anti-bot-index) and [methodology](https://crawlora.net/anti-bot-index/methodology).
