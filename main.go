// crawlora-antibot detects which anti-bot / WAF vendor protects a website and
// how hard it is to scrape, from a single passive request. It is a detector,
// not a bypass. Optionally, --difficulty fetches the live MEASURED tier from
// Crawlora's hosted engine.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Crawlora-org/crawlora-antibot/api"
	"github.com/Crawlora-org/crawlora-antibot/detect"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

type output struct {
	*detect.Result
	Measured *api.Difficulty `json:"measured,omitempty"`
}

func main() {
	var (
		asJSON     = flag.Bool("json", false, "output JSON")
		difficulty = flag.Bool("difficulty", false, "also fetch the live MEASURED difficulty from the Crawlora API (needs an API key)")
		deep       = flag.Bool("deep", false, "exhaustive measured sweep (implies -difficulty, fast=false)")
		apiKey     = flag.String("api-key", os.Getenv("CRAWLORA_API_KEY"), "Crawlora API key (or env CRAWLORA_API_KEY)")
		apiBase    = flag.String("api-base", envOr("CRAWLORA_API_BASE", api.DefaultBaseURL), "Crawlora API base URL (or env CRAWLORA_API_BASE)")
		timeout    = flag.Duration("timeout", detect.DefaultTimeout, "per-request timeout for the local probe")
		ua         = flag.String("user-agent", detect.DefaultUserAgent, "User-Agent for the local probe")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("crawlora-antibot", version)
		return
	}
	urls := flag.Args()
	if len(urls) == 0 {
		usage()
		os.Exit(2)
	}
	useAPI := *difficulty || *deep

	ctx := context.Background()
	results := make([]output, 0, len(urls))
	for _, raw := range urls {
		u := normalizeURL(raw)
		res := detect.Inspect(ctx, u, detect.ProbeOptions{UserAgent: *ua, Timeout: *timeout})
		out := output{Result: res}
		if useAPI {
			if *apiKey == "" {
				fmt.Fprintln(os.Stderr, "warning: --difficulty needs an API key (set CRAWLORA_API_KEY or --api-key); showing the local heuristic only")
			} else if m, err := api.CheckDifficulty(ctx, *apiBase, *apiKey, u, !*deep, 90*time.Second); err != nil {
				fmt.Fprintln(os.Stderr, "api:", err)
			} else {
				out.Measured = m
			}
		}
		results = append(results, out)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		var v any = results
		if len(results) == 1 {
			v = results[0]
		}
		if err := enc.Encode(v); err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(1)
		}
		return
	}
	for i, out := range results {
		if i > 0 {
			fmt.Println()
		}
		printHuman(out)
	}
}

func printHuman(o output) {
	r := o.Result
	fmt.Println(r.URL)
	if r.FinalURL != "" && r.FinalURL != r.URL {
		fmt.Printf("  → %s\n", r.FinalURL)
	}
	if !r.Reachable {
		fmt.Printf("  unreachable    %s\n", firstNonEmpty(r.Error, "no response"))
		fmt.Printf("  note           %s\n", r.Approach)
		return
	}
	fmt.Printf("  status         %d\n", r.Status)
	switch {
	case r.PrimaryVendor != "":
		fmt.Printf("  protection     %s\n", r.PrimaryVendor)
	case r.Protected:
		fmt.Printf("  protection     (unidentified vendor)\n")
	default:
		fmt.Printf("  protection     none detected\n")
	}
	for _, d := range r.Protections {
		extra := ""
		if d.CaptchaType != "" {
			extra = " " + d.CaptchaType
			if d.CaptchaMode != "" {
				extra += "/" + d.CaptchaMode
			}
		}
		if d.CustomVM {
			extra += " [closed VM]"
		}
		fmt.Printf("                 - %s (%s, %s)%s  [%s]\n", d.Vendor, d.Kind, d.Confidence, extra, strings.Join(d.Evidence, ", "))
	}
	fmt.Printf("  block reason   %s\n", r.BlockReason)
	fmt.Printf("  difficulty     %s (%d/10, %s) — heuristic\n", r.DifficultyBand, r.DifficultyScore, r.AccessTier)
	fmt.Printf("  approach       %s\n", r.Approach)

	if o.Measured != nil {
		m := o.Measured
		fmt.Println("  ── measured (Crawlora API) ──")
		fmt.Printf("  difficulty     %s (%d/10)  scrapeable=%v\n", m.DifficultyBand, m.DifficultyScore, m.Scrapeable)
		if m.RecommendedProfile != "" {
			fmt.Printf("  recommended    %s\n", m.RecommendedProfile)
		}
		if m.RecommendedApproach != "" {
			fmt.Printf("  approach       %s\n", m.RecommendedApproach)
		}
		if m.BlockReason != "" {
			fmt.Printf("  block reason   %s\n", m.BlockReason)
		}
	} else {
		fmt.Println("  (run with --difficulty for the live measured tier)")
	}
}

func normalizeURL(s string) string {
	if !strings.Contains(s, "://") {
		return "https://" + s
	}
	return s
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func usage() {
	fmt.Fprintf(os.Stderr, `crawlora-antibot %s — detect which anti-bot/WAF protects a site and how hard it is to scrape.

USAGE:
  crawlora-antibot [flags] <url> [url...]

EXAMPLES:
  crawlora-antibot example.com
  crawlora-antibot -json https://www.cloudflare.com
  CRAWLORA_API_KEY=... crawlora-antibot --difficulty https://www.g2.com

FLAGS:
`, version)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\nLocal detection is passive and offline. --difficulty calls Crawlora's hosted\n"+
		"engine for the live MEASURED tier. This tool DETECTS protection; it does not bypass it.\n"+
		"Docs & open dataset: https://crawlora.net/anti-bot-index\n")
}
