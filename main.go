// crawlora-antibot detects which anti-bot / WAF vendor protects a website and
// how hard it is to scrape, from a single passive request. It is a detector,
// not a bypass. Optionally, --difficulty fetches the live MEASURED tier from
// Crawlora's hosted engine.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
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
		asJSON      = flag.Bool("json", false, "output JSON (NDJSON: one object per line)")
		difficulty  = flag.Bool("difficulty", false, "also fetch the live MEASURED difficulty from the Crawlora API (needs an API key)")
		deep        = flag.Bool("deep", false, "exhaustive measured sweep (implies -difficulty, fast=false)")
		apiKey      = flag.String("api-key", os.Getenv("CRAWLORA_API_KEY"), "Crawlora API key (or env CRAWLORA_API_KEY)")
		apiBase     = flag.String("api-base", envOr("CRAWLORA_API_BASE", api.DefaultBaseURL), "Crawlora API base URL (or env CRAWLORA_API_BASE)")
		timeout     = flag.Duration("timeout", detect.DefaultTimeout, "per-request timeout for the local probe")
		ua          = flag.String("user-agent", detect.DefaultUserAgent, "User-Agent for the local probe")
		concurrency = flag.Int("concurrency", 8, "number of URLs to probe in parallel (batch mode)")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("crawlora-antibot", version)
		return
	}

	urls := gatherURLs(flag.Args())
	if len(urls) == 0 {
		usage()
		os.Exit(2)
	}

	useAPI := *difficulty || *deep
	if useAPI && *apiKey == "" {
		fmt.Fprintln(os.Stderr, "warning: --difficulty needs an API key (set CRAWLORA_API_KEY or --api-key); showing the local heuristic only")
		useAPI = false
	}

	results := scanAll(context.Background(), urls, scanConfig{
		ua: *ua, timeout: *timeout, useAPI: useAPI, deep: *deep,
		apiKey: *apiKey, apiBase: *apiBase, concurrency: *concurrency,
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout) // compact + newline per record = NDJSON
		for _, o := range results {
			if err := enc.Encode(o); err != nil {
				fmt.Fprintln(os.Stderr, "encode:", err)
				os.Exit(1)
			}
		}
		return
	}
	for i, o := range results {
		if i > 0 {
			fmt.Println()
		}
		printHuman(o)
	}
}

type scanConfig struct {
	ua          string
	timeout     time.Duration
	useAPI      bool
	deep        bool
	apiKey      string
	apiBase     string
	concurrency int
}

// scanAll probes every URL (bounded parallelism) and returns results in input order.
func scanAll(ctx context.Context, urls []string, cfg scanConfig) []output {
	if cfg.concurrency < 1 {
		cfg.concurrency = 1
	}
	results := make([]output, len(urls))
	sem := make(chan struct{}, cfg.concurrency)
	var wg sync.WaitGroup
	for i, raw := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, raw string) {
			defer wg.Done()
			defer func() { <-sem }()
			u := normalizeURL(raw)
			res := detect.Inspect(ctx, u, detect.ProbeOptions{UserAgent: cfg.ua, Timeout: cfg.timeout})
			out := output{Result: res}
			if cfg.useAPI {
				if m, err := api.CheckDifficulty(ctx, cfg.apiBase, cfg.apiKey, u, !cfg.deep, 90*time.Second); err != nil {
					fmt.Fprintln(os.Stderr, "api:", u, "-", err)
				} else {
					out.Measured = m
				}
			}
			results[i] = out
		}(i, raw)
	}
	wg.Wait()
	return results
}

// gatherURLs collects URLs from args, and from stdin when a "-" arg is given or
// when stdin is piped and no positional URLs were passed (blank lines and
// #-comments are ignored).
func gatherURLs(args []string) []string {
	var urls []string
	readStdin := false
	for _, a := range args {
		if a == "-" {
			readStdin = true
			continue
		}
		urls = append(urls, a)
	}
	if readStdin || (len(urls) == 0 && stdinPiped()) {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			urls = append(urls, strings.Fields(line)[0]) // tolerate "url  # note"
		}
	}
	return urls
}

func stdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice == 0
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
  cat urls.txt | crawlora-antibot [flags]

EXAMPLES:
  crawlora-antibot example.com
  crawlora-antibot -json https://www.cloudflare.com
  CRAWLORA_API_KEY=... crawlora-antibot --difficulty https://www.g2.com
  cat domains.txt | crawlora-antibot -json --concurrency 16 > results.ndjson

FLAGS:
`, version)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, "\nLocal detection is passive and offline. --difficulty calls Crawlora's hosted\n"+
		"engine for the live MEASURED tier. This tool DETECTS protection; it does not bypass it.\n"+
		"Docs & open dataset: https://crawlora.net/anti-bot-index\n")
}
