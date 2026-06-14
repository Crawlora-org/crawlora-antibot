// Package detect is the open anti-bot / WAF detector behind crawlora-antibot.
//
// It performs ONE passive HTTP GET and classifies, from the response alone,
// which protection vendor fronts a site, why a request was stopped, and a
// rough difficulty estimate. Everything here works from public response
// fingerprints — it never logs in, submits a form, solves a challenge, or
// attempts to bypass anything. The real, *measured* difficulty (running the
// live escalating-transport fleet per URL) is a separate hosted capability;
// see the api package and the --difficulty flag.
package detect

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultUserAgent is a current Chrome UA — the honest "what a basic cloud
	// scraper sees" vantage used by the public Anti-Bot Adoption Index.
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	// DefaultTimeout is the per-request timeout.
	DefaultTimeout = 15 * time.Second
	maxBody        = 80 * 1024 // capped body slice, like the index scanner
)

// Detection is one vendor (or CAPTCHA) found on a site.
type Detection struct {
	Vendor          string   `json:"vendor"`
	Kind            Kind     `json:"kind"`
	Confidence      string   `json:"confidence"`       // high | medium | low
	ConfidenceScore int      `json:"confidence_score"` // 0..100
	Evidence        []string `json:"evidence"`
	CustomVM        bool     `json:"custom_vm,omitempty"`
	VMVendor        string   `json:"vm_vendor,omitempty"`
	CaptchaType     string   `json:"captcha_type,omitempty"`
	CaptchaMode     string   `json:"captcha_mode,omitempty"`
}

// Result is the full local classification of one URL.
type Result struct {
	URL             string      `json:"url"`
	FinalURL        string      `json:"final_url,omitempty"`
	Status          int         `json:"status"`
	Reachable       bool        `json:"reachable"`
	Protected       bool        `json:"protected"`
	PrimaryVendor   string      `json:"primary_vendor,omitempty"`
	Protections     []Detection `json:"protections"`
	CaptchaTypes    []string    `json:"captcha_types,omitempty"`
	CustomVM        bool        `json:"custom_vm,omitempty"`
	BlockReason     string      `json:"block_reason"`
	DifficultyBand  string      `json:"difficulty_band"`  // easy|medium|hard|very_hard|blocked|closed_vm|unknown
	DifficultyScore int         `json:"difficulty_score"` // 0..10 (heuristic)
	AccessTier      string      `json:"access_tier"`      // T1..T5
	Approach        string      `json:"approach"`
	Heuristic       bool        `json:"heuristic"` // true => band/tier are a passive estimate, not a live measurement
	Error           string      `json:"error,omitempty"`
}

// ProbeOptions tune the single passive request.
type ProbeOptions struct {
	UserAgent string
	Timeout   time.Duration
}

// Probe is the captured response from one passive GET.
type Probe struct {
	URL         string
	FinalURL    string
	Status      int
	Header      http.Header
	CookieNames []string
	Body        string
	bodyLower   string
	Err         error
}

// Inspect is Fetch + Classify.
func Inspect(ctx context.Context, url string, opt ProbeOptions) *Result {
	return Classify(Fetch(ctx, url, opt))
}

// Fetch performs one passive GET (real Chrome UA, follows redirects, capped body).
func Fetch(ctx context.Context, url string, opt ProbeOptions) *Probe {
	if opt.UserAgent == "" {
		opt.UserAgent = DefaultUserAgent
	}
	if opt.Timeout == 0 {
		opt.Timeout = DefaultTimeout
	}
	p := &Probe{URL: url, FinalURL: url, Header: http.Header{}}

	rctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if err != nil {
		p.Err = err
		return p
	}
	req.Header.Set("User-Agent", opt.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := (&http.Client{Timeout: opt.Timeout}).Do(req)
	if err != nil {
		p.Err = err
		return p
	}
	defer resp.Body.Close()

	p.Status = resp.StatusCode
	p.Header = resp.Header
	if resp.Request != nil && resp.Request.URL != nil {
		p.FinalURL = resp.Request.URL.String()
	}
	for _, c := range resp.Cookies() {
		p.CookieNames = append(p.CookieNames, strings.ToLower(c.Name))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	p.Body = string(body)
	p.bodyLower = strings.ToLower(p.Body)
	return p
}

var (
	loginPathRe = regexp.MustCompile(`(?i)/(login|log-in|signin|sign-in|authwall|account/login|users/sign_in)(/?$|[?#])`)
	cfErrorRe   = regexp.MustCompile(`error[^0-9]{0,6}(1\d{3})`)
)

var challengeMarkers = []string{
	"just a moment", "cf-chl", "/cdn-cgi/challenge-platform", "checking your browser",
	"verifying you are human", "attention required", "captcha-delivery", "enable javascript and cookies",
}

// contentful reports whether the response looks like real page content (vs a
// challenge/block shell). Body markers are only trusted when NOT contentful.
func contentful(p *Probe) bool {
	if p.Status < 200 || p.Status >= 300 || len(p.Body) < 1500 {
		return false
	}
	for _, m := range challengeMarkers {
		if strings.Contains(p.bodyLower, m) {
			return false
		}
	}
	return true
}

func confFromScore(s int) string {
	switch {
	case s >= 85:
		return "high"
	case s >= 50:
		return "medium"
	default:
		return "low"
	}
}

func matchSignature(p *Probe, s Signature, isContentful bool) (int, []string) {
	score := 0
	var ev []string
	for _, h := range s.Headers {
		if p.Header.Get(h) != "" {
			score += 90
			ev = append(ev, "header:"+h)
		}
	}
	for h, subs := range s.HeaderContains {
		v := strings.ToLower(p.Header.Get(h))
		if v == "" {
			continue
		}
		for _, sub := range subs {
			if strings.Contains(v, sub) {
				score += 60
				ev = append(ev, h+"~"+sub)
				break
			}
		}
	}
	for _, c := range s.Cookies {
		for _, name := range p.CookieNames {
			if strings.HasPrefix(name, c) {
				score += 70
				ev = append(ev, "cookie:"+c)
				break
			}
		}
	}
	for _, sc := range s.Script {
		if strings.Contains(p.bodyLower, sc) {
			score += 30
			ev = append(ev, "script:"+sc)
		}
	}
	if !isContentful {
		for _, b := range s.Body {
			if strings.Contains(p.bodyLower, b) {
				score += 30
				ev = append(ev, "body:"+b)
			}
		}
	}
	if score > 100 {
		score = 100
	}
	return score, ev
}

// Classify turns a Probe into a Result using only the captured response.
func Classify(p *Probe) *Result {
	r := &Result{URL: p.URL, FinalURL: p.FinalURL, Status: p.Status, Protections: []Detection{}}
	if p.Err != nil {
		r.Error = p.Err.Error()
	}
	if p.Status == 0 {
		r.Reachable = false
		r.BlockReason = "unreachable"
		r.DifficultyBand = "unknown"
		r.AccessTier = "?"
		r.Heuristic = true
		r.Approach = "Site did not respond (timeout, DNS, or TLS error) — not necessarily blocked."
		return r
	}
	r.Reachable = true
	isCF := contentful(p)

	best := map[string]Detection{}
	present := map[string]bool{}
	for _, s := range Signatures {
		score, ev := matchSignature(p, s, isCF)
		if score <= 0 {
			continue
		}
		present[s.Vendor] = true
		d := Detection{
			Vendor: s.Vendor, Kind: s.Kind, ConfidenceScore: score,
			Confidence: confFromScore(score), Evidence: ev,
			CustomVM: s.CustomVM, VMVendor: s.VMVendor,
		}
		if cur, ok := best[s.Vendor]; !ok || score > cur.ConfidenceScore {
			best[s.Vendor] = d
		}
	}
	// Suppression (e.g. drop "Akamai (edge)" when "Akamai Bot Manager" is confirmed).
	for _, s := range Signatures {
		if s.SuppressedBy != "" && present[s.SuppressedBy] {
			delete(best, s.Vendor)
		}
	}
	// CAPTCHA widgets.
	for _, h := range detectCAPTCHA(p.bodyLower) {
		if h.Type != "" {
			r.CaptchaTypes = append(r.CaptchaTypes, h.Type)
		}
		best[h.Vendor] = Detection{
			Vendor: h.Vendor, Kind: KindCAPTCHA, Confidence: "medium", ConfidenceScore: 60,
			Evidence: h.Evidence, CaptchaType: h.Type, CaptchaMode: h.Mode,
		}
	}

	topScore := -1
	for _, d := range best {
		r.Protections = append(r.Protections, d)
		if d.CustomVM {
			r.CustomVM = true
		}
		if d.Kind == KindWAF || d.Kind == KindBotManagement {
			r.Protected = true
			s := d.ConfidenceScore
			if d.Kind == KindBotManagement {
				s++ // prefer bot management over edge WAF at equal score
			}
			if s > topScore {
				topScore = s
				r.PrimaryVendor = d.Vendor
			}
		}
	}
	sort.SliceStable(r.Protections, func(i, j int) bool {
		if r.Protections[i].ConfidenceScore != r.Protections[j].ConfidenceScore {
			return r.Protections[i].ConfidenceScore > r.Protections[j].ConfidenceScore
		}
		return r.Protections[i].Vendor < r.Protections[j].Vendor
	})

	r.BlockReason = classifyBlock(p, isCF)
	scoreHeuristic(r)
	return r
}

func classifyBlock(p *Probe, isCF bool) string {
	b := p.bodyLower
	cfCode := 0
	if m := cfErrorRe.FindStringSubmatch(b); m != nil {
		cfCode = atoi(m[1])
	}
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(b, s) {
				return true
			}
		}
		return false
	}

	// auth_required
	if p.Header.Get("WWW-Authenticate") != "" || loginPathRe.MatchString(p.FinalURL) {
		return "auth_required"
	}
	if !isCF && has("authwall", "sign in to continue", "log in to continue", "please log in", "please sign in", "login_required", "you must be logged in", "sign in to see") &&
		!has("captcha", "datadome", "are you a robot", "just a moment") {
		return "auth_required"
	}
	// geo_blocked
	if p.Status == 451 || cfCode == 1009 {
		return "geo_blocked"
	}
	if !isCF && has("not available in your country", "not available in your region", "not available in your location", "unavailable in your country", "unavailable in your region", "not available in your area") {
		return "geo_blocked"
	}
	// rate_limited
	if p.Status == 429 || cfCode == 1015 {
		return "rate_limited"
	}
	if !isCF && p.Status >= 400 && p.Status != 404 && has("rate limit", "ratelimited", "too many requests", "slow down", "being rate limited") {
		return "rate_limited"
	}
	// captcha_required
	if !isCF && has("g-recaptcha", "hcaptcha", "cf-turnstile", "funcaptcha", "px-captcha", "are you a robot", "captcha-delivery") {
		return "captcha_required"
	}
	// bot_challenge
	if !isCF && (strings.Contains(strings.ToLower(p.Header.Get("cf-mitigated")), "challenge") || cfCode == 1010 ||
		has("just a moment", "cf-chl", "checking your browser", "verifying you are human", "attention required", "/cdn-cgi/challenge-platform", "enable javascript and cookies")) {
		return "bot_challenge"
	}
	// payment_required
	if p.Status == 402 {
		return "payment_required"
	}
	// ip_blocked
	if cfCode == 1005 || cfCode == 1006 || cfCode == 1007 || cfCode == 1008 || cfCode == 1106 {
		return "ip_blocked"
	}
	if !isCF && has("your ip address", "your ip has been", "ip address has been blocked", "banned your ip", "your network has been") {
		return "ip_blocked"
	}
	// service_unavailable
	if p.Status >= 500 && p.Status <= 599 {
		return "service_unavailable"
	}
	// forbidden
	if p.Status == 999 || (p.Status >= 400 && p.Status < 500 && p.Status != 404) {
		return "forbidden"
	}
	if !isCF && has("your request has been blocked", "access denied", "you don't have permission to access", "you don't have permission to view") {
		return "forbidden"
	}
	// ok
	if isCF || (p.Status >= 200 && p.Status < 300) {
		return "ok"
	}
	if p.Status == 0 {
		return "unreachable"
	}
	return "other"
}

// scoreHeuristic estimates a difficulty band/tier from the single passive
// response, keyed off the block reason (a normal "ok" response vs an active
// challenge/block) rather than body length, so a short-but-valid 200 isn't
// mistaken for a block. It is explicitly a heuristic (Result.Heuristic = true);
// the measured tier comes from --difficulty (the hosted escalating engine).
func scoreHeuristic(r *Result) {
	r.Heuristic = true
	hasBot, hasWAF := false, false
	for _, d := range r.Protections {
		if d.Kind == KindBotManagement {
			hasBot = true
		}
		if d.Kind == KindWAF || d.Kind == KindBotManagement {
			hasWAF = true
		}
	}
	hasCaptcha := len(r.CaptchaTypes) > 0
	ok := r.BlockReason == "ok"
	blocked := r.BlockReason == "bot_challenge" || r.BlockReason == "captcha_required" ||
		r.BlockReason == "forbidden" || r.BlockReason == "ip_blocked" ||
		r.BlockReason == "rate_limited" || r.BlockReason == "geo_blocked" ||
		r.BlockReason == "payment_required"

	set := func(band string, score int, tier, approach string) {
		r.DifficultyBand, r.DifficultyScore, r.AccessTier, r.Approach = band, score, tier, approach
	}
	switch {
	case r.CustomVM:
		set("closed_vm", 10, "T5", "Signs every request with a closed in-browser JS VM. Generic transports can't mint a valid token — needs a real browser execution context (Crawlora's unblocker).")
	case r.BlockReason == "auth_required":
		set("auth", 0, "—", "Behind a sign-in wall — not public. Detect the wall; do not attempt to pass it.")
	case blocked && hasBot:
		set("very_hard", 8, "T4", "Bot management actively challenged a datacenter request. Needs a stealth/anti-detect browser + residential IP + human-like behavior.")
	case blocked:
		set("hard", 6, "T3", "A challenge/block was served. Needs a real headless browser (JS) and likely a better IP; an HTTP-only client gets a challenge shell.")
	case hasBot && ok:
		set("hard", 6, "T3", "Bot management is present but the page answered passively. Deep pages will likely need a headless browser or stealth — verify the exact URL.")
	case hasWAF && ok:
		set("medium", 3, "T2", "A managed WAF/CDN is present but answered passively. A matched browser-like TLS fingerprint usually gets through; a plain client may be blocked.")
	case hasCaptcha:
		set("hard", 6, "T3", "A CAPTCHA widget is present. The page may gate behind it — a browser (plus a CAPTCHA service) is typically required.")
	case !r.Protected && ok:
		set("easy", 1, "T1", "Plain HTTP works — a direct request returns clean data; no proxy or browser needed.")
	case r.BlockReason == "service_unavailable":
		set("medium", 3, "T2", "Server returned a 5xx — likely transient. Retry; if it persists it may be soft-blocking automated clients.")
	default:
		set("medium", 3, "T2", "Reachable; protection is unclear. A browser-like fingerprint is the safe default.")
	}
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }
