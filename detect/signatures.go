package detect

// Kind classifies what a detected vendor does.
type Kind string

const (
	KindWAF           Kind = "waf"
	KindBotManagement Kind = "bot_management"
	KindCAPTCHA       Kind = "captcha"
	KindRateLimit     Kind = "rate_limit"
)

// Signature is a single vendor fingerprint built entirely from PUBLIC markers
// (vendor documentation + the open microlinkhq/is-antibot database). It answers
// "WHICH protection fronts this site" from one passive response — it is a
// detector, never a bypass.
//
// Matching is case-insensitive. Body/Script markers are only trusted on a
// challenge-shaped (non-contentful) response, so a vendor name in ordinary page
// text does not create a false positive.
type Signature struct {
	Vendor string
	Kind   Kind

	// Headers: response header names whose mere presence implies the vendor.
	Headers []string
	// HeaderContains: header name -> any of these lowercase substrings in its value.
	HeaderContains map[string][]string
	// Cookies: Set-Cookie name prefixes.
	Cookies []string
	// Body: substrings expected in a challenge/block page body.
	Body []string
	// Script: script-src / inline JS markers in the body.
	Script []string

	// CustomVM marks a closed in-browser JS VM that signs every request.
	CustomVM bool
	VMVendor string

	// SuppressedBy: if this other vendor is also detected, drop this one
	// (e.g. "Akamai (edge)" is dropped when "Akamai Bot Manager" matches).
	SuppressedBy string
}

// Signatures is the public vendor fingerprint database. Markers are documented,
// public facts — the same ones open tools like wafw00f and microlinkhq/is-antibot
// already match on.
var Signatures = []Signature{
	{
		Vendor: "Cloudflare", Kind: KindWAF,
		Headers:        []string{"cf-ray", "cf-mitigated"},
		HeaderContains: map[string][]string{"server": {"cloudflare"}},
		Cookies:        []string{"__cf_bm", "cf_clearance", "__cfduid", "__cfwaitingroom"},
		Body:           []string{"/cdn-cgi/challenge-platform", "cf-chl", "just a moment", "attention required"},
	},
	{
		Vendor: "DataDome", Kind: KindBotManagement,
		Headers: []string{"x-datadome", "x-dd-b", "x-datadome-cid"},
		Cookies: []string{"datadome"},
		Body:    []string{"datadome"},
		Script:  []string{"js.datadome.co", "captcha-delivery.com"},
	},
	{
		Vendor: "Akamai Bot Manager", Kind: KindBotManagement,
		Cookies: []string{"_abck", "bm_sz", "ak_bmsc", "bm_sv", "bm_mi"},
		Script:  []string{"bmak."},
	},
	{
		// Edge/CDN only — NOT bot management. Suppressed when Bot Manager is confirmed.
		Vendor: "Akamai (edge)", Kind: KindWAF,
		Headers:        []string{"x-akamai-transformed", "x-akamai-request-id", "akamai-grn", "x-akamai-session-info"},
		HeaderContains: map[string][]string{"server": {"akamaighost"}},
		SuppressedBy:   "Akamai Bot Manager",
	},
	{
		Vendor: "PerimeterX (HUMAN)", Kind: KindBotManagement,
		Headers: []string{"x-px", "x-perimeterx", "x-px-authorization"},
		Cookies: []string{"_px", "_pxhd", "_pxvid", "_pxff", "pxcts", "_px2", "_px3", "_pxde"},
		Body:    []string{"perimeterx", "px-captcha"},
		Script:  []string{"perimeterx.net", "client.perimeterx.com", "window._pxappid", "_pxaction", "pxinit"},
	},
	{
		Vendor: "Kasada", Kind: KindBotManagement,
		Headers:  []string{"x-kpsdk-ct", "x-kpsdk-cd", "x-kpsdk-v", "x-kasada-pow", "x-kasada", "x-kasada-challenge"},
		Cookies:  []string{"kp_uidz", "__kp"},
		Script:   []string{"__kasada", "kasada.js"},
		CustomVM: true, VMVendor: "kasada",
	},
	{
		Vendor: "Imperva (Incapsula)", Kind: KindWAF,
		Headers:        []string{"x-iinfo"},
		HeaderContains: map[string][]string{"x-cdn": {"incapsula", "imperva"}},
		Cookies:        []string{"incap_ses_", "visid_incap_", "nlbi_", "incap_count", "reese84"},
		Body:           []string{"incapsula incident id", "powered by incapsula"},
		Script:         []string{"/_incapsula_resource"},
	},
	{
		Vendor: "AWS WAF", Kind: KindWAF,
		Headers: []string{"x-amzn-waf-action"},
		Cookies: []string{"aws-waf-token"},
		Script:  []string{"token.awswaf.com"},
	},
	{
		Vendor: "Sucuri", Kind: KindWAF,
		Headers:        []string{"x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"},
		HeaderContains: map[string][]string{"server": {"sucuri"}},
		Cookies:        []string{"sucuri_cloudproxy_"},
		Body:           []string{"sucuri website firewall", "cloudproxy@sucuri.net"},
		Script:         []string{"cdn.sucuri.net"},
	},
	{
		// F5 Shape Security (bot management). NOTE: BIG-IP `BIGipServer*` / `f5_`
		// cookies are load-balancer persistence cookies and are deliberately NOT
		// matched — they are not bot defense.
		Vendor: "F5 Shape", Kind: KindBotManagement,
		Headers:  []string{"x-shape-original-url"},
		Cookies:  []string{"shape_"},
		CustomVM: true, VMVendor: "shape",
	},
	{
		Vendor: "Reblaze", Kind: KindBotManagement,
		HeaderContains: map[string][]string{"server": {"reblaze"}},
		Cookies:        []string{"rbzid", "rbzsessionid"},
	},
	{
		Vendor: "Barracuda", Kind: KindWAF,
		Cookies: []string{"barra_counter_session", "barracuda_", "bni__barracuda"},
	},
	{
		Vendor: "Citrix NetScaler", Kind: KindWAF,
		HeaderContains: map[string][]string{"via": {"ns-cache"}},
		Cookies:        []string{"ns_af", "citrix_ns_id", "nsc_"},
	},
	{
		Vendor: "Wallarm", Kind: KindWAF,
		HeaderContains: map[string][]string{"server": {"nginx-wallarm", "wallarm"}},
	},
	{
		Vendor: "Radware AppWall", Kind: KindWAF,
		Headers: []string{"x-sl-compstate"},
	},
	{
		Vendor: "Fastly (Signal Sciences)", Kind: KindBotManagement,
		Headers: []string{"x-sigsci-requestid", "x-sigsci-agentresponse", "x-sigsci-tags"},
	},
	{
		Vendor: "Vercel Security", Kind: KindWAF,
		HeaderContains: map[string][]string{"x-vercel-mitigated": {"challenge"}},
		Body:           []string{"vercel security checkpoint", "/vercel/security/"},
	},
	{
		Vendor: "DDoS-Guard", Kind: KindWAF,
		HeaderContains: map[string][]string{"server": {"ddos-guard"}},
		Cookies:        []string{"__ddg1", "__ddg2", "__ddgid", "__ddgmark"},
	},
	{
		Vendor: "Qrator", Kind: KindWAF,
		HeaderContains: map[string][]string{"server": {"qrator"}},
	},
	{
		Vendor: "Variti", Kind: KindBotManagement,
		HeaderContains: map[string][]string{"server": {"variti"}},
	},
	{
		Vendor: "Fortinet FortiWeb", Kind: KindWAF,
		Cookies: []string{"fortiwafsid"},
	},
	{
		Vendor: "Wordfence", Kind: KindWAF,
		Body: []string{"generated by wordfence", "wordfence blocking", "blocked by wordfence"},
	},
	{
		Vendor: "ModSecurity", Kind: KindWAF,
		HeaderContains: map[string][]string{"server": {"mod_security", "modsecurity"}},
		Body:           []string{"this error was generated by mod_security", "mod_security module"},
	},
	{
		Vendor: "TikTok (proprietary VM)", Kind: KindBotManagement,
		Headers:  []string{"x-bogus", "x-gnarly", "x-argus", "x-ladon"},
		Cookies:  []string{"ttwid", "mstoken", "s_v_web_id", "tt_csrf_token"},
		Script:   []string{"webmssdk", "byted_acrawler", "/webmssdk/", "frontiersign"},
		CustomVM: true, VMVendor: "tiktok",
	},
}
