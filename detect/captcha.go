package detect

import "strings"

// CaptchaHit is a CAPTCHA widget identified in the page body.
type CaptchaHit struct {
	Vendor   string
	Type     string
	Mode     string
	Evidence []string
}

type captchaSig struct {
	vendor string
	any    []string
	refine func(body string) (ctype, mode string)
}

// captchaSignatures match documented, public CAPTCHA widget markers.
var captchaSignatures = []captchaSig{
	{
		vendor: "Google reCAPTCHA",
		any:    []string{"g-recaptcha", "recaptcha/api", "recaptcha/enterprise", "gstatic.com/recaptcha", "www.google.com/recaptcha", "recaptcha.net", "grecaptcha"},
		refine: func(b string) (string, string) {
			switch {
			case strings.Contains(b, "recaptcha/enterprise") || strings.Contains(b, "grecaptcha.enterprise"):
				return "recaptcha_enterprise", "managed"
			case strings.Contains(b, "?render=") || strings.Contains(b, ".execute("):
				return "recaptcha_v3", "score"
			case strings.Contains(b, `data-size="invisible"`) || strings.Contains(b, "data-size='invisible'"):
				return "recaptcha_v2", "invisible"
			default:
				return "recaptcha_v2", "checkbox"
			}
		},
	},
	{vendor: "hCaptcha", any: []string{"hcaptcha.com", "h-captcha"}, refine: func(b string) (string, string) {
		if strings.Contains(b, "invisible") {
			return "hcaptcha", "invisible"
		}
		return "hcaptcha", "checkbox"
	}},
	{vendor: "Cloudflare Turnstile", any: []string{"challenges.cloudflare.com/turnstile", "cf-turnstile"}, refine: func(b string) (string, string) {
		switch {
		case strings.Contains(b, "interaction-only"):
			return "turnstile", "invisible"
		case strings.Contains(b, "non-interactive"):
			return "turnstile", "non_interactive"
		default:
			return "turnstile", "managed"
		}
	}},
	{vendor: "Arkose Labs (FunCaptcha)", any: []string{"arkoselabs.com", "funcaptcha"}, refine: func(string) (string, string) { return "arkose_funcaptcha", "puzzle_slider" }},
	{vendor: "GeeTest", any: []string{"geetest", "gcaptcha4", "initgeetest"}, refine: func(b string) (string, string) {
		if strings.Contains(b, "gcaptcha4") {
			return "geetest_v4", "puzzle_slider"
		}
		return "geetest_v3", "puzzle_slider"
	}},
	{vendor: "AWS WAF CAPTCHA", any: []string{"token.awswaf.com", "captcha.awswaf.com", "gokuprops"}, refine: func(string) (string, string) { return "aws_waf_captcha", "puzzle_slider" }},
	{vendor: "Friendly Captcha", any: []string{"friendlycaptcha.com", "frc-captcha"}, refine: func(string) (string, string) { return "friendly_captcha", "proof_of_work" }},
	{vendor: "Tencent Captcha", any: []string{"turing.captcha.qcloud.com", "tencentcaptcha"}, refine: func(string) (string, string) { return "tencent_captcha", "puzzle_slider" }},
	{vendor: "NetEase Yidun", any: []string{"dun.163.com", "yidun"}, refine: func(string) (string, string) { return "netease_yidun", "puzzle_slider" }},
	{vendor: "Alibaba slider", any: []string{"x5secdata"}, refine: func(string) (string, string) { return "alibaba_slider", "puzzle_slider" }},
	{vendor: "Anubis (PoW)", any: []string{"anubis_challenge", "within.website/x/cmd/anubis"}, refine: func(string) (string, string) { return "anubis_pow", "proof_of_work" }},
}

// detectCAPTCHA scans a lowercased body for CAPTCHA widget markers.
func detectCAPTCHA(bodyLower string) []CaptchaHit {
	var hits []CaptchaHit
	for _, c := range captchaSignatures {
		for _, m := range c.any {
			if strings.Contains(bodyLower, m) {
				ctype, mode := "", ""
				if c.refine != nil {
					ctype, mode = c.refine(bodyLower)
				}
				hits = append(hits, CaptchaHit{Vendor: c.vendor, Type: ctype, Mode: mode, Evidence: []string{"body:" + m}})
				break
			}
		}
	}
	return hits
}
