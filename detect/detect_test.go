package detect

import (
	"net/http"
	"strings"
	"testing"
)

// mk builds a synthetic Probe so Classify can be tested without network.
func mk(status int, headers map[string]string, cookies []string, body string) *Probe {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, strings.ToLower(c))
	}
	return &Probe{
		URL: "https://x.test", FinalURL: "https://x.test", Status: status,
		Header: h, CookieNames: names, Body: body, bodyLower: strings.ToLower(body),
	}
}

func hasVendor(r *Result, v string) bool {
	for _, d := range r.Protections {
		if d.Vendor == v {
			return true
		}
	}
	return false
}

func TestCloudflareChallenge(t *testing.T) {
	r := Classify(mk(403, map[string]string{"cf-ray": "abc", "cf-mitigated": "challenge"}, nil, "<html>Just a moment...</html>"))
	if !hasVendor(r, "Cloudflare") {
		t.Fatalf("expected Cloudflare, got %+v", r.Protections)
	}
	if r.BlockReason != "bot_challenge" {
		t.Errorf("block=%s want bot_challenge", r.BlockReason)
	}
	if !r.Protected {
		t.Error("want protected")
	}
	if r.DifficultyBand != "hard" {
		t.Errorf("band=%s want hard", r.DifficultyBand)
	}
}

func TestAkamaiBotManagerSuppressesEdge(t *testing.T) {
	r := Classify(mk(200, map[string]string{"akamai-grn": "0.x", "server": "AkamaiGHost"}, []string{"_abck", "bm_sz"}, strings.Repeat("x", 2000)))
	if !hasVendor(r, "Akamai Bot Manager") {
		t.Fatal("want Akamai Bot Manager")
	}
	if hasVendor(r, "Akamai (edge)") {
		t.Error("edge should be suppressed when Bot Manager is present")
	}
	if r.PrimaryVendor != "Akamai Bot Manager" {
		t.Errorf("primary=%s want Akamai Bot Manager", r.PrimaryVendor)
	}
}

func TestPlainEasy(t *testing.T) {
	r := Classify(mk(200, nil, nil, strings.Repeat("<p>hello world</p>", 500)))
	if r.Protected {
		t.Error("want not protected")
	}
	if r.DifficultyBand != "easy" {
		t.Errorf("band=%s want easy", r.DifficultyBand)
	}
	if r.BlockReason != "ok" {
		t.Errorf("block=%s want ok", r.BlockReason)
	}
}

// BIG-IP load-balancer cookies must NOT be read as F5 Shape bot management.
func TestBigIPLoadBalancerNotDetected(t *testing.T) {
	r := Classify(mk(200, nil, []string{"BIGipServer_pool", "f5_cspm"}, strings.Repeat("x", 2000)))
	if hasVendor(r, "F5 Shape") {
		t.Error("BIG-IP LB cookie must not be detected as F5 Shape bot management")
	}
}

func TestDataDomeForbidden(t *testing.T) {
	r := Classify(mk(403, map[string]string{"x-datadome": "1"}, []string{"datadome"}, "blocked"))
	if !hasVendor(r, "DataDome") {
		t.Fatal("want DataDome")
	}
	if r.BlockReason != "forbidden" {
		t.Errorf("block=%s want forbidden", r.BlockReason)
	}
	if r.DifficultyBand != "very_hard" {
		t.Errorf("band=%s want very_hard", r.DifficultyBand)
	}
	if r.PrimaryVendor != "DataDome" {
		t.Errorf("primary=%s want DataDome", r.PrimaryVendor)
	}
}

func TestKasadaClosedVM(t *testing.T) {
	r := Classify(mk(429, map[string]string{"x-kpsdk-ct": "tok"}, []string{"kp_uidz"}, "blocked"))
	if !r.CustomVM {
		t.Error("want CustomVM for Kasada")
	}
	if r.DifficultyBand != "closed_vm" {
		t.Errorf("band=%s want closed_vm", r.DifficultyBand)
	}
}

func TestRecaptchaEnterpriseTyping(t *testing.T) {
	body := strings.Repeat("x", 1600) + `<div class="g-recaptcha"></div><script src="https://www.google.com/recaptcha/enterprise.js"></script>`
	r := Classify(mk(200, nil, nil, body))
	if len(r.CaptchaTypes) == 0 || r.CaptchaTypes[0] != "recaptcha_enterprise" {
		t.Errorf("captcha=%v want [recaptcha_enterprise]", r.CaptchaTypes)
	}
}

func TestPaymentRequired402(t *testing.T) {
	r := Classify(mk(402, map[string]string{"cf-ray": "z"}, nil, "payment required"))
	if r.BlockReason != "payment_required" {
		t.Errorf("block=%s want payment_required", r.BlockReason)
	}
}

func TestUnreachable(t *testing.T) {
	p := &Probe{URL: "https://x.test", Status: 0}
	r := Classify(p)
	if r.Reachable {
		t.Error("want not reachable")
	}
	if r.BlockReason != "unreachable" || r.DifficultyBand != "unknown" {
		t.Errorf("got block=%s band=%s", r.BlockReason, r.DifficultyBand)
	}
}
