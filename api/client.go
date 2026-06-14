// Package api is a thin client for Crawlora's hosted anti-bot check — the
// optional, MEASURED difficulty behind the --difficulty flag.
//
// The detection logic (package detect) runs locally and open. The live
// escalating-transport measurement (actually trying to reach the URL across
// HTTP → browser → stealth tiers) stays a hosted capability; this client just
// calls it.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultBaseURL is the public Crawlora REST base.
const DefaultBaseURL = "https://api.crawlora.net/api/v1"

// Difficulty is the measured result from POST /diagnostics/antibot-check.
type Difficulty struct {
	URL                 string      `json:"url"`
	DifficultyScore     int         `json:"difficulty_score"`
	DifficultyBand      string      `json:"difficulty_band"`
	Scrapeable          bool        `json:"scrapeable"`
	BlockReason         string      `json:"block_reason"`
	Enforcement         string      `json:"enforcement"`
	RecommendedProfile  string      `json:"recommended_profile"`
	RecommendedApproach string      `json:"recommended_approach"`
	EasiestTransport    string      `json:"easiest_working_transport"`
	Coverage            string      `json:"coverage"`
	CustomVM            bool        `json:"custom_vm"`
	VMVendor            string      `json:"vm_vendor"`
	CaptchaTypes        []string    `json:"captcha_types"`
	Summary             string      `json:"summary"`
	Protections         []Detection `json:"protections"`
}

// Detection mirrors a protection entry in the API response.
type Detection struct {
	Vendor          string   `json:"vendor"`
	Kind            string   `json:"kind"`
	Confidence      string   `json:"confidence"`
	ConfidenceScore int      `json:"confidence_score"`
	Evidence        []string `json:"evidence"`
	CaptchaType     string   `json:"captcha_type"`
	CaptchaMode     string   `json:"captcha_mode"`
}

type envelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// CheckDifficulty calls the hosted endpoint. fast=true stops at the first tier
// that retrieves the page; fast=false runs the exhaustive multi-run sweep.
func CheckDifficulty(ctx context.Context, baseURL, apiKey, targetURL string, fast bool, timeout time.Duration) (*Difficulty, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if timeout == 0 {
		timeout = 90 * time.Second
	}
	body, _ := json.Marshal(map[string]any{"url": targetURL, "fast": fast})

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, baseURL+"/diagnostics/antibot-check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", apiKey)

	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("auth failed (HTTP %d) — check your API key (x-api-key / CRAWLORA_API_KEY)", resp.StatusCode)
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limited (HTTP 429)")
	}

	var env envelope
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode >= 400 {
		msg := env.Msg
		if msg == "" {
			msg = snippet(raw)
		}
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, msg)
	}

	payload := env.Data
	if len(payload) == 0 {
		payload = raw // tolerate an unwrapped object
	}
	var d Difficulty
	if err := json.Unmarshal(payload, &d); err != nil {
		return nil, fmt.Errorf("could not parse API response (HTTP %d): %v", resp.StatusCode, err)
	}
	if d.URL == "" {
		d.URL = targetURL
	}
	return &d, nil
}

func snippet(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
