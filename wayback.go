package main

// ─────────────────────────────────────────────────────────────────────────────
//  wayback.go – Wayback Machine CDX API (4 search modes, native net/http)
// ─────────────────────────────────────────────────────────────────────────────

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// sensitiveExts is the full extension list for the CDX sensitive-files filter.
const sensitiveExts = `xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar.gz|` +
	`tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|` +
	`md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|` +
	`tmp|crt|pem|key|pub|asc`

// WaybackResult holds results of all 4 CDX queries.
type WaybackResult struct {
	Main      []string
	Wildcard  []string
	Specific  []string
	Sensitive []string
}

// RunWaybackCDX executes all 4 Wayback CDX queries for the domain.
//
//	1. Main domain    → url=www.domain/*
//	2. Wildcard       → url=*.www.domain/*
//	3. Specific path  → url=https://www.domain/en/*
//	4. Sensitive files → filtered by extension list
func RunWaybackCDX(domain string) (WaybackResult, error) {
	logStep("Wayback CDX API – 4 searches for: " + domain)
	var res WaybackResult
	base := "https://web.archive.org/cdx/search/cdx"

	// ── 1. Main domain ──────────────────────────────────────────────────────
	// https://web.archive.org/cdx/search/cdx?url=www.domain/*&collapse=urlkey&output=text&fl=original
	q1 := base + "?url=www." + url.QueryEscape(domain) + "/*&collapse=urlkey&output=text&fl=original"
	logInfo("[1/4] Main domain → " + q1)
	v, err := cdxGet(q1)
	if err != nil {
		return res, fmt.Errorf("CDX main: %w", err)
	}
	res.Main = v
	logOK(fmt.Sprintf("wayback_main.txt       → %d URLs", len(v)))

	// ── 2. Wildcard domain ──────────────────────────────────────────────────
	// https://web.archive.org/cdx/search/cdx?url=*.www.domain/*&collapse=urlkey&output=text&fl=original
	q2 := base + "?url=*." + url.QueryEscape("www."+domain) + "/*&collapse=urlkey&output=text&fl=original"
	logInfo("[2/4] Wildcard     → " + q2)
	v, err = cdxGet(q2)
	if err != nil {
		return res, fmt.Errorf("CDX wildcard: %w", err)
	}
	res.Wildcard = v
	logOK(fmt.Sprintf("wayback_wildcard.txt   → %d URLs", len(v)))

	// ── 3. Specific path (/en/*) ─────────────────────────────────────────────
	// https://web.archive.org/cdx/search/cdx?url=https://www.domain/en/*&collapse=urlkey&output=text&fl=original
	q3 := base + "?url=" + url.QueryEscape("https://www."+domain+"/en/*") +
		"&collapse=urlkey&output=text&fl=original"
	logInfo("[3/4] Specific     → " + q3)
	v, err = cdxGet(q3)
	if err != nil {
		return res, fmt.Errorf("CDX specific: %w", err)
	}
	res.Specific = v
	logOK(fmt.Sprintf("wayback_specific.txt   → %d URLs", len(v)))

	// ── 4. Sensitive file extensions ─────────────────────────────────────────
	// filter=original:.*.(xls|xml|...etc)$
	q4 := base + "?url=*." + url.QueryEscape("www."+domain) + "/*" +
		"&collapse=urlkey&output=text&fl=original" +
		"&filter=original:.*\\.(" + sensitiveExts + ")$"
	logInfo("[4/4] Sensitive    → " + q4)
	v, err = cdxGet(q4)
	if err != nil {
		return res, fmt.Errorf("CDX sensitive: %w", err)
	}
	res.Sensitive = v
	logOK(fmt.Sprintf("wayback_sensitive.txt  → %d URLs", len(v)))

	return res, nil
}

// cdxGet performs one HTTP GET to the Wayback CDX API and returns lines.
func cdxGet(rawURL string) ([]string, error) {
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return nonEmptyLines(string(body)), nil
}
