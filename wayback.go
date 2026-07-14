package main

// ─────────────────────────────────────────────────────────────────────────────
//  wayback.go – Wayback Machine CDX API (4 search modes, native net/http, concurrent, resilient)
// ─────────────────────────────────────────────────────────────────────────────

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// User agents pool for request randomization
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
	"Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.65 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; GT-I9505 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
	"Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/114.0",
	"Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
	"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
	"Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.137 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
	"Mozilla/5.0 (Linux; Android 9; Redmi Note 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.126 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
	"Mozilla/5.0 (Linux; U; Android 4.2.2; en-us; GT-P5113 Build/JDQ39) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19577",
	"Mozilla/5.0 (X11) AppleWebKit/62.41 (KHTML, like Gecko) Edge/17.10859 Safari/452.6",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14931",
	"Chrome (AppleWebKit/537.1; Chrome50.0; Windows NT 6.3) AppleWebKit/537.36 (KHTML like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.9200",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
	"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.16) Gecko/20120421 Firefox/11.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko Firefox/11.0",
	"Mozilla/5.0 (Windows NT 6.1; U;WOW64; de;rv:11.0) Gecko Firefox/11.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0",
	"Mozilla/6.0 (Macintosh; I; Intel Mac OS X 11_7_9; de-LI; rv:1.9b4) Gecko/2012010317 Firefox/10.0a4",
	"Mozilla/5.0 (X11; Mageia; Linux x86_64; rv:10.0.9) Gecko/20100101 Firefox/10.0.9",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0a2) Gecko/20111101 Firefox/9.0a2",
	"Mozilla/5.0 (Windows NT 6.2; rv:9.0.1) Gecko/20100101 Firefox/9.0.1",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0) Gecko/20100101 Firefox/9.0",
	"Mozilla/5.0 (Windows NT 5.1; rv:8.0; en_us) Gecko/20100101 Firefox/8.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20100101 Firefox/7.0",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110613 Firefox/6.0a2",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110612 Firefox/6.0a2",
	"Mozilla/5.0 (X11; Linux i686; rv:6.0) Gecko/20100101 Firefox/6.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.90 Safari/537.36",
	"Mozilla/5.0 (X11; NetBSD) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
	"Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.60 Safari/537.17",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1309.0 Safari/537.17",
	"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.15 (KHTML, like Gecko) Chrome/24.0.1295.0 Safari/537.15",
	"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.14 (KHTML, like Gecko) Chrome/24.0.1292.0 Safari/537.14",
	"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13",
	"Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

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

// Global, reused client to avoid socket exhaustion and overhead.
var waybackClient = &http.Client{
	Timeout: 300 * time.Second,
}

// RunWaybackCDX executes all 4 Wayback CDX queries for the domain concurrently and saves them to disk.
func RunWaybackCDX(domain string, folder string) (WaybackResult, error) {
	logStep("Wayback CDX API – 4 searches for: " + domain)
	var res WaybackResult
	base := "https://web.archive.org/cdx/search/cdx"

	q1 := base + "?url=www." + url.QueryEscape(domain) + "/*&collapse=urlkey&output=text&fl=original"
	q2 := base + "?url=*." + url.QueryEscape("www."+domain) + "/*&collapse=urlkey&output=text&fl=original"
	q3 := base + "?url=" + url.QueryEscape("https://www."+domain+"/en/*") + "&collapse=urlkey&output=text&fl=original"
	q4 := base + "?url=*." + url.QueryEscape("www."+domain) + "/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(" + sensitiveExts + ")$"

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	var mainURLs []string
	var wildcardURLs []string
	var specificURLs []string
	var sensitiveURLs []string

	addError := func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}

	wg.Add(4)

	// Query 1: Main domain
	go func() {
		defer wg.Done()
		logInfo("[1/4] Main domain → " + q1)
		v, err := cdxGet(q1)
		if err != nil {
			err = fmt.Errorf("CDX main: %w", err)
			logErr(err.Error())
			addError(err)
			return
		}
		mainURLs = v

		filePath := filepath.Join(folder, "wayback_main.txt")
		if err := writeLines(filePath, v); err != nil {
			logErr(fmt.Sprintf("Failed to write wayback_main.txt: %v", err))
		} else {
			logOK(fmt.Sprintf("wayback_main.txt       → %d URLs", len(v)))
		}
	}()

	// Query 2: Wildcard domain
	go func() {
		defer wg.Done()
		logInfo("[2/4] Wildcard     → " + q2)
		v, err := cdxGet(q2)
		if err != nil {
			err = fmt.Errorf("CDX wildcard: %w", err)
			logErr(err.Error())
			addError(err)
			return
		}
		wildcardURLs = v

		filePath := filepath.Join(folder, "wayback_wildcard.txt")
		if err := writeLines(filePath, v); err != nil {
			logErr(fmt.Sprintf("Failed to write wayback_wildcard.txt: %v", err))
		} else {
			logOK(fmt.Sprintf("wayback_wildcard.txt   → %d URLs", len(v)))
		}
	}()

	// Query 3: Specific path
	go func() {
		defer wg.Done()
		logInfo("[3/4] Specific     → " + q3)
		v, err := cdxGet(q3)
		if err != nil {
			err = fmt.Errorf("CDX specific: %w", err)
			logErr(err.Error())
			addError(err)
			return
		}
		specificURLs = v

		filePath := filepath.Join(folder, "wayback_specific.txt")
		if err := writeLines(filePath, v); err != nil {
			logErr(fmt.Sprintf("Failed to write wayback_specific.txt: %v", err))
		} else {
			logOK(fmt.Sprintf("wayback_specific.txt   → %d URLs", len(v)))
		}
	}()

	// Query 4: Sensitive file extensions
	go func() {
		defer wg.Done()
		logInfo("[4/4] Sensitive    → " + q4)
		v, err := cdxGet(q4)
		if err != nil {
			err = fmt.Errorf("CDX sensitive: %w", err)
			logErr(err.Error())
			addError(err)
			return
		}
		sensitiveURLs = v

		filePath := filepath.Join(folder, "wayback_sensitive.txt")
		if err := writeLines(filePath, v); err != nil {
			logErr(fmt.Sprintf("Failed to write wayback_sensitive.txt: %v", err))
		} else {
			logOK(fmt.Sprintf("wayback_sensitive.txt  → %d URLs", len(v)))
		}
	}()

	wg.Wait()

	res.Main = mainURLs
	res.Wildcard = wildcardURLs
	res.Specific = specificURLs
	res.Sensitive = sensitiveURLs

	if len(errs) == 4 {
		return res, fmt.Errorf("all 4 CDX queries failed completely: %v", errs)
	}

	return res, nil
}

// cdxGet performs one HTTP GET to the Wayback CDX API, streaming response lines directly.
func cdxGet(rawURL string) ([]string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("HTTP request creation: %w", err)
	}

	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := waybackClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP Do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var out []string
	scanner := bufio.NewScanner(resp.Body)

	const maxCapacity = 10 * 1024 * 1024
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			out = append(out, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return out, nil
}
