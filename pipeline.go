package main

// ─────────────────────────────────────────────────────────────────────────────
//  pipeline.go – "recontool scan -d <domain>" or "recontool -d <domain>"
//  Full automated recon pipeline:
//    Step 1 – Wayback CDX    (4 searches  → wayback_*.txt)
//    Step 2 – Subfinder      (Go package  → subfinder.txt)
//    Step 3 – Chaos          (Go package  → chaos.txt)       [if -key provided]
//    Step 4 – HTTPX          (Go package  → httpx.txt + 1xx/2xx/3xx/4xx/5xx.txt)
//    Step 5 – Uncover        (Go package  → uncover.txt)     [if queries given]
// ─────────────────────────────────────────────────────────────────────────────

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	chaosClient    "github.com/projectdiscovery/chaos-client/pkg/chaos"
	subfinderRunner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
	httpxRunner    "github.com/projectdiscovery/httpx/runner"
	uncoverRunner  "github.com/projectdiscovery/uncover/runner"
)

// PipelineOptions holds the full-scan pipeline configuration.
type PipelineOptions struct {
	Domain   string
	// Chaos
	ChaosKey string
	// Uncover
	UncoverQuery  string
	UncoverEngine string
	UncoverLimit  int
	// Subfinder
	SubfinderAll     bool
	SubfinderSilent  bool
	SubfinderTimeout int
	SubfinderThreads int
	// HTTPX
	HTTPXThreads  int
	HTTPXTimeout  int
	HTTPXTitle    bool
	HTTPXTechDetect bool
	// Global
	Silent  bool
	Verbose bool
	NoColor bool
	Output  string // override output directory name
}

// CmdScan is the entry point for "recontool scan [flags]" and
// also "recontool -d <domain>" (the default full-pipeline mode).
func CmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.Usage = func() { scanHelp() }

	var opts PipelineOptions

	// ── TARGET ─────────────────────────────────────────────────────────────
	fs.StringVar(&opts.Domain, "d", "", "target domain to recon (required)")

	// ── CHAOS ──────────────────────────────────────────────────────────────
	fs.StringVar(&opts.ChaosKey, "key", "", "projectdiscovery cloud (pdcp) API key for chaos")

	// ── UNCOVER ────────────────────────────────────────────────────────────
	fs.StringVar(&opts.UncoverQuery, "uq", "", "uncover search query (e.g. 'ssl:example.com')")
	fs.StringVar(&opts.UncoverEngine, "ue", "shodan", "uncover engine(s), comma-separated")
	fs.IntVar(&opts.UncoverLimit, "ul", 100, "uncover result limit (default 100)")

	// ── SUBFINDER ──────────────────────────────────────────────────────────
	fs.BoolVar(&opts.SubfinderAll, "sf-all", false, "use all subfinder sources (slow)")
	fs.IntVar(&opts.SubfinderTimeout, "sf-timeout", 30, "subfinder timeout in seconds")
	fs.IntVar(&opts.SubfinderThreads, "sf-threads", 10, "subfinder goroutine count")

	// ── HTTPX ──────────────────────────────────────────────────────────────
	fs.IntVar(&opts.HTTPXThreads, "hx-threads", 50, "httpx thread count")
	fs.IntVar(&opts.HTTPXTimeout, "hx-timeout", 10, "httpx timeout in seconds")
	fs.BoolVar(&opts.HTTPXTitle, "hx-title", false, "httpx: display page title")
	fs.BoolVar(&opts.HTTPXTechDetect, "hx-td", false, "httpx: display technologies")

	// ── GLOBAL ─────────────────────────────────────────────────────────────
	fs.BoolVar(&opts.Silent, "silent", false, "suppress progress logs")
	fs.BoolVar(&opts.Verbose, "v", false, "verbose output")
	fs.StringVar(&opts.Output, "o", "", "output folder name (default: domain name)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// also check env for chaos key
	if opts.ChaosKey == "" {
		opts.ChaosKey = os.Getenv("PDCP_API_KEY")
	}

	if opts.Domain == "" {
		logErr("Domain required. Use: recontool scan -d example.com")
		scanHelp()
		os.Exit(1)
	}

	opts.Domain = normaliseDomain(opts.Domain)
	RunPipeline(opts)
}

// RunPipeline executes the full automated recon pipeline.
func RunPipeline(opts PipelineOptions) {
	// Apply robust defaults for zero/uninitialized options (e.g. in interactive mode)
	if opts.SubfinderTimeout <= 0 {
		opts.SubfinderTimeout = 30
	}
	if opts.SubfinderThreads <= 0 {
		opts.SubfinderThreads = 10
	}
	if opts.HTTPXThreads <= 0 {
		opts.HTTPXThreads = 50
	}
	if opts.HTTPXTimeout <= 0 {
		opts.HTTPXTimeout = 10
	}
	if opts.UncoverLimit <= 0 {
		opts.UncoverLimit = 100
	}
	if opts.UncoverEngine == "" {
		opts.UncoverEngine = "shodan"
	}

	domain := opts.Domain

	// ── Create output folder ──────────────────────────────────────────────
	folder := domain
	if opts.Output != "" {
		folder = opts.Output
	}
	if err := os.MkdirAll(folder, 0755); err != nil {
		logErr(fmt.Sprintf("Cannot create folder %q: %v", folder, err))
		os.Exit(1)
	}
	if !opts.Silent {
		logOK("Output folder: " + folder + "/")
	}

	start := time.Now()

	// ══════════════════════════════════════════════════════════════════════
	// STEP 1 – WAYBACK CDX
	// ══════════════════════════════════════════════════════════════════════
	if !opts.Silent {
		logStep(fmt.Sprintf("[1/5] Wayback CDX – %s", domain))
	}
	wb, err := RunWaybackCDX(domain)
	if err != nil {
		logErr("Wayback: " + err.Error())
	} else {
		for _, pair := range []struct {
			name  string
			lines []string
		}{
			{"wayback_main.txt", wb.Main},
			{"wayback_wildcard.txt", wb.Wildcard},
			{"wayback_specific.txt", wb.Specific},
			{"wayback_sensitive.txt", wb.Sensitive},
		} {
			_ = writeLines(filepath.Join(folder, pair.name), pair.lines)
		}
	}
	fmt.Println()

	// ══════════════════════════════════════════════════════════════════════
	// STEP 2 – SUBFINDER
	// ══════════════════════════════════════════════════════════════════════
	if !opts.Silent {
		logStep(fmt.Sprintf("[2/5] Subfinder – %s", domain))
	}
	subdomains := pipelineSubfinder(domain, opts)
	subfinderFile := filepath.Join(folder, "subfinder.txt")
	if err := writeLines(subfinderFile, subdomains); err != nil {
		logErr("Cannot write subfinder.txt: " + err.Error())
	} else if !opts.Silent {
		logOK(fmt.Sprintf("subfinder.txt          → %d subdomains", len(subdomains)))
	}
	fmt.Println()

	// ══════════════════════════════════════════════════════════════════════
	// STEP 3 – CHAOS (optional, requires -key)
	// ══════════════════════════════════════════════════════════════════════
	var chaosSubdomains []string
	if opts.ChaosKey != "" {
		if !opts.Silent {
			logStep(fmt.Sprintf("[3/5] Chaos – %s", domain))
		}
		chaosSubdomains = pipelineChaos(domain, opts.ChaosKey, opts.Silent)
		chaosFile := filepath.Join(folder, "chaos.txt")
		if err := writeLines(chaosFile, chaosSubdomains); err != nil {
			logErr("Cannot write chaos.txt: " + err.Error())
		} else if !opts.Silent {
			logOK(fmt.Sprintf("chaos.txt              → %d subdomains", len(chaosSubdomains)))
		}
		// merge chaos results into subdomain list for httpx
		subdomains = dedupe(append(subdomains, chaosSubdomains...))
	} else {
		if !opts.Silent {
			logWarn("[3/5] Chaos – skipped (no -key / PDCP_API_KEY)")
		}
	}
	fmt.Println()

	// ══════════════════════════════════════════════════════════════════════
	// STEP 4 – HTTPX (all status code families)
	// ══════════════════════════════════════════════════════════════════════
	if !opts.Silent {
		logStep(fmt.Sprintf("[4/5] HTTPX – probing %d hosts", len(subdomains)))
	}
	allHTTPX, byFam := pipelineHTTPX(subdomains, subfinderFile, opts)

	httpxFile := filepath.Join(folder, "httpx.txt")
	if err := writeLines(httpxFile, allHTTPX); err != nil {
		logErr("Cannot write httpx.txt: " + err.Error())
	} else if !opts.Silent {
		logOK(fmt.Sprintf("httpx.txt              → %d total results", len(allHTTPX)))
	}

	for _, fam := range []string{"1xx", "2xx", "3xx", "4xx", "5xx"} {
		p := filepath.Join(folder, fam+".txt")
		_ = writeLines(p, byFam[fam])
		if !opts.Silent {
			logOK(fmt.Sprintf("%-24s → %d responses", fam+".txt", len(byFam[fam])))
		}
	}
	fmt.Println()

	// ══════════════════════════════════════════════════════════════════════
	// STEP 5 – UNCOVER (optional, requires -uq)
	// ══════════════════════════════════════════════════════════════════════
	if opts.UncoverQuery != "" {
		if !opts.Silent {
			logStep(fmt.Sprintf("[5/5] Uncover – query: %s", opts.UncoverQuery))
		}
		uncoverFile := filepath.Join(folder, "uncover.txt")
		pipelineUncover(opts, uncoverFile)
		if !opts.Silent {
			logOK("uncover.txt            → written")
		}
	} else {
		if !opts.Silent {
			logWarn("[5/5] Uncover – skipped (use -uq '<query>' to enable)")
		}
	}
	fmt.Println()

	// ══════════════════════════════════════════════════════════════════════
	// SUMMARY
	// ══════════════════════════════════════════════════════════════════════
	elapsed := time.Since(start).Round(time.Second)
	fmt.Println(cGreen + cBold + "═══════════════════════  DONE  ══════════════════════════" + cReset)
	fmt.Printf("  Tool    : %s v%s  by %s\n", toolName, toolVersion, toolAuthor)
	fmt.Printf("  GitHub  : %s\n", toolGitHub)
	fmt.Printf("  Target  : %s\n", domain)
	fmt.Printf("  Folder  : %s/\n", folder)
	fmt.Println("  Output  :")
	fmt.Printf("    ├── subfinder.txt            (%d lines)\n", len(subdomains))
	if opts.ChaosKey != "" {
		fmt.Printf("    ├── chaos.txt                (%d lines)\n", len(chaosSubdomains))
	}
	fmt.Printf("    ├── httpx.txt                (%d lines)\n", len(allHTTPX))
	fmt.Printf("    ├── 1xx.txt                  (%d lines)\n", len(byFam["1xx"]))
	fmt.Printf("    ├── 2xx.txt                  (%d lines)\n", len(byFam["2xx"]))
	fmt.Printf("    ├── 3xx.txt                  (%d lines)\n", len(byFam["3xx"]))
	fmt.Printf("    ├── 4xx.txt                  (%d lines)\n", len(byFam["4xx"]))
	fmt.Printf("    ├── 5xx.txt                  (%d lines)\n", len(byFam["5xx"]))
	fmt.Printf("    ├── wayback_main.txt          (%d lines)\n", len(wb.Main))
	fmt.Printf("    ├── wayback_wildcard.txt      (%d lines)\n", len(wb.Wildcard))
	fmt.Printf("    ├── wayback_specific.txt      (%d lines)\n", len(wb.Specific))
	fmt.Printf("    └── wayback_sensitive.txt     (%d lines)\n", len(wb.Sensitive))
	fmt.Printf("  Time    : %s\n", elapsed)
	fmt.Println(cGreen + cBold + "═════════════════════════════════════════════════════════" + cReset)
}

// ── Internal pipeline helpers ────────────────────────────────────────────────

func pipelineSubfinder(domain string, opts PipelineOptions) []string {
	var buf bytes.Buffer
	sfOpts := &subfinderRunner.Options{
		Threads:            opts.SubfinderThreads,
		Timeout:            opts.SubfinderTimeout,
		MaxEnumerationTime: 10,
		Silent:             true,
		All:                opts.SubfinderAll,
		Output:             &buf,
	}
	runner, err := subfinderRunner.NewRunner(sfOpts)
	if err != nil {
		logErr("subfinder init: " + err.Error())
		return nil
	}
	ctx := context.Background()
	if _, err := runner.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{&buf}); err != nil {
		logErr("subfinder run: " + err.Error())
	}
	return nonEmptyLines(buf.String())
}

func pipelineChaos(domain, apiKey string, silent bool) []string {
	client := chaosClient.New(apiKey)
	ch := client.GetSubdomains(&chaosClient.SubdomainsRequest{Domain: domain})
	var subs []string
	for r := range ch {
		if r.Error != nil {
			logErr("chaos: " + r.Error.Error())
			break
		}
		subs = append(subs, r.Subdomain+"."+domain)
	}
	return subs
}

func pipelineHTTPX(subdomains []string, inputFile string, opts PipelineOptions) ([]string, map[string][]string) {
	byFam := map[string][]string{
		"1xx": {}, "2xx": {}, "3xx": {}, "4xx": {}, "5xx": {},
	}
	if len(subdomains) == 0 {
		logWarn("No subdomains to probe.")
		return nil, byFam
	}

	var (
		mu       sync.Mutex
		allLines []string
	)

	hOpts := httpxRunner.Options{
		InputFile:       inputFile,
		Threads:         opts.HTTPXThreads,
		Timeout:         opts.HTTPXTimeout,
		Silent:          true,
		FollowRedirects: true,
		StatusCode:      true,
		ExtractTitle:    opts.HTTPXTitle,
		OnResult: func(r httpxRunner.Result) {
			if r.Err != nil {
				return
			}
			line := fmt.Sprintf("%s [%d]", r.URL, r.StatusCode)
			if opts.HTTPXTitle && r.Title != "" {
				line += " [" + r.Title + "]"
			}
			fam := statusFamily(r.StatusCode)
			mu.Lock()
			allLines = append(allLines, line)
			if _, ok := byFam[fam]; ok {
				byFam[fam] = append(byFam[fam], line)
			}
			mu.Unlock()
		},
	}

	hRunner, err := httpxRunner.New(&hOpts)
	if err != nil {
		logErr("httpx init: " + err.Error())
		return nil, byFam
	}
	defer hRunner.Close()
	hRunner.RunEnumeration()
	return allLines, byFam
}

func pipelineUncover(opts PipelineOptions, outputFile string) {
	uOpts := &uncoverRunner.Options{
		Silent:      true,
		Limit:       opts.UncoverLimit,
		OutputFile:  outputFile,
		OutputFields: "ip:port",
	}
	if opts.UncoverQuery != "" {
		uOpts.Query = splitComma(opts.UncoverQuery)
	}
	if opts.UncoverEngine != "" {
		uOpts.Engine = splitComma(opts.UncoverEngine)
	}

	r, err := uncoverRunner.NewRunner(uOpts)
	if err != nil {
		logErr("uncover init: " + err.Error())
		return
	}
	defer r.Close()
	if err := r.Run(context.Background()); err != nil {
		logErr("uncover run: " + err.Error())
	}
}

// dedupe removes duplicate strings preserving order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func scanHelp() {
	fmt.Printf(`
%sUsage:%s
  recontool scan [flags]
  recontool -d <domain>         (shortcut – same as scan)

%sTARGET:%s
  -d string       target domain to recon (required)

%sCHAOS:%s
  -key string     projectdiscovery cloud (pdcp) API key
                  (also reads PDCP_API_KEY environment variable)

%sUNCOVER:%s
  -uq string      uncover search query (e.g. 'ssl:example.com')
  -ue string      uncover engine(s), comma-separated (default: shodan)
  -ul int         uncover result limit (default 100)

%sSUBFINDER TUNING:%s
  -sf-all         use all subfinder sources (slow)
  -sf-timeout int subfinder timeout in seconds (default 30)
  -sf-threads int subfinder goroutine count (default 10)

%sHTTPX TUNING:%s
  -hx-threads int httpx thread count (default 50)
  -hx-timeout int httpx timeout in seconds (default 10)
  -hx-title       display page titles in httpx output
  -hx-td          display technologies (wappalyzer)

%sGLOBAL:%s
  -silent         suppress progress logs
  -v              verbose output
  -o string       custom output folder name (default: domain name)

%sOUTPUT FILES (saved inside <domain>/ folder):%s
  subfinder.txt         all discovered subdomains
  chaos.txt             chaos subdomains  (if -key given)
  httpx.txt             ALL HTTP probe results
  1xx.txt               informational (100-199)
  2xx.txt               success (200-299)
  3xx.txt               redirects (300-399)
  4xx.txt               client errors (400-499)
  5xx.txt               server errors (500-599)
  wayback_main.txt      CDX: www.domain/*
  wayback_wildcard.txt  CDX: *.www.domain/*
  wayback_specific.txt  CDX: /en/*
  wayback_sensitive.txt CDX: sensitive file extensions
  uncover.txt           uncover OSINT results (if -uq given)

%sEXAMPLES:%s
  recontool -d example.com
  recontool scan -d example.com -key PDCP_KEY
  recontool scan -d example.com -key PDCP_KEY -uq "ssl:example.com" -ue shodan
  recontool scan -d example.com -sf-all -hx-title -silent
`, cBold, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset,
		cCyan, cReset, cCyan, cReset, cCyan, cReset, cGreen, cReset,
		cYellow, cReset)
}
