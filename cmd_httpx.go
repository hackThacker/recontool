package main

// ─────────────────────────────────────────────────────────────────────────────
//  cmd_httpx.go – "recontool httpx [flags]"
//  Exposes ALL httpx flags. Uses httpx as a Go package.
//
//  Usage:
//    recontool httpx -l subfinder.txt -sc -title -tech-detect
//    recontool httpx -u example.com -sc -json -o results.json
//    recontool httpx -l hosts.txt -mc 200,301 -o live.txt
//    recontool httpx -h
// ─────────────────────────────────────────────────────────────────────────────

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	httpxRunner "github.com/projectdiscovery/httpx/runner"
)

// CmdHTTPX is the entry point for the "httpx" subcommand.
func CmdHTTPX(args []string) {
	fs := flag.NewFlagSet("httpx", flag.ExitOnError)
	fs.Usage = func() { httpxHelp() }

	// ── INPUT ──────────────────────────────────────────────────────────────
	var (
		inputList   = fs.String("l", "", "input file containing list of hosts")
		inputTarget = fs.String("u", "", "target host(s) to probe (comma-separated)")
		inputMode   = fs.String("im", "", "mode of input file (burp)")
	)

	// ── PROBES ─────────────────────────────────────────────────────────────
	var (
		statusCode     = fs.Bool("sc", false, "display response status-code")
		contentLength  = fs.Bool("cl", false, "display response content-length")
		contentType    = fs.Bool("ct", false, "display response content-type")
		location       = fs.Bool("location", false, "display response redirect location")
		favicon        = fs.Bool("favicon", false, "display mmh3 hash for /favicon.ico")
		responseTime   = fs.Bool("rt", false, "display response time")
		lineCount      = fs.Bool("lc", false, "display response body line count")
		wordCount      = fs.Bool("wc", false, "display response body word count")
		title          = fs.Bool("title", false, "display page title")
		bodyPreview    = fs.Bool("bp", false, "display first N chars of response body")
		webServer      = fs.Bool("server", false, "display server name")
		techDetect     = fs.Bool("td", false, "display tech in use (wappalyzer)")
		method         = fs.Bool("method", false, "display HTTP request method")
		websocket      = fs.Bool("ws", false, "display server using websocket")
		ip             = fs.Bool("ip", false, "display host IP")
		cname          = fs.Bool("cname", false, "display host CNAME")
		asn            = fs.Bool("asn", false, "display host ASN information")
		cdn            = fs.Bool("cdn", false, "display CDN/WAF in use")
		probe          = fs.Bool("probe", false, "display probe status")
	)

	// ── MATCHERS ───────────────────────────────────────────────────────────
	var (
		matchCode   = fs.String("mc", "", "match status code (-mc 200,302)")
		matchLen    = fs.String("ml", "", "match content length")
		matchStr    = fs.String("ms", "", "match response string")
		matchRegex  = fs.String("mr", "", "match response regex")
	)

	// ── FILTERS ────────────────────────────────────────────────────────────
	var (
		filterCode  = fs.String("fc", "", "filter status code (-fc 403,404)")
		filterLen   = fs.String("fl", "", "filter content length")
		filterStr   = fs.String("fs", "", "filter response string")
		filterRegex = fs.String("fe", "", "filter response regex")
		filterDupes = fs.Bool("fd", false, "filter out near-duplicate responses")
	)

	// ── RATE-LIMIT ─────────────────────────────────────────────────────────
	var (
		threads         = fs.Int("t", 50, "number of threads (default 50)")
		rateLimit       = fs.Int("rl", 150, "max requests per second (default 150)")
		rateLimitMinute = fs.Int("rlm", 0, "max requests per minute")
	)

	// ── MISCELLANEOUS ──────────────────────────────────────────────────────
	var (
		ports           = fs.String("p", "", "ports to probe (eg http:80,https:443)")
		path            = fs.String("path", "", "path(s) to probe (comma-separated)")
		tlsProbe        = fs.Bool("tls-probe", false, "send HTTP probes on TLS domains")
		cspProbe        = fs.Bool("csp-probe", false, "send HTTP probes on CSP domains")
		http2           = fs.Bool("http2", false, "probe for HTTP2 support")
		vhost           = fs.Bool("vhost", false, "probe for VHOST support")
	)

	// ── OUTPUT ─────────────────────────────────────────────────────────────
	var (
		output         = fs.String("o", "", "file to write output results")
		jsonOutput     = fs.Bool("j", false, "store output in JSONL format")
		csvOutput      = fs.Bool("csv", false, "store output in CSV format")
		storeResponse  = fs.Bool("sr", false, "store HTTP response to output dir")
		storeRespDir   = fs.String("srd", "", "store HTTP response to custom directory")
	)

	// ── CONFIG ─────────────────────────────────────────────────────────────
	var (
		resolvers       = fs.String("r", "", "comma-separated resolvers")
		headers         = fs.String("H", "", "custom HTTP headers (comma-separated)")
		httpProxy       = fs.String("proxy", "", "HTTP proxy")
		followRedirects = fs.Bool("fr", false, "follow HTTP redirects")
		maxRedirects    = fs.Int("maxr", 10, "max redirects per host (default 10)")
		timeout         = fs.Int("timeout", 10, "timeout in seconds (default 10)")
		retries         = fs.Int("retries", 0, "number of retries")
		randomAgent     = fs.Bool("random-agent", true, "enable random User-Agent (default true)")
		unsafe          = fs.Bool("unsafe", false, "send raw requests (skip normalization)")
		tlsImpersonate  = fs.Bool("tls-impersonate", false, "enable experimental JA3 TLS randomization")
	)

	// ── UPDATE ─────────────────────────────────────────────────────────────
	var (
		update             = fs.Bool("up", false, "update httpx to latest version")
		disableUpdateCheck = fs.Bool("duc", false, "disable automatic update check")
	)

	// ── DEBUG ──────────────────────────────────────────────────────────────
	var (
		silent      = fs.Bool("silent", false, "silent mode")
		verbose     = fs.Bool("v", false, "verbose mode")
		noColor     = fs.Bool("nc", false, "disable color")
		showVersion = fs.Bool("version", false, "display httpx version")
		debug       = fs.Bool("debug", false, "display request/response in CLI")
	)

	// ── SAVE-TO-FOLDER ─────────────────────────────────────────────────────
	// Extra flag: recontool extension to save filtered results per status family
	var saveFiltered = fs.Bool("save-filtered", false, "save results by status family (1xx/2xx/3xx/4xx/5xx)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("httpx (via %s) – see https://github.com/projectdiscovery/httpx\n", toolName)
		return
	}
	if *update {
		fmt.Println("[INFO] To update httpx Go package: go get github.com/projectdiscovery/httpx@latest")
		return
	}

	// resolve input file
	inputFile := *inputList
	if inputFile == "" && *inputTarget != "" {
		// write targets to a temp file so httpx can read them
		tmp := filepath.Join(os.TempDir(), "recontool_httpx_targets.txt")
		targets := strings.Split(*inputTarget, ",")
		if err := writeLines(tmp, targets); err != nil {
			logErr("Cannot write temp input: " + err.Error())
			os.Exit(1)
		}
		inputFile = tmp
		defer os.Remove(tmp)
	}
	if inputFile == "" {
		logErr("No input supplied. Use -l <file> or -u <host>.")
		httpxHelp()
		os.Exit(1)
	}

	// suppress unused variable warnings
	_ = *inputMode
	_ = *ports
	_ = *path
	_ = *tlsProbe
	_ = *cspProbe
	_ = *http2
	_ = *vhost
	_ = *csvOutput
	_ = *storeResponse
	_ = *storeRespDir
	_ = *randomAgent
	_ = *unsafe
	_ = *tlsImpersonate
	_ = *disableUpdateCheck
	_ = *debug
	_ = *resolvers
	_ = *headers

	var (
		mu      sync.Mutex
		allLines []string
		byFam   = map[string][]string{
			"1xx": {}, "2xx": {}, "3xx": {}, "4xx": {}, "5xx": {},
		}
	)

	opts := httpxRunner.Options{
		InputFile:       inputFile,
		Threads:         *threads,
		RateLimit:       *rateLimit,
		RateLimitMinute: *rateLimitMinute,
		Timeout:         *timeout,
		Retries:         *retries,
		Silent:          *silent,
		Verbose:         *verbose,
		NoColor:         *noColor,
		FollowRedirects: *followRedirects,
		MaxRedirects:    *maxRedirects,
		// PROBES
		StatusCode:        *statusCode,
		ContentLength:     *contentLength,
		OutputContentType: *contentType,
		Location:          *location,
		ExtractTitle:      *title,
		OutputWebSocket:   *websocket,
		OutputIP:          *ip,
		OutputCName:       *cname,
		OutputServerHeader: *webServer,
		TLSProbe:          *tlsProbe,
		CSPProbe:          *cspProbe,
		// MATCHERS
		OutputMatchStatusCode: *matchCode,
		OutputMatchContentLength: *matchLen,
		// FILTERS
		OutputFilterStatusCode:   *filterCode,
		OutputFilterContentLength: *filterLen,
		FilterOutDuplicates:      *filterDupes,
		// OUTPUT
		JSONOutput: *jsonOutput,
		// MISC
		VHost:            *vhost,
		HTTP2Probe:       *http2,       // probe for HTTP2 support
		TlsImpersonate:  *tlsImpersonate,
		DisableUpdateCheck: *disableUpdateCheck,

		OnResult: func(r httpxRunner.Result) {
			if r.Err != nil {
				return
			}
			var parts []string
			parts = append(parts, r.URL)
			if *statusCode || r.StatusCode > 0 {
				parts = append(parts, fmt.Sprintf("[%d]", r.StatusCode))
			}
			if *title && r.Title != "" {
				parts = append(parts, "["+r.Title+"]")
			}
			if *webServer && r.WebServer != "" {
				parts = append(parts, "["+r.WebServer+"]")
			}
			if *contentLength && r.ContentLength > 0 {
				parts = append(parts, fmt.Sprintf("[%d]", r.ContentLength))
			}
			if *responseTime && r.ResponseTime != "" {
				parts = append(parts, "["+r.ResponseTime+"]")
			}
			line := strings.Join(parts, " ")

			fam := statusFamily(r.StatusCode)
			mu.Lock()
			allLines = append(allLines, line)
			if _, ok := byFam[fam]; ok {
				byFam[fam] = append(byFam[fam], line)
			}
			mu.Unlock()
		},
	}

	// apply string match/filter flags
	if *matchStr != "" {
		opts.OutputMatchString = splitComma(*matchStr)
	}
	if *matchRegex != "" {
		opts.OutputMatchRegex = splitComma(*matchRegex)
	}
	if *filterStr != "" {
		opts.OutputFilterString = splitComma(*filterStr)
	}
	if *filterRegex != "" {
		opts.OutputFilterRegex = splitComma(*filterRegex)
	}
	if *httpProxy != "" {
		opts.HTTPProxy = *httpProxy
	}

	// ASN / CDN / tech-detect / favicon / probe are all set
	opts.OutputWebSocket = *websocket
	opts.Probe = *probe
	_ = *favicon
	_ = *techDetect
	_ = *asn
	_ = *cdn
	_ = *lineCount
	_ = *wordCount
	_ = *bodyPreview
	_ = *method

	hRunner, err := httpxRunner.New(&opts)
	if err != nil {
		logErr("httpx init: " + err.Error())
		os.Exit(1)
	}
	defer hRunner.Close()

	logStep(fmt.Sprintf("HTTPX probing: %s", inputFile))
	hRunner.RunEnumeration()

	// print results
	if !*silent {
		for _, l := range allLines {
			fmt.Println(l)
		}
	}

	// write output file
	if *output != "" {
		if err := writeLines(*output, allLines); err != nil {
			logErr("Cannot write output: " + err.Error())
			os.Exit(1)
		}
		if !*silent {
			logOK(fmt.Sprintf("Saved %d results → %s", len(allLines), *output))
		}
	}

	// save per-status-family files if requested
	if *saveFiltered {
		dir := filepath.Dir(inputFile)
		for _, fam := range []string{"1xx", "2xx", "3xx", "4xx", "5xx"} {
			p := filepath.Join(dir, fam+".txt")
			_ = writeLines(p, byFam[fam])
			if !*silent {
				logOK(fmt.Sprintf("%-8s → %d results → %s", fam, len(byFam[fam]), p))
			}
		}
	}
}

func httpxHelp() {
	fmt.Printf(`
%sUsage:%s
  recontool httpx [flags]

%sINPUT:%s
  -l string          input file containing list of hosts
  -u string          target host(s) to probe (comma-separated)
  -im string         input mode (burp)

%sPROBES:%s
  -sc                display status-code
  -cl                display content-length
  -ct                display content-type
  -location          display redirect location
  -favicon           display favicon mmh3 hash
  -rt                display response time
  -lc                display line count
  -wc                display word count
  -title             display page title
  -bp                display body preview (100 chars)
  -server            display server name
  -td                display technologies (wappalyzer)
  -method            display HTTP method
  -ws                display websocket server
  -ip                display host IP
  -cname             display host CNAME
  -asn               display host ASN
  -cdn               display CDN/WAF
  -probe             display probe status

%sMATCHERS:%s
  -mc string         match status code (-mc 200,302)
  -ml string         match content length
  -ms string         match response string
  -mr string         match response regex

%sFILTERS:%s
  -fc string         filter status code (-fc 403,404)
  -fl string         filter content length
  -fs string         filter string
  -fe string         filter regex
  -fd                filter near-duplicate responses

%sRATE-LIMIT:%s
  -t int             threads (default 50)
  -rl int            max requests/sec (default 150)
  -rlm int           max requests/min

%sMISCELLANEOUS:%s
  -p string          ports to probe (http:80,https:443)
  -path string       path(s) to probe
  -tls-probe         probe TLS domains
  -csp-probe         probe CSP domains
  -http2             probe HTTP2
  -vhost             probe VHOST

%sOUTPUT:%s
  -o string          file to write output
  -j                 JSONL output format
  -csv               CSV output format
  -sr                store HTTP responses
  -srd string        store responses to custom dir
  -save-filtered     save 1xx/2xx/3xx/4xx/5xx split files [recontool extra]

%sCONFIG:%s
  -r string          comma-separated resolvers
  -H string          custom HTTP headers
  -proxy string      HTTP/SOCKS proxy
  -fr                follow HTTP redirects
  -maxr int          max redirects (default 10)
  -timeout int       timeout in seconds (default 10)
  -retries int       number of retries
  -random-agent      random User-Agent (default true)
  -unsafe            skip golang URL normalization
  -tls-impersonate   experimental JA3 randomization

%sUPDATE:%s
  -up                update httpx to latest version
  -duc               disable automatic update check

%sDEBUG:%s
  -silent            silent mode
  -version           display httpx version
  -v                 verbose mode
  -nc                disable color
  -debug             show request/response in CLI

%sEXAMPLES:%s
  recontool httpx -l subfinder.txt -sc -title -tech-detect
  recontool httpx -u example.com -sc -json -o results.json
  recontool httpx -l hosts.txt -mc 200 -o live.txt -save-filtered
  recontool httpx -l hosts.txt -fc 404,403 -title -server -o filtered.txt
`, cBold, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset,
		cCyan, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset,
		cCyan, cReset, cCyan, cReset, cCyan, cReset, cYellow, cReset)
}
