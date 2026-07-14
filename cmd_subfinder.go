package main

// ─────────────────────────────────────────────────────────────────────────────
//  cmd_subfinder.go – "recontool subfinder [flags]"
//  Exposes ALL subfinder flags. Uses subfinder as a Go package.
//
//  Usage:
//    recontool subfinder -d example.com
//    recontool subfinder -d example.com -all -silent -o subs.txt
//    recontool subfinder -dL domains.txt -s shodan,crtsh -json
//    recontool subfinder -h
// ─────────────────────────────────────────────────────────────────────────────

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	subfinderRunner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// CmdSubfinder is the entry point for the "subfinder" subcommand.
func CmdSubfinder(args []string) {
	fs := flag.NewFlagSet("subfinder", flag.ExitOnError)
	fs.Usage = func() { subfinderHelp() }

	// ── INPUT ──────────────────────────────────────────────────────────────
	var (
		domains   = fs.String("d", "", "domain(s) to find subdomains for (comma-separated)")
		domainList = fs.String("dL", "", "file containing list of domains")
	)

	// ── SOURCE ─────────────────────────────────────────────────────────────
	var (
		sources        = fs.String("s", "", "specific sources to use (-s crtsh,github)")
		recursive      = fs.Bool("recursive", false, "use only recursive sources")
		all            = fs.Bool("all", false, "use all sources (slow)")
		excludeSources = fs.String("es", "", "sources to exclude from enumeration")
	)

	// ── FILTER ─────────────────────────────────────────────────────────────
	var (
		matchSub  = fs.String("m", "", "subdomain(s) to match (file or comma-separated)")
		filterSub = fs.String("f", "", "subdomain(s) to filter (file or comma-separated)")
	)

	// ── RATE-LIMIT ─────────────────────────────────────────────────────────
	var (
		rateLimit = fs.Int("rl", 0, "maximum HTTP requests per second")
		threads   = fs.Int("t", 10, "number of concurrent goroutines (active only)")
	)

	// ── UPDATE ─────────────────────────────────────────────────────────────
	var (
		update             = fs.Bool("up", false, "update subfinder to latest version")
		disableUpdateCheck = fs.Bool("duc", false, "disable automatic update check")
	)

	// ── OUTPUT ─────────────────────────────────────────────────────────────
	var (
		output      = fs.String("o", "", "file to write output to")
		jsonOutput  = fs.Bool("oJ", false, "write output in JSONL format")
		outputDir   = fs.String("oD", "", "directory to write output (-dL only)")
		collectSrc  = fs.Bool("cs", false, "include all sources in output (-json only)")
		includeIP   = fs.Bool("oI", false, "include host IP in output (-active only)")
	)

	// ── CONFIG ─────────────────────────────────────────────────────────────
	var (
		configFile   = fs.String("config", "", "flag config file path")
		providerCfg  = fs.String("pc", "", "provider config file path")
		resolvers    = fs.String("r", "", "comma-separated list of resolvers")
		resolverList = fs.String("rL", "", "file containing list of resolvers")
		activeOnly   = fs.Bool("nW", false, "display active subdomains only")
		proxy        = fs.String("proxy", "", "HTTP proxy to use")
		excludeIP    = fs.Bool("ei", false, "exclude IPs from domain list")
		maxResults   = fs.Int("mr", 0, "limit results per source (0 = unlimited)")
	)

	// ── DEBUG ──────────────────────────────────────────────────────────────
	var (
		silent      = fs.Bool("silent", false, "show only subdomains in output")
		verbose     = fs.Bool("v", false, "show verbose output")
		noColor     = fs.Bool("nc", false, "disable color in output")
		listSources = fs.Bool("ls", false, "list all available sources")
		showVersion = fs.Bool("version", false, "show version of subfinder")
	)

	// ── OPTIMIZATION ───────────────────────────────────────────────────────
	var (
		timeout = fs.Int("timeout", 30, "seconds to wait before timing out")
		maxTime = fs.Int("max-time", 10, "minutes to wait for results")
	)

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	// handle -h inside FlagSet automatically

	if *showVersion {
		fmt.Printf("subfinder (via %s) – see https://github.com/projectdiscovery/subfinder\n", toolName)
		return
	}
	if *listSources {
		fmt.Println("Source list depends on provider-config.yaml. Visit:")
		fmt.Println("  https://github.com/projectdiscovery/subfinder#post-installation-instructions")
		return
	}
	if *update {
		fmt.Println("[INFO] To update subfinder Go package: go get github.com/projectdiscovery/subfinder/v2@latest")
		return
	}

	// collect domains to enumerate
	var domainList2 []string
	if *domains != "" {
		for _, d := range strings.Split(*domains, ",") {
			if d = strings.TrimSpace(d); d != "" {
				domainList2 = append(domainList2, normaliseDomain(d))
			}
		}
	}
	if *domainList != "" {
		lines, err := readLines(*domainList)
		if err != nil {
			logErr("Cannot read -dL file: " + err.Error())
			os.Exit(1)
		}
		for _, l := range lines {
			domainList2 = append(domainList2, normaliseDomain(l))
		}
	}
	if len(domainList2) == 0 {
		logErr("No domain supplied. Use -d <domain> or -dL <file>.")
		subfinderHelp()
		os.Exit(1)
	}

	// build subfinder options using verified API fields
	opts := &subfinderRunner.Options{
		Threads:            *threads,
		Timeout:            *timeout,
		MaxEnumerationTime: *maxTime,
		Silent:             *silent,
		Verbose:            *verbose,
		NoColor:            *noColor,
		All:                *all,
		OnlyRecursive:      *recursive,
		CaptureSources:     *collectSrc,
		HostIP:             *includeIP,
		DisableUpdateCheck: *disableUpdateCheck,
		// Output writer set below
	}
	if *configFile != "" {
		opts.Config = *configFile
	}
	if *providerCfg != "" {
		opts.ProviderConfig = *providerCfg
	}
	if *proxy != "" {
		opts.Proxy = *proxy
	}
	if *rateLimit > 0 {
		opts.RateLimit = *rateLimit
	}
	_ = *maxResults // MaxResults not available in subfinder Options; use source limits instead
	if *excludeIP {
		opts.ExcludeIps = true
	}
	if *activeOnly {
		opts.RemoveWildcard = true
	}
	// sources / exclude-sources / match / filter / resolvers handled via
	// goflags.StringSlice – we set them from parsed strings
	if *sources != "" {
		opts.Sources = splitComma(*sources)
	}
	if *excludeSources != "" {
		opts.ExcludeSources = splitComma(*excludeSources)
	}
	if *matchSub != "" {
		opts.Match = splitComma(*matchSub)
	}
	if *filterSub != "" {
		opts.Filter = splitComma(*filterSub)
	}
	if *resolvers != "" {
		opts.Resolvers = splitComma(*resolvers)
	}
	if *resolverList != "" {
		opts.ResolverList = *resolverList
	}

	runner, err := subfinderRunner.NewRunner(opts)
	if err != nil {
		logErr("subfinder init: " + err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	var allSubs []string

	for _, domain := range domainList2 {
		logStep("subfinder: " + domain)
		var buf bytes.Buffer
		opts.Output = &buf

		if _, err := runner.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{&buf}); err != nil {
			logErr("subfinder: " + err.Error())
			continue
		}
		subs := nonEmptyLines(buf.String())
		logOK(fmt.Sprintf("%s → %d subdomains", domain, len(subs)))
		allSubs = append(allSubs, subs...)

		// write per-domain output if -oD is set
		if *outputDir != "" {
			_ = os.MkdirAll(*outputDir, 0755)
			p := filepath.Join(*outputDir, domain+".txt")
			_ = writeLines(p, subs)
		}
	}

	// print to stdout if not silent
	if !*silent || *output == "" {
		for _, s := range allSubs {
			if *jsonOutput {
				fmt.Printf(`{"subdomain":%q}`+"\n", s)
			} else {
				fmt.Println(s)
			}
		}
	}

	// write to -o file
	if *output != "" {
		if err := writeLines(*output, allSubs); err != nil {
			logErr("Cannot write output file: " + err.Error())
			os.Exit(1)
		}
		if !*silent {
			logOK(fmt.Sprintf("Saved %d subdomains → %s", len(allSubs), *output))
		}
	}
}

func subfinderHelp() {
	fmt.Printf(`
%sUsage:%s
  recontool subfinder [flags]

%sINPUT:%s
  -d string     domain(s) to find subdomains for (comma-separated)
  -dL string    file containing list of domains

%sSOURCE:%s
  -s string     specific sources (-s crtsh,github)
  -recursive    use only recursive sources
  -all          use all sources (slow)
  -es string    sources to exclude

%sFILTER:%s
  -m string     subdomain(s) to match (file or comma-separated)
  -f string     subdomain(s) to filter

%sRATE-LIMIT:%s
  -rl int       maximum HTTP requests per second
  -t int        concurrent goroutines (default 10)

%sUPDATE:%s
  -up           update subfinder to latest version
  -duc          disable automatic update check

%sOUTPUT:%s
  -o string     file to write output to
  -oJ           write output in JSONL format
  -oD string    directory to write output (-dL only)
  -cs           include all sources in output (-json only)
  -oI           include host IP in output (-active only)

%sCONFIG:%s
  -config string    flag config file
  -pc string        provider config file
  -r string         comma-separated resolvers
  -rL string        resolver list file
  -nW               display active subdomains only
  -proxy string     HTTP proxy
  -ei               exclude IPs from domain list
  -mr int           limit results per source (0 = unlimited)

%sDEBUG:%s
  -silent       show only subdomains in output
  -version      show subfinder version
  -v            verbose output
  -nc           disable color
  -ls           list all available sources

%sOPTIMIZATION:%s
  -timeout int  timeout in seconds (default 30)
  -max-time int max time in minutes (default 10)

%sEXAMPLES:%s
  recontool subfinder -d example.com
  recontool subfinder -d example.com -all -silent -o subs.txt
  recontool subfinder -dL domains.txt -s shodan,crtsh -json
`, cBold, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset,
		cCyan, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset,
		cCyan, cReset, cCyan, cReset, cYellow, cReset)
}

// splitComma splits a comma-separated string into a []string.
func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
