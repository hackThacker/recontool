package main

// ─────────────────────────────────────────────────────────────────────────────
//  cmd_uncover.go – "recontool uncover [flags]"
//  Exposes ALL uncover flags. Uses uncover as a Go package.
//
//  Usage:
//    recontool uncover -q "org:example.com" -e shodan,censys
//    recontool uncover -shodan "ssl:example.com" -j -o results.json
//    recontool uncover -fofa "domain=example.com" -l 500
//    recontool uncover -h
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"flag"
	"fmt"
	"os"

	uncoverRunner "github.com/projectdiscovery/uncover/runner"
)

// CmdUncover is the entry point for the "uncover" subcommand.
func CmdUncover(args []string) {
	fs := flag.NewFlagSet("uncover", flag.ExitOnError)
	fs.Usage = func() { uncoverHelp() }

	// ── INPUT ──────────────────────────────────────────────────────────────
	var (
		query  = fs.String("q", "", `search query (e.g. -q 'example query' or -q 'query.txt')`)
		engine = fs.String("e", "shodan", "search engine(s) to query (comma-separated)")
	)
	// -asq awesome search queries
	var asq = fs.String("asq", "", "awesome search queries to discover exposed assets (e.g. -asq 'jira')")

	// ── SEARCH-ENGINE SPECIFIC ─────────────────────────────────────────────
	var (
		shodan     = fs.String("s", "", "query for shodan")
		shodanIdb  = fs.String("sd", "", "query for shodan-idb")
		fofa       = fs.String("ff", "", "query for fofa")
		censys     = fs.String("cs", "", "query for censys")
		quake      = fs.String("qk", "", "query for quake")
		hunter     = fs.String("ht", "", "query for hunter")
		zoomEye    = fs.String("ze", "", "query for zoomeye")
		netlas     = fs.String("ne", "", "query for netlas")
		criminalIP = fs.String("cl", "", "query for criminalip")
		publicWWW  = fs.String("pw", "", "query for publicwww")
		hunterHow  = fs.String("hh", "", "query for hunterhow")
		google     = fs.String("gg", "", "query for google")
		onyphe     = fs.String("on", "", "query for onyphe")
		driftnet   = fs.String("df", "", "query for driftnet")
		daydaymap  = fs.String("ddm", "", "query for daydaymap")
	)

	// ── CONFIG ─────────────────────────────────────────────────────────────
	var (
		providerFile    = fs.String("pc", "", "provider configuration file")
		configFile      = fs.String("config", "", "flag configuration file")
		timeout         = fs.Int("timeout", 30, "timeout in seconds (default 30)")
		rateLimit       = fs.Int("rl", 0, "maximum HTTP requests per second")
		rateLimitMinute = fs.Int("rlm", 0, "maximum requests per minute")
		retry           = fs.Int("retry", 2, "number of retries (default 2)")
		proxy           = fs.String("proxy", "", "HTTP proxy to use")
	)

	// ── OUTPUT ─────────────────────────────────────────────────────────────
	var (
		output      = fs.String("o", "", "output file to write results")
		field       = fs.String("f", "ip:port", `field to display (ip,port,host) (default "ip:port")`)
		jsonOutput  = fs.Bool("j", false, "write output in JSONL format")
		raw         = fs.Bool("r", false, "write raw output as received by remote API")
		limit       = fs.Int("l", 100, "limit number of results (default 100)")
		noColor     = fs.Bool("nc", false, "disable colors in output")
	)

	// ── DEBUG ──────────────────────────────────────────────────────────────
	var (
		silent      = fs.Bool("silent", false, "show only results in output")
		showVersion = fs.Bool("version", false, "show version of uncover")
		verbose     = fs.Bool("v", false, "show verbose output")
	)

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("uncover (via %s) – see https://github.com/projectdiscovery/uncover\n", toolName)
		return
	}

	// Build Options using verified API field names (from go doc)
	opts := &uncoverRunner.Options{
		OutputFields:       *field,
		JSON:               *jsonOutput,
		Raw:                *raw,
		Limit:              *limit,
		Silent:             *silent,
		Verbose:            *verbose,
		NoColor:            *noColor,
		Timeout:            *timeout,
		RateLimit:          *rateLimit,
		RateLimitMinute:    *rateLimitMinute,
		Retries:            *retry,
		Proxy:              *proxy,
		DisableUpdateCheck: false,
	}

	if *configFile != "" {
		opts.ConfigFile = *configFile
	}
	if *providerFile != "" {
		opts.ProviderFile = *providerFile
	}
	if *output != "" {
		opts.OutputFile = *output
	}

	// Set queries using goflags.StringSlice compatible approach.
	// uncover Options fields are goflags.StringSlice – we assign []string values.
	if *query != "" {
		opts.Query = splitComma(*query)
	}
	if *engine != "" && *engine != "shodan" {
		opts.Engine = splitComma(*engine)
	} else if *engine == "shodan" && *shodan == "" && *query == "" {
		opts.Engine = []string{"shodan"}
	}
	if *asq != "" {
		opts.AwesomeSearchQueries = splitComma(*asq)
	}

	// Per-engine queries
	if *shodan != "" {
		opts.Shodan = splitComma(*shodan)
	}
	if *shodanIdb != "" {
		opts.ShodanIdb = splitComma(*shodanIdb)
	}
	if *fofa != "" {
		opts.Fofa = splitComma(*fofa)
	}
	if *censys != "" {
		opts.Censys = splitComma(*censys)
	}
	if *quake != "" {
		opts.Quake = splitComma(*quake)
	}
	if *hunter != "" {
		opts.Hunter = splitComma(*hunter)
	}
	if *zoomEye != "" {
		opts.ZoomEye = splitComma(*zoomEye)
	}
	if *netlas != "" {
		opts.Netlas = splitComma(*netlas)
	}
	if *criminalIP != "" {
		opts.CriminalIP = splitComma(*criminalIP)
	}
	if *publicWWW != "" {
		opts.Publicwww = splitComma(*publicWWW)
	}
	if *hunterHow != "" {
		opts.HunterHow = splitComma(*hunterHow)
	}
	if *google != "" {
		opts.Google = splitComma(*google)
	}
	if *onyphe != "" {
		opts.Onyphe = splitComma(*onyphe)
	}
	if *driftnet != "" {
		opts.Driftnet = splitComma(*driftnet)
	}
	if *daydaymap != "" {
		opts.Daydaymap = splitComma(*daydaymap)
	}

	// Validate: must have at least one query
	hasQuery := *query != "" || *asq != "" ||
		*shodan != "" || *shodanIdb != "" || *fofa != "" ||
		*censys != "" || *quake != "" || *hunter != "" ||
		*zoomEye != "" || *netlas != "" || *criminalIP != "" ||
		*publicWWW != "" || *hunterHow != "" || *google != "" ||
		*onyphe != "" || *driftnet != "" || *daydaymap != ""
	if !hasQuery {
		logErr("No query supplied. Use -q <query> or a specific engine flag like -shodan, -fofa, etc.")
		uncoverHelp()
		os.Exit(1)
	}

	if !*silent {
		logStep("uncover – querying " + *engine)
	}

	r, err := uncoverRunner.NewRunner(opts)
	if err != nil {
		logErr("uncover init: " + err.Error())
		os.Exit(1)
	}
	defer r.Close()

	ctx := context.Background()
	if err := r.Run(ctx); err != nil {
		logErr("uncover run: " + err.Error())
		os.Exit(1)
	}

	if !*silent {
		logOK("uncover completed.")
	}
}

func uncoverHelp() {
	fmt.Printf(`
%sUsage:%s
  recontool uncover [flags]

%sINPUT:%s
  -q string      search query (e.g. -q 'example query' or -q 'query.txt')
  -e string      search engine(s) to query, comma-separated
                 (shodan,shodan-idb,fofa,censys,quake,hunter,zoomeye,netlas,
                  criminalip,publicwww,hunterhow,google,onyphe,driftnet,daydaymap)
  -asq string    awesome search queries (e.g. -asq 'jira')

%sSEARCH-ENGINE SPECIFIC:%s
  -s string      query for shodan
  -sd string     query for shodan-idb
  -ff string     query for fofa
  -cs string     query for censys
  -qk string     query for quake
  -ht string     query for hunter
  -ze string     query for zoomeye
  -ne string     query for netlas
  -cl string     query for criminalip
  -pw string     query for publicwww
  -hh string     query for hunterhow
  -gg string     query for google
  -on string     query for onyphe
  -df string     query for driftnet
  -ddm string    query for daydaymap

%sCONFIG:%s
  -pc string     provider configuration file
  -config string flag configuration file
  -timeout int   timeout in seconds (default 30)
  -rl int        max HTTP requests per second
  -rlm int       max requests per minute
  -retry int     number of retries (default 2)
  -proxy string  HTTP proxy to use

%sOUTPUT:%s
  -o string      output file to write results
  -f string      field to display: ip,port,host (default "ip:port")
  -j             write output in JSONL format
  -r             write raw output as received from API
  -l int         limit number of results (default 100)
  -nc            disable colors in output

%sDEBUG:%s
  -silent        show only results in output
  -version       show version of uncover
  -v             show verbose output

%sEXAMPLES:%s
  recontool uncover -q "org:example.com" -e shodan,censys
  recontool uncover -shodan "ssl:example.com" -j -o results.json
  recontool uncover -fofa "domain=example.com" -l 500
  recontool uncover -q "example.com" -e shodan,fofa,censys -f ip:port -l 200
  recontool uncover -asq jira -e shodan -j

%sNOTE:%s
  Configure API keys in: %s~/.config/uncover/provider-config.yaml%s
  See: https://github.com/projectdiscovery/uncover#configuration
`, cBold, cReset, cCyan, cReset, cCyan, cReset, cCyan, cReset,
		cCyan, cReset, cCyan, cReset, cYellow, cReset, cBold, cReset, cBlue, cReset)
}
