package main

// ─────────────────────────────────────────────────────────────────────────────
//  cmd_chaos.go – "recontool chaos [flags]"
//  Exposes ALL chaos-client flags. Uses chaos as a Go package.
//
//  Usage:
//    recontool chaos -d example.com -key PDCP_KEY
//    recontool chaos -dL domains.txt -key PDCP_KEY -json -o subs.txt
//    recontool chaos -d example.com -key PDCP_KEY -count
//    recontool chaos -h
// ─────────────────────────────────────────────────────────────────────────────

import (
	"flag"
	"fmt"
	"os"

	chaosClient "github.com/projectdiscovery/chaos-client/pkg/chaos"
)

// CmdChaos is the entry point for the "chaos" subcommand.
func CmdChaos(args []string) {
	fs := flag.NewFlagSet("chaos", flag.ExitOnError)
	fs.Usage = func() { chaosHelp() }

	// ── ALL FLAGS (matching chaos-client CLI exactly) ───────────────────────
	var (
		apiKey             = fs.String("key", "", "projectdiscovery cloud (pdcp) API key")
		domain             = fs.String("d", "", "domain to search for subdomains")
		count              = fs.Bool("count", false, "show statistics for the specified domain")
		silent             = fs.Bool("silent", false, "make the output silent")
		output             = fs.String("o", "", "file to write output to (optional)")
		domainList         = fs.String("dL", "", "file containing domains to search for subdomains")
		jsonOutput         = fs.Bool("json", false, "print output as json")
		showVersion        = fs.Bool("version", false, "show version of chaos")
		verbose            = fs.Bool("v", false, "verbose mode")
		update             = fs.Bool("up", false, "update chaos to latest version")
		disableUpdateCheck = fs.Bool("duc", false, "disable automatic chaos update check")
	)
	// alias: -verbose = -v
	fs.Bool("verbose", false, "verbose mode (alias for -v)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("chaos-client v%s (via %s) – https://github.com/projectdiscovery/chaos-client\n",
			chaosClient.Version, toolName)
		return
	}
	if *update {
		fmt.Println("[INFO] To update chaos Go package: go get github.com/projectdiscovery/chaos-client@latest")
		return
	}
	_ = *disableUpdateCheck

	// Validate API key
	if *apiKey == "" {
		*apiKey = os.Getenv("PDCP_API_KEY") // also check env
	}
	if *apiKey == "" {
		logErr("No API key supplied. Use -key <pdcp-api-key> or set PDCP_API_KEY env variable.")
		logInfo("Get your key at: https://cloud.projectdiscovery.io")
		os.Exit(1)
	}

	// Collect domains
	var domains []string
	if *domain != "" {
		domains = append(domains, normaliseDomain(*domain))
	}
	if *domainList != "" {
		lines, err := readLines(*domainList)
		if err != nil {
			logErr("Cannot read -dL file: " + err.Error())
			os.Exit(1)
		}
		for _, l := range lines {
			if d := normaliseDomain(l); d != "" {
				domains = append(domains, d)
			}
		}
	}
	if len(domains) == 0 {
		logErr("No domain supplied. Use -d <domain> or -dL <file>.")
		chaosHelp()
		os.Exit(1)
	}

	// Create chaos client
	client := chaosClient.New(*apiKey)

	var allSubs []string

	for _, d := range domains {
		if !*silent {
			logStep("chaos: " + d)
		}

		// ── Statistics mode ────────────────────────────────────────────────
		if *count {
			resp, err := client.GetStatistics(&chaosClient.GetStatisticsRequest{Domain: d})
			if err != nil {
				logErr(fmt.Sprintf("chaos stats [%s]: %v", d, err))
				continue
			}
			if *jsonOutput {
				fmt.Printf(`{"domain":%q,"subdomains":%d}`+"\n", d, resp.Subdomains)
			} else {
				fmt.Printf("[%s] %d subdomains indexed\n", d, resp.Subdomains)
			}
			continue
		}

		// ── Subdomain enumeration mode ──────────────────────────────────────
		resultCh := client.GetSubdomains(&chaosClient.SubdomainsRequest{Domain: d})
		var domainSubs []string

		for result := range resultCh {
			if result.Error != nil {
				logErr(fmt.Sprintf("chaos [%s]: %v", d, result.Error))
				break
			}
			sub := result.Subdomain + "." + d
			domainSubs = append(domainSubs, sub)

			if !*silent {
				if *jsonOutput {
					fmt.Printf(`{"subdomain":%q}`+"\n", sub)
				} else {
					fmt.Println(sub)
				}
			}
		}

		if !*silent {
			logOK(fmt.Sprintf("%s → %d subdomains", d, len(domainSubs)))
		}
		allSubs = append(allSubs, domainSubs...)
	}

	// Write output file
	if *output != "" && len(allSubs) > 0 {
		if err := writeLines(*output, allSubs); err != nil {
			logErr("Cannot write output: " + err.Error())
			os.Exit(1)
		}
		if !*silent {
			logOK(fmt.Sprintf("Saved %d subdomains → %s", len(allSubs), *output))
		}
	}

	// Print all if silent mode (silent means only output, no logging)
	if *silent {
		for _, s := range allSubs {
			fmt.Println(s)
		}
	}

	_ = *verbose
}

func chaosHelp() {
	fmt.Printf(`
%sUsage:%s
  recontool chaos [flags]

%sFLAGS:%s
  -key string     projectdiscovery cloud (pdcp) API key
                  (also reads PDCP_API_KEY environment variable)
  -d string       domain to search for subdomains
  -count          show statistics for the specified domain
  -silent         make the output silent (only results printed)
  -o string       file to write output to (optional)
  -dL string      file containing domains to search for subdomains
  -json           print output as json
  -version        show version of chaos
  -v, -verbose    verbose mode
  -up, -update    update chaos to latest version
  -duc            disable automatic chaos update check

%sEXAMPLES:%s
  recontool chaos -d example.com -key YOUR_PDCP_KEY
  recontool chaos -d example.com -key YOUR_PDCP_KEY -count
  recontool chaos -d example.com -key YOUR_PDCP_KEY -json -o subs.json
  recontool chaos -dL domains.txt -key YOUR_PDCP_KEY -o subs.txt
  recontool chaos -d example.com -key YOUR_PDCP_KEY -silent

%sNOTE:%s
  Get your free PDCP API key at: %shttps://cloud.projectdiscovery.io%s
`, cBold, cReset, cCyan, cReset, cYellow, cReset, cBold, cReset, cBlue, cReset)
}
