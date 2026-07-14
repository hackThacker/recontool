package main

// ─────────────────────────────────────────────────────────────────────────────
//
//	ReconTool – Unified recon CLI for subfinder + httpx + chaos + uncover + wayback
//
//	Author  : hackthacker
//	GitHub  : https://github.com/hackthacker/recontool
//	Version : 1.0.0
//
//	COMMANDS:
//	  recontool -d example.com          → full automated pipeline
//	  recontool scan [flags]             → full automated pipeline
//	  recontool subfinder [flags]        → run subfinder (all flags)
//	  recontool httpx [flags]            → run httpx (all flags)
//	  recontool chaos [flags]            → run chaos (all flags)
//	  recontool uncover [flags]          → run uncover (all flags)
//
//	GLOBAL:
//	  recontool -v / --version           → show version
//	  recontool -h / --help              → show full help
//	  recontool -u / --update            → check for updates on GitHub
//
// ─────────────────────────────────────────────────────────────────────────────

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// Tool metadata
// ─────────────────────────────────────────────

const (
	toolVersion  = "1.0.0"
	toolName     = "ReconTool"
	toolAuthor   = "hackthacker"
	toolGitHub   = "https://github.com/hackthacker/recontool"
	latestAPIURL = "https://api.github.com/repos/hackthacker/recontool/releases/latest"
)

// ─────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────

func banner() {
	fmt.Println(cCyan + cBold + `
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
` + cReset)
	fmt.Printf("  %s%-10s%s %sv%s%s  |  by %s%s%s  |  %s%s%s\n",
		cBold, toolName, cReset,
		cGreen, toolVersion, cReset,
		cYellow, toolAuthor, cReset,
		cBlue, toolGitHub, cReset,
	)
	fmt.Println(strings.Repeat("─", 78))
}

// ─────────────────────────────────────────────
// Global help
// ─────────────────────────────────────────────

func printHelp() {
	banner()
	fmt.Printf(`
%sUSAGE:%s
  recontool [command] [flags]

%sCOMMANDS:%s
  %sscan%s       Full automated recon pipeline (wayback → subfinder → chaos → httpx → uncover)
  %ssubfinder%s  Run subfinder subdomain enumeration with ALL subfinder flags
  %shttpx%s      Run httpx HTTP probing with ALL httpx flags
  %schaos%s      Run chaos subdomain search with ALL chaos flags
  %suncover%s    Run uncover OSINT search with ALL uncover flags

%sGLOBAL FLAGS:%s
  -d, --domain <domain>   Shortcut: run full scan (same as scan -d <domain>)
  -v, --version           Show version information and exit
  -u, --update            Check GitHub for latest version
  -h, --help              Show this help message

%sQUICK START:%s
  recontool -d example.com                          # full pipeline
  recontool scan -d example.com -key PDCP_KEY       # with chaos
  recontool subfinder -d example.com -all -o out.txt
  recontool httpx -l subfinder.txt -sc -title -save-filtered
  recontool chaos -d example.com -key YOUR_KEY
  recontool uncover -q "ssl:example.com" -e shodan,censys

%sSUBCOMMAND HELP:%s
  recontool scan -h
  recontool subfinder -h
  recontool httpx -h
  recontool chaos -h
  recontool uncover -h

%sAUTHOR:%s
  %s%s%s  (%s%s%s)
`, cBold, cReset,
		cBold, cReset,
		cGreen, cReset, cGreen, cReset, cGreen, cReset, cGreen, cReset, cGreen, cReset,
		cBold, cReset,
		cBold, cReset,
		cBold, cReset,
		cBold, cReset,
		cYellow, toolAuthor, cReset, cBlue, toolGitHub, cReset)
	os.Exit(0)
}

// ─────────────────────────────────────────────
// Version
// ─────────────────────────────────────────────

func printVersion() {
	fmt.Printf("%s%s%s  v%s%s%s\n", cBold, toolName, cReset, cGreen, toolVersion, cReset)
	fmt.Printf("Author  : %s%s%s\n", cYellow, toolAuthor, cReset)
	fmt.Printf("GitHub  : %s%s%s\n", cBlue, toolGitHub, cReset)
	os.Exit(0)
}

// ─────────────────────────────────────────────
// Update checker
// ─────────────────────────────────────────────

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Name    string `json:"name"`
}

func checkUpdate() {
	fmt.Printf("%s[UPDATE]%s Querying GitHub releases…\n", cCyan, cReset)
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", latestAPIURL, nil)
	req.Header.Set("User-Agent", toolName+"/"+toolVersion)

	resp, err := client.Do(req)
	if err != nil {
		logErr("Cannot reach GitHub API: " + err.Error())
		os.Exit(1)
	}
	defer resp.Body.Close()

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		logErr("Failed to parse GitHub response: " + err.Error())
		os.Exit(1)
	}

	latest := strings.TrimPrefix(rel.TagName, "v")
	fmt.Printf("  Installed : %s%s%s\n", cYellow, toolVersion, cReset)
	fmt.Printf("  Latest    : %s%s%s\n", cGreen, latest, cReset)
	if latest == toolVersion || latest == "" {
		logOK("You are on the latest version.")
	} else {
		fmt.Printf("\n%s%s[NEW VERSION]%s %s → %s available!\n",
			cBold, cGreen, cReset, toolVersion, latest)
		fmt.Printf("  Download : %s%s%s\n", cBlue, rel.HTMLURL, cReset)
	}
	os.Exit(0)
}

// ─────────────────────────────────────────────
// Main / Router
// ─────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		// No args: show banner + interactive domain prompt then run pipeline
		banner()
		reader := newStdinReader()
		fmt.Print(cBold + "\nEnter target domain (or 'help'): " + cReset)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || line == "help" {
			printHelp()
		}
		RunPipeline(PipelineOptions{Domain: normaliseDomain(line)})
		return
	}

	switch os.Args[1] {
	// ── Subcommands ────────────────────────────────────────────────────────
	case "scan":
		banner()
		CmdScan(os.Args[2:])

	case "subfinder":
		banner()
		CmdSubfinder(os.Args[2:])

	case "httpx":
		banner()
		CmdHTTPX(os.Args[2:])

	case "chaos":
		banner()
		CmdChaos(os.Args[2:])

	case "uncover":
		banner()
		CmdUncover(os.Args[2:])

	// ── Global flags ───────────────────────────────────────────────────────
	case "-h", "--help", "help":
		printHelp()

	case "-v", "--version", "version":
		printVersion()

	case "-u", "--update", "update":
		checkUpdate()

	default:
		// Accept bare: recontool -d example.com (or any flags without subcommand)
		// treat as "scan"
		banner()
		CmdScan(os.Args[1:])
	}
}
