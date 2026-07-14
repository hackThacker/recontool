package main

// ─────────────────────────────────────────────────────────────────────────────
//
//	ReconTool – Unified recon CLI for subfinder + httpx + chaos + uncover + wayback
//
//	Author  : hackthacker
//	GitHub  : https://github.com/hackthacker/recontool
//	Version : 1.0.7
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
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// Tool metadata
// ─────────────────────────────────────────────

const (
	toolVersion  = "1.0.7"
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
// ─────────────────────────────────────────────
// Update checker
// ─────────────────────────────────────────────

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	HTMLURL string        `json:"html_url"`
	Name    string        `json:"name"`
	Assets  []githubAsset `json:"assets"`
}

// semver comparison functions
func parseSemver(v string) (major, minor, patch int, ok bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	var err error
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, false
	}
	patchPart := parts[2]
	if idx := strings.IndexAny(patchPart, "-+"); idx != -1 {
		patchPart = patchPart[:idx]
	}
	patch, err = strconv.Atoi(patchPart)
	if err != nil {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}

func isNewerVersion(current, latest string) bool {
	maj1, min1, pat1, ok1 := parseSemver(current)
	maj2, min2, pat2, ok2 := parseSemver(latest)
	if !ok1 || !ok2 {
		return current != latest
	}
	if maj2 > maj1 {
		return true
	}
	if maj2 < maj1 {
		return false
	}
	if min2 > min1 {
		return true
	}
	if min2 < min1 {
		return false
	}
	return pat2 > pat1
}

func findMatchingAsset(assets []githubAsset, osName, archName string) (githubAsset, bool) {
	for _, asset := range assets {
		name := strings.ToLower(asset.Name)

		matchesOS := false
		if osName == "darwin" {
			if strings.Contains(name, "darwin") || strings.Contains(name, "macos") || strings.Contains(name, "osx") {
				matchesOS = true
			}
		} else {
			if strings.Contains(name, osName) {
				matchesOS = true
			}
		}

		matchesArch := false
		if archName == "amd64" {
			if strings.Contains(name, "amd64") || strings.Contains(name, "x86_64") || strings.Contains(name, "x64") {
				matchesArch = true
			}
		} else if archName == "386" {
			if strings.Contains(name, "386") || strings.Contains(name, "x86") || strings.Contains(name, "i386") {
				matchesArch = true
			}
		} else {
			if strings.Contains(name, archName) {
				matchesArch = true
			}
		}

		if matchesOS && matchesArch {
			return asset, true
		}
	}
	return githubAsset{}, false
}

func replaceExecutable(newBytes []byte) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not get executable path: %w", err)
	}

	// Resolve symlinks to find the actual target binary
	if realPath, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = realPath
	}

	dir := filepath.Dir(execPath)

	// Create temporary file in the same directory
	tmpFile, err := os.CreateTemp(dir, "recontool_update_*")
	if err != nil {
		return fmt.Errorf("could not create temporary file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	// Write the binary data
	if _, err := tmpFile.Write(newBytes); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write update bytes: %w", err)
	}

	// Make it executable
	if err := tmpFile.Chmod(0755); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Replace the running executable safely
	if runtime.GOOS == "windows" {
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath)

		if err := os.Rename(execPath, oldPath); err != nil {
			return fmt.Errorf("permission denied or failed renaming running executable: %w", err)
		}

		if err := os.Rename(tmpName, execPath); err != nil {
			// Restore original
			_ = os.Rename(oldPath, execPath)
			return fmt.Errorf("failed replacing executable with new binary: %w", err)
		}
	} else {
		if err := os.Rename(tmpName, execPath); err != nil {
			return fmt.Errorf("permission denied or failed replacing executable: %w", err)
		}
	}

	return nil
}

func checkUpdate() {
	fmt.Printf("%s[UPDATE]%s Querying GitHub releases…\n", cCyan, cReset)
	client := &http.Client{Timeout: 15 * time.Second}
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
	current := strings.TrimPrefix(toolVersion, "v")

	if !isNewerVersion(current, latest) {
		fmt.Printf("Installed : v%s\n", current)
		fmt.Printf("Latest    : v%s\n", latest)
		fmt.Println("Already up to date.")
		os.Exit(0)
	}

	// Newer version exists
	logInfo("New version available: v" + latest)

	// Try to find matching precompiled release asset
	osName := runtime.GOOS
	archName := runtime.GOARCH
	asset, found := findMatchingAsset(rel.Assets, osName, archName)

	if found {
		logInfo("Downloading precompiled release binary for " + osName + "/" + archName + "...")
		logInfo("URL: " + asset.BrowserDownloadURL)

		dResp, err := client.Get(asset.BrowserDownloadURL)
		if err != nil {
			logErr("Download request failed: " + err.Error())
			os.Exit(1)
		}
		defer dResp.Body.Close()

		if dResp.StatusCode != http.StatusOK {
			logErr(fmt.Sprintf("Download failed with HTTP status code: %d", dResp.StatusCode))
			os.Exit(1)
		}

		newBytes, err := io.ReadAll(dResp.Body)
		if err != nil {
			logErr("Failed to read downloaded binary: " + err.Error())
			os.Exit(1)
		}

		logInfo("Installing update...")
		if err := replaceExecutable(newBytes); err != nil {
			if os.IsPermission(err) || strings.Contains(strings.ToLower(err.Error()), "permission denied") || strings.Contains(strings.ToLower(err.Error()), "access is denied") {
				logErr("Permission Denied: Administrator or root privileges are required to replace the binary.")
				if runtime.GOOS == "windows" {
					logInfo("Please run your terminal (PowerShell/CMD) as Administrator and try again.")
				} else {
					logInfo("Please run: sudo recontool -u")
				}
			} else {
				logErr("Update failed: " + err.Error())
			}
			os.Exit(1)
		}
	} else {
		// Fallback to "go install" if no release assets matched
		logWarn("No precompiled release asset found for " + osName + "/" + archName)
		logInfo("Falling back to compiling from source via 'go install'...")
		cmd := exec.Command("go", "install", "-v", "github.com/hackthacker/recontool@latest")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			logErr("Update failed: " + err.Error())
			logInfo("Please update manually: go install -v github.com/hackthacker/recontool@latest")
			os.Exit(1)
		}
	}

	fmt.Println("Updated successfully!")
	fmt.Printf("Old Version : v%s\n", current)
	fmt.Printf("New Version : v%s\n", latest)
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
