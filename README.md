<div align="center">

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
```

**A unified, terminal-based recon tool for bug bounty hunters and pentesters.**  
Combines **subfinder · httpx · chaos · uncover · Wayback CDX** into one powerful CLI.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-hackthacker-red)](https://github.com/hackthacker)
[![Release](https://img.shields.io/github/v/release/hackthacker/recontool?color=blue)](https://github.com/hackthacker/recontool/releases)

</div>

---

## ⚡ Installation

### One-line Install (recommended)
```bash
go install -v github.com/hackthacker/recontool@latest
```
> Requires **Go 1.21+**. After install, the `recontool` binary is available in `$GOPATH/bin` (or `~/go/bin`).

### From Source
```bash
git clone https://github.com/hackthacker/recontool
cd recontool
go build -o recontool .
./recontool -h
```

---

## 🚀 Quick Start

```bash
# Full automated recon pipeline (everything at once)
recontool -d example.com

# With chaos (projectdiscovery cloud key)
recontool scan -d example.com -key YOUR_PDCP_KEY

# With uncover OSINT search
recontool scan -d example.com -key PDCP_KEY -uq "ssl:example.com" -ue shodan,censys
```

---

## 📖 Commands

```
recontool [command] [flags]

COMMANDS:
  scan        Full automated recon pipeline
  subfinder   Run subfinder subdomain enumeration
  httpx       Run httpx HTTP probing
  chaos       Run chaos subdomain search
  uncover     Run uncover OSINT search

GLOBAL:
  -v, --version    Show version info
  -h, --help       Show help
  -u, --update     Check for updates on GitHub
```

---

## 🔁 Full Pipeline — `recontool scan`

Runs **5 tools in sequence**, saves all output inside a `<domain>/` folder:

```bash
recontool scan -d example.com
```

### Pipeline Steps

| Step | Tool | Output File |
|------|------|------------|
| 1 | Wayback CDX (4 queries) | `wayback_main.txt`, `wayback_wildcard.txt`, `wayback_specific.txt`, `wayback_sensitive.txt` |
| 2 | subfinder | `subfinder.txt` |
| 3 | chaos *(optional, needs `-key`)* | `chaos.txt` |
| 4 | httpx (all status codes) | `httpx.txt`, `1xx.txt`, `2xx.txt`, `3xx.txt`, `4xx.txt`, `5xx.txt` |
| 5 | uncover *(optional, needs `-uq`)* | `uncover.txt` |

### Scan Flags

```
  -d string       target domain (required)
  -key string     ProjectDiscovery Cloud API key (or set PDCP_API_KEY env)
  -uq string      uncover search query  (e.g. 'ssl:example.com')
  -ue string      uncover engine(s)     (default: shodan)
  -ul int         uncover result limit  (default: 100)
  -sf-all         use ALL subfinder sources (slow but thorough)
  -sf-timeout int subfinder timeout in seconds (default: 30)
  -sf-threads int subfinder goroutines (default: 10)
  -hx-threads int httpx threads (default: 50)
  -hx-timeout int httpx timeout (default: 10)
  -hx-title       show page titles in httpx results
  -hx-td          show technologies (wappalyzer)
  -silent         suppress progress logs
  -o string       custom output folder name
```

---

## 🔍 subfinder

Full subfinder subdomain enumeration with **all flags**:

```bash
recontool subfinder -d example.com
recontool subfinder -d example.com -all -silent -o subs.txt
recontool subfinder -dL domains.txt -s shodan,crtsh -json
recontool subfinder -h   # show all flags
```

| Flag | Description |
|------|-------------|
| `-d` | Domain(s) to enumerate (comma-separated) |
| `-dL` | File containing list of domains |
| `-s` | Specific sources (`-s crtsh,github,shodan`) |
| `-all` | Use all available sources (slow) |
| `-recursive` | Use only recursive sources |
| `-es` | Exclude sources |
| `-o` | Output file |
| `-oJ` | JSONL output |
| `-silent` | Only print subdomains |
| `-rl` | Rate limit (requests/sec) |
| `-t` | Threads (default: 10) |
| `-timeout` | Timeout in seconds |
| `-proxy` | HTTP proxy |
| `-config` | Config file path |
| `-pc` | Provider config file |

---

## 🌐 httpx

Full HTTP probing with **all flags** + status-family splitting:

```bash
recontool httpx -l subfinder.txt -sc -title
recontool httpx -l hosts.txt -mc 200 -o live.txt -save-filtered
recontool httpx -u example.com -sc -json -o results.json
recontool httpx -h   # show all flags
```

| Flag | Description |
|------|-------------|
| `-l` | Input file of hosts |
| `-u` | Target host(s) to probe |
| `-sc` | Show status code |
| `-title` | Show page title |
| `-server` | Show server name |
| `-td` | Show technologies (wappalyzer) |
| `-ct` | Show content-type |
| `-rt` | Show response time |
| `-ip` | Show host IP |
| `-cdn` | Show CDN/WAF |
| `-mc` | Match status codes (`-mc 200,301`) |
| `-fc` | Filter status codes (`-fc 404,403`) |
| `-ms` | Match response string |
| `-fs` | Filter response string |
| `-j` | JSONL output |
| `-o` | Output file |
| `-save-filtered` | Save `1xx/2xx/3xx/4xx/5xx.txt` files |
| `-t` | Threads (default: 50) |
| `-timeout` | Timeout (default: 10s) |
| `-proxy` | HTTP/SOCKS proxy |
| `-fr` | Follow redirects |

---

## 💥 chaos

ProjectDiscovery Cloud subdomain dataset:

```bash
recontool chaos -d example.com -key YOUR_PDCP_KEY
recontool chaos -dL domains.txt -key PDCP_KEY -o subs.txt
recontool chaos -d example.com -key PDCP_KEY -count
recontool chaos -h   # show all flags
```

| Flag | Description |
|------|-------------|
| `-key` | PDCP API key (or set `PDCP_API_KEY` env) |
| `-d` | Domain to search |
| `-dL` | File of domains |
| `-count` | Show subdomain count only |
| `-json` | JSONL output |
| `-o` | Output file |
| `-silent` | Only print results |

> Get your free API key at [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)

---

## 🔭 uncover

OSINT search across 15+ engines (Shodan, Censys, Fofa, etc.):

```bash
recontool uncover -q "org:example.com" -e shodan,censys,fofa
recontool uncover -shodan "ssl:example.com" -j -o results.json
recontool uncover -fofa "domain=example.com" -l 500
recontool uncover -h   # show all flags
```

| Flag | Description |
|------|-------------|
| `-q` | Search query |
| `-e` | Engine(s): `shodan,fofa,censys,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow,google,onyphe,driftnet,daydaymap` |
| `-asq` | Awesome search queries (e.g. `jira`) |
| `-s` | Query for shodan |
| `-ff` | Query for fofa |
| `-cs` | Query for censys |
| `-l` | Limit results (default: 100) |
| `-j` | JSONL output |
| `-f` | Field: `ip,port,host` (default: `ip:port`) |
| `-o` | Output file |
| `-proxy` | HTTP proxy |

> Configure engine API keys in: `~/.config/uncover/provider-config.yaml`

---

## 🕰️ Wayback CDX

Automatically queries **4 Wayback Machine CDX endpoints** per domain:

| File | Query |
|------|-------|
| `wayback_main.txt` | `url=www.domain/*` — all archived URLs |
| `wayback_wildcard.txt` | `url=*.www.domain/*` — wildcard subdomains |
| `wayback_specific.txt` | `url=https://www.domain/en/*` — specific path |
| `wayback_sensitive.txt` | Filtered: `xls,xml,pdf,sql,zip,env,key,pem,config,bak,log...` |

---

## 📁 Output Structure

Running `recontool -d example.com` creates:

```
example.com/
├── subfinder.txt         ← all discovered subdomains
├── chaos.txt             ← chaos subdomains (if -key given)
├── httpx.txt             ← ALL HTTP probe results
├── 1xx.txt               ← informational (100–199)
├── 2xx.txt               ← success (200–299)
├── 3xx.txt               ← redirects (300–399)
├── 4xx.txt               ← client errors (400–499)
├── 5xx.txt               ← server errors (500–599)
├── wayback_main.txt
├── wayback_wildcard.txt
├── wayback_specific.txt
├── wayback_sensitive.txt
└── uncover.txt           ← OSINT results (if -uq given)
```

---

## 🛠️ Requirements

- **Go 1.21+**
- Optional: [PDCP API key](https://cloud.projectdiscovery.io) for `chaos`
- Optional: Engine API keys in `~/.config/uncover/provider-config.yaml` for `uncover`

---

## 📦 Powered By

| Package | Purpose |
|---------|---------|
| [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration |
| [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | HTTP probing |
| [projectdiscovery/chaos-client](https://github.com/projectdiscovery/chaos-client) | Chaos DB subdomains |
| [projectdiscovery/uncover](https://github.com/projectdiscovery/uncover) | OSINT engine search |
| Wayback CDX API | Historical URL discovery |

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
Made with ❤️ by <a href="https://github.com/hackthacker"><b>hackthacker</b></a>
</div>
