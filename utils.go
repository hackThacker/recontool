package main

// ─────────────────────────────────────────────────────────────────────────────
//  Shared utilities: colours, logging, file I/O, domain normalisation
// ─────────────────────────────────────────────────────────────────────────────

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ── ANSI colours ──────────────────────────────────────────────────────────────
const (
	cReset  = "\033[0m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cMag    = "\033[35m"
	cBlue   = "\033[34m"
	cBold   = "\033[1m"
)

// ── Logging ───────────────────────────────────────────────────────────────────
func logInfo(msg string) { fmt.Println(cCyan + "[INFO] " + cReset + msg) }
func logOK(msg string)   { fmt.Println(cGreen + "[SUCCESS] " + cReset + msg) }
func logWarn(msg string) { fmt.Println(cYellow + "[WARNING] " + cReset + msg) }
func logErr(msg string)  { fmt.Println(cRed + "[ERR] " + cReset + msg) }
func logStep(msg string) { fmt.Println(cMag + cBold + "[STEP] " + cReset + cBold + msg + cReset) }

// ── Domain ────────────────────────────────────────────────────────────────────

// normaliseDomain strips scheme, www prefix and trailing slash.
//
//	www.example.com       → example.com
//	https://example.com/  → example.com
func normaliseDomain(raw string) string {
	d := strings.TrimSpace(raw)
	for _, p := range []string{"https://", "http://"} {
		d = strings.TrimPrefix(d, p)
	}
	d = strings.TrimSuffix(d, "/")
	d = strings.TrimPrefix(d, "www.")
	return strings.ToLower(d)
}

// ── File I/O ──────────────────────────────────────────────────────────────────

// writeLines writes a []string to a file, one line each.
// Always creates / truncates, even when lines is empty.
func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err2 := fmt.Fprintln(w, l); err2 != nil {
			return err2
		}
	}
	return w.Flush()
}

// readLines reads all non-blank lines from a file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanLines(bufio.NewScanner(f)), nil
}

// nonEmptyLines splits a raw multi-line string into trimmed non-blank lines.
func nonEmptyLines(raw string) []string {
	return scanLines(bufio.NewScanner(strings.NewReader(raw)))
}

func scanLines(sc *bufio.Scanner) []string {
	var out []string
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// statusFamily maps HTTP status code → family string.
func statusFamily(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "other"
	}
}

// newStdinReader returns a buffered reader from os.Stdin.
func newStdinReader() *bufio.Reader {
	return bufio.NewReader(os.Stdin)
}
