package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type ChaosItem struct {
	Name string `json:"name"`
	URL  string `json:"URL"`
}

var chaosHttpClient = &http.Client{
	Timeout: 60 * time.Second,
}

func runChaosDataset(domain, folder string) {
	nameWithoutTLD := getDomainNameWithoutTLD(domain)

	resp, err := chaosHttpClient.Get("https://chaos-data.projectdiscovery.io/index.json")
	if err != nil {
		logWarn("Failed to fetch Chaos index")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logWarn(fmt.Sprintf("Chaos index returned HTTP %d", resp.StatusCode))
		return
	}

	var items []ChaosItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		logWarn("Failed to parse Chaos index")
		return
	}

	var matchedItem *ChaosItem
	for _, item := range items {
		if strings.EqualFold(item.Name, nameWithoutTLD) {
			matchedItem = &item
			break
		}
	}

	if matchedItem == nil {
		logInfo("No Chaos dataset available")
		return
	}

	logOK("Chaos dataset found")

	err = downloadAndUnzip(matchedItem.URL, folder)
	if err != nil {
		logWarn("Failed to download or extract Chaos dataset")
		return
	}

	logOK("Downloaded and extracted Chaos dataset")
}

func getDomainNameWithoutTLD(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, prefix := range []string{"https://", "http://"} {
		domain = strings.TrimPrefix(domain, prefix)
	}
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.TrimPrefix(domain, "www.")

	etld1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback to basic dot split logic if error
		parts := strings.Split(domain, ".")
		if len(parts) > 1 {
			last := parts[len(parts)-1]
			penultimate := parts[len(parts)-2]
			if len(last) == 2 && (penultimate == "co" || penultimate == "org" || penultimate == "net" || penultimate == "gov" || penultimate == "ac") {
				if len(parts) > 2 {
					return parts[len(parts)-3]
				}
			}
			return parts[len(parts)-2]
		}
		return domain
	}

	suffix, _ := publicsuffix.PublicSuffix(etld1)
	if suffix != "" {
		return strings.TrimSuffix(etld1, "."+suffix)
	}

	parts := strings.Split(etld1, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return etld1
}

func downloadAndUnzip(zipURL, destDir string) error {
	tmpFile, err := os.CreateTemp("", "chaos-*.zip")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	resp, err := http.Get(zipURL)
	if err != nil {
		return fmt.Errorf("download zip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return fmt.Errorf("write zip: %w", err)
	}

	_, err = tmpFile.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("seek zip: %w", err)
	}

	fi, err := tmpFile.Stat()
	if err != nil {
		return fmt.Errorf("stat zip: %w", err)
	}

	r, err := zip.NewReader(tmpFile, fi.Size())
	if err != nil {
		return fmt.Errorf("open zip reader: %w", err)
	}

	for _, f := range r.File {
		fPath := filepath.Join(destDir, filepath.Clean(f.Name))

		// Ensure it stays inside the destination directory to prevent Zip Slip
		if !strings.HasPrefix(filepath.Clean(fPath), filepath.Clean(destDir)) {
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fPath, os.ModePerm); err != nil {
				return fmt.Errorf("create dir: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fPath), os.ModePerm); err != nil {
			return fmt.Errorf("create parent dir: %w", err)
		}

		// Read the content of the zip file entry
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry: %w", err)
		}
		zipBytes, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("read zip entry: %w", err)
		}

		var finalBytes []byte
		isText := strings.HasSuffix(strings.ToLower(f.Name), ".txt")

		if isText {
			if _, err := os.Stat(fPath); err == nil {
				// File exists, merge and deduplicate lines
				existingBytes, err := os.ReadFile(fPath)
				if err == nil {
					linesMap := make(map[string]bool)
					existingStr := string(existingBytes)
					for _, line := range strings.Split(existingStr, "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							linesMap[line] = true
						}
					}
					zipStr := string(zipBytes)
					for _, line := range strings.Split(zipStr, "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							linesMap[line] = true
						}
					}

					var mergedLines []string
					for line := range linesMap {
						mergedLines = append(mergedLines, line)
					}
					finalBytes = []byte(strings.Join(mergedLines, "\n") + "\n")
				} else {
					finalBytes = zipBytes
				}
			} else {
				finalBytes = zipBytes
			}
		} else {
			finalBytes = zipBytes
		}

		outFile, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("open output file: %w", err)
		}
		_, err = outFile.Write(finalBytes)
		outFile.Close()
		if err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
	}

	return nil
}
