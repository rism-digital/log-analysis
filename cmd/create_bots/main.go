package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/ahankins/log-analysis/internal/botdata"
	"gopkg.in/yaml.v3"
)

type botEntry struct {
	Regex string `yaml:"regex"`
}

func main() {
	output := flag.String("output", "bots.json", "Output file path")
	flag.StringVar(output, "o", "bots.json", "Output file path")
	flag.Parse()

	fmt.Println("Downloading latest bots.yml...")
	ymlContent, err := downloadYAML(botdata.SourceURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Extracting regex patterns...")
	patterns, err := extractPatterns(ymlContent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract failed: %v\n", err)
		os.Exit(1)
	}

	file := botdata.BuildFile(patterns)
	payload, err := file.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Writing %d literal and %d regex patterns to %q...\n", len(file.LiteralPatterns), len(file.RegexPatterns), *output)
	if err := os.WriteFile(*output, append(payload, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Done.")
}

func downloadYAML(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func extractPatterns(ymlContent []byte) ([]string, error) {
	var entries []botEntry
	if err := yaml.Unmarshal(ymlContent, &entries); err != nil {
		return nil, err
	}

	patterns := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Regex == "" {
			continue
		}
		patterns = append(patterns, entry.Regex)
	}
	return patterns, nil
}
