package main

import "testing"

func TestExtractPatterns(t *testing.T) {
	content := []byte(`
- regex: 'WireReaderBot'
  name: 'WireReaderBot'
- regex: 'ia_archiver|alexabot|verifybot'
  name: 'Alexa Crawler'
`)

	patterns, err := extractPatterns(content)
	if err != nil {
		t.Fatalf("extractPatterns error: %v", err)
	}
	if len(patterns) != 2 {
		t.Fatalf("unexpected pattern count: %d", len(patterns))
	}
	if patterns[0] != "WireReaderBot" || patterns[1] != "ia_archiver|alexabot|verifybot" {
		t.Fatalf("unexpected patterns: %#v", patterns)
	}
}
