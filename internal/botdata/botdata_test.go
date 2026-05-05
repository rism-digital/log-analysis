package botdata

import "testing"

func TestBuildFileSplitsLiteralAlternationAndDedupes(t *testing.T) {
	file := BuildFile([]string{
		`ia_archiver|alexabot|verifybot`,
		`WireReaderBot`,
		`WireReaderBot`,
		`DuckDuck(?:Go-Favicons-)?Bot`,
	})

	if len(file.LiteralPatterns) < 4 {
		t.Fatalf("expected literal patterns, got %#v", file.LiteralPatterns)
	}
	if file.Version != SchemaVersion || file.SourceURL != SourceURL {
		t.Fatalf("unexpected metadata: %#v", file)
	}

	literals := map[string]bool{}
	for _, literal := range file.LiteralPatterns {
		literals[literal] = true
	}
	for _, expected := range []string{"WireReaderBot", "ia_archiver", "alexabot", "verifybot"} {
		if !literals[expected] {
			t.Fatalf("missing literal %q in %#v", expected, file.LiteralPatterns)
		}
	}

	hasDuckDuck := false
	for _, pattern := range file.RegexPatterns {
		if pattern == `DuckDuck(?:Go-Favicons-)?Bot` {
			hasDuckDuck = true
			break
		}
	}
	if !hasDuckDuck {
		t.Fatalf("expected regex pattern to remain in regex set: %#v", file.RegexPatterns)
	}
	hasPreludeRegex := false
	for _, pattern := range file.RegexPatterns {
		if pattern == `check_ssl_cert.*` {
			hasPreludeRegex = true
			break
		}
	}
	if !hasPreludeRegex {
		t.Fatalf("expected prelude regex pattern in regex set: %#v", file.RegexPatterns)
	}
}

func TestDecodeLiteralPattern(t *testing.T) {
	literal, ok := decodeLiteralPattern(`Cloudflare\-Healthchecks`)
	if !ok || literal != `Cloudflare-Healthchecks` {
		t.Fatalf("unexpected literal decode: %q %v", literal, ok)
	}

	if _, ok := decodeLiteralPattern(`Cloudflare-?Diagnostics`); ok {
		t.Fatal("expected optional regex pattern to be rejected as literal")
	}
}
