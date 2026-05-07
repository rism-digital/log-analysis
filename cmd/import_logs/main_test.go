package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ahankins/log-analysis/internal/botdata"
)

const sampleLogLine = "{\"remote_addr\":\"1.2.3.4\",\"request_uri\":\"/ok\",\"http_host\":\"example.org\",\"scheme\":\"https\",\"http_user_agent\":\"Mozilla/5.0\",\"http_accept\":\"text/html+json\",\"status\":\"200\",\"time_iso8601\":\"2026-05-04T10:00:00+00:00\",\"geoip_country_code\":\"CH\",\"geoip_city\":\"Zurich\",\"geoip_latitude\":\"47.37\",\"geoip_longitude\":\"8.54\",\"request_time\":\"0.123\",\"bytes_sent\":\"42\"}\n"

const sampleBZ2Base64 = "QlpoOTFBWSZTWVeSxbcAAK3fgAAQEA//0AhCBBC+//56MAD6jYinqMIDQABkAAGg1R6mmjQDQAAAAAaaRGTJPVPapsSPKaM0npNpoam0d8Pua89JjlnRwAGWWj7+7UPkqXJcSiHZQFOEe3BAYuSJHzTUqRpC84oQZhdFIoaUBgQJ8nLBaApTkCMSgQcmUWTqd3IRHoci0624rgQwjG8L89U9K2rDT8qejfQnr5KGMV6zhmg3MDKYCStrYBm4SxaBSNniwCla39KPax1u9TcYLY8KJ+9bAJsjxtk7WvcCQWmCXm5JSFCSXXSsj1k4PMEonJQ9B21ZIXgGiAdBlTD4IZ9MTwKpZlwfi7kinChIK8li24A="

func testLogger() *logger {
	return newLogger(levelDebug)
}

func testConfig() Config {
	return Config{
		Matomo: MatomoConfig{
			URL:       "https://analytics.example.com",
			AuthToken: "secret",
			IDSite:    "7",
			BatchSize: 2,
		},
		Exclude: ExcludeConfig{
			Bots:       true,
			Paths:      []string{"*autocomplete*"},
			Extensions: []string{"jpg", "css"},
		},
	}
}

func testImporter(t *testing.T, patterns []string) *Importer {
	t.Helper()
	matcher, err := compileBotMatcher(botdata.BuildFile(patterns))
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	importer, err := NewImporter(testConfig(), testLogger(), matcher)
	if err != nil {
		t.Fatalf("new importer: %v", err)
	}
	return importer
}

func mustBenchmarkImporter(b *testing.B, patterns []string) *Importer {
	b.Helper()
	matcher, err := compileBotMatcher(botdata.BuildFile(patterns))
	if err != nil {
		b.Fatalf("compile matcher: %v", err)
	}
	importer, err := NewImporter(testConfig(), newLogger(levelWarning), matcher)
	if err != nil {
		b.Fatalf("new importer: %v", err)
	}
	return importer
}

func TestParseLineCreatesHit(t *testing.T) {
	importer := testImporter(t, []string{"ExampleBot"})

	hit, outcome, err := importer.parseLine([]byte(sampleLogLine), 1)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeReal {
		t.Fatal("expected hit")
	}
	if hit.URL != "https://example.org/ok" {
		t.Fatalf("unexpected url: %s", hit.URL)
	}
	if hit.Dimension1 != "text/html%2bjson" {
		t.Fatalf("unexpected dimension1: %s", hit.Dimension1)
	}
	if hit.Country != "ch" {
		t.Fatalf("unexpected country: %s", hit.Country)
	}
}

func TestParseLineFiltersPathAndExtension(t *testing.T) {
	importer := testImporter(t, []string{"ExampleBot"})

	line := strings.Replace(sampleLogLine, "\"/ok\"", "\"/api/autocomplete?q=test\"", 1)
	_, outcome, err := importer.parseLine([]byte(line), 1)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeIgnored {
		t.Fatal("expected path-filtered line to be ignored")
	}

	line = strings.Replace(sampleLogLine, "\"/ok\"", "\"/asset/site.css\"", 1)
	_, outcome, err = importer.parseLine([]byte(line), 2)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeIgnored {
		t.Fatal("expected extension-filtered line to be ignored")
	}
}

func TestBotRegexLookbehindCompatibility(t *testing.T) {
	importer := testImporter(t, []string{`(?<!HTC)[ _]Butterfly/`})

	line := strings.Replace(sampleLogLine, "\"Mozilla/5.0\"", "\"Android Butterfly/1.0\"", 1)
	_, outcome, err := importer.parseLine([]byte(line), 1)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeBot {
		t.Fatal("expected bot line to be classified as bot")
	}

	line = strings.Replace(sampleLogLine, "\"Mozilla/5.0\"", "\"HTC Butterfly/1.0\"", 1)
	_, outcome, err = importer.parseLine([]byte(line), 2)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeReal {
		t.Fatal("expected HTC line to remain")
	}
}

func TestGetIPAddressKeepsRemoteForInvalidForwardedValue(t *testing.T) {
	value, err := getIPAddress(&logRecord{
		RemoteAddr:        "1.2.3.4",
		HTTPXForwardedFor: "1.2.3.4,5.6.7.8",
	}, testLogger())
	if err != nil {
		t.Fatalf("getIPAddress error: %v", err)
	}
	if value != "1.2.3.4" {
		t.Fatalf("unexpected client ip: %s", value)
	}
}

func TestFlexibleStringAllowsNumbers(t *testing.T) {
	importer := testImporter(t, []string{"ExampleBot"})

	line := "{\"remote_addr\":\"1.2.3.4\",\"request_uri\":\"/ok\",\"http_host\":\"example.org\",\"scheme\":\"https\",\"http_user_agent\":\"Mozilla/5.0\",\"http_accept\":\"text/html+json\",\"status\":200,\"time_iso8601\":\"2026-05-04T10:00:00+00:00\",\"geoip_country_code\":\"CH\",\"geoip_city\":\"Zurich\",\"geoip_latitude\":47.37,\"geoip_longitude\":8.54,\"request_time\":0.123,\"bytes_sent\":42}\n"
	hit, outcome, err := importer.parseLine([]byte(line), 1)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeReal {
		t.Fatal("expected hit")
	}
	if hit.Dimension2 != "200" || hit.BWBytes != "42" || hit.Lat != "47.37" {
		t.Fatalf("unexpected coerced values: %#v", hit)
	}
}

func TestBotMatcherUsesLiteralAndRegexPaths(t *testing.T) {
	matcher, err := compileBotMatcher(botdata.BuildFile([]string{`Cloudflare\-Healthchecks`, `(?<!HTC)[ _]Butterfly/`}))
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}

	matched, err := matcher.MatchString("Cloudflare-Healthchecks")
	if err != nil {
		t.Fatalf("literal match error: %v", err)
	}
	if !matched {
		t.Fatal("expected literal matcher to match")
	}

	matched, err = matcher.MatchString("Android Butterfly/1.0")
	if err != nil {
		t.Fatalf("regex match error: %v", err)
	}
	if !matched {
		t.Fatal("expected regex matcher to match")
	}

	matched, err = matcher.MatchString("Mozilla/5.0")
	if err != nil {
		t.Fatalf("non-match error: %v", err)
	}
	if matched {
		t.Fatal("expected non-bot user agent to stay unmatched")
	}
}

func TestNormalizeRequestPath(t *testing.T) {
	if got := normalizeRequestPath("//double/slash"); got != "/double/slash" {
		t.Fatalf("unexpected normalized path: %s", got)
	}
}

func TestCutBeforeQueryAndExtractExtension(t *testing.T) {
	if got := cutBeforeQuery("/path/file.css?x=1"); got != "/path/file.css" {
		t.Fatalf("unexpected cutBeforeQuery result: %s", got)
	}
	if got := extractExtension("/path/file.css"); got != "css" {
		t.Fatalf("unexpected extension: %s", got)
	}
	if got := extractExtension("/path.with.dot/file"); got != "" {
		t.Fatalf("unexpected extension for extensionless path: %s", got)
	}
}

func TestCIDRFiltering(t *testing.T) {
	cfg := testConfig()
	cfg.Exclude.Addresses = []string{"1.2.3.0/24"}
	matcher, err := compileBotMatcher(botdata.BuildFile([]string{"ExampleBot"}))
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	importer, err := NewImporter(cfg, testLogger(), matcher)
	if err != nil {
		t.Fatalf("new importer: %v", err)
	}

	_, outcome, err := importer.parseLine([]byte(sampleLogLine), 1)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeIgnored {
		t.Fatal("expected CIDR-filtered line to be ignored")
	}
}

func TestParseLineMalformedJSONIsError(t *testing.T) {
	importer := testImporter(t, []string{"ExampleBot"})

	_, outcome, err := importer.parseLine([]byte("{nope\n"), 1)
	if err != nil {
		t.Fatalf("parseLine error: %v", err)
	}
	if outcome != lineOutcomeError {
		t.Fatalf("expected error outcome, got %v", outcome)
	}
}

func TestParseLogFileDryRunHandlesPlainGzipAndBzip2(t *testing.T) {
	importer := testImporter(t, []string{"ExampleBot"})
	dir := t.TempDir()

	plainPath := filepath.Join(dir, "sample.log")
	if err := os.WriteFile(plainPath, []byte(sampleLogLine), 0o644); err != nil {
		t.Fatalf("write plain file: %v", err)
	}

	gzipPath := filepath.Join(dir, "sample.log.gz")
	gzFile, err := os.Create(gzipPath)
	if err != nil {
		t.Fatalf("create gzip file: %v", err)
	}
	gzWriter := gzip.NewWriter(gzFile)
	if _, err := gzWriter.Write([]byte(sampleLogLine)); err != nil {
		t.Fatalf("write gzip data: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := gzFile.Close(); err != nil {
		t.Fatalf("close gzip file: %v", err)
	}

	bzipPath := filepath.Join(dir, "sample.log.bz2")
	bzipData, err := base64.StdEncoding.DecodeString(sampleBZ2Base64)
	if err != nil {
		t.Fatalf("decode bzip test data: %v", err)
	}
	if err := os.WriteFile(bzipPath, bzipData, 0o644); err != nil {
		t.Fatalf("write bzip file: %v", err)
	}

	for _, path := range []string{plainPath, gzipPath, bzipPath} {
		if _, ok := importer.parseLogFile(path, true); !ok {
			t.Fatalf("expected dry-run success for %s", path)
		}
	}
}

func TestSubmitHitsAndBatching(t *testing.T) {
	var requests []matomoPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload matomoPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		requests = append(requests, payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Matomo.URL = server.URL
	cfg.Matomo.BatchSize = 2
	matcher, err := compileBotMatcher(botdata.BuildFile([]string{"ExampleBot"}))
	if err != nil {
		t.Fatalf("compile matcher: %v", err)
	}
	importer, err := NewImporter(cfg, testLogger(), matcher)
	if err != nil {
		t.Fatalf("new importer: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "batch.log")
	content := sampleLogLine + strings.Replace(sampleLogLine, "\"/ok\"", "\"/second\"", 1) + strings.Replace(sampleLogLine, "\"/ok\"", "\"/third\"", 1)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write batch file: %v", err)
	}

	if _, ok := importer.parseLogFile(path, false); !ok {
		t.Fatal("expected upload success")
	}
	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
	if len(requests[0].Requests) != 2 || len(requests[1].Requests) != 1 {
		t.Fatalf("unexpected batch sizes: %d and %d", len(requests[0].Requests), len(requests[1].Requests))
	}
	if requests[0].TokenAuth != "secret" {
		t.Fatalf("unexpected token auth: %s", requests[0].TokenAuth)
	}
}

func TestParseArgsAllowsInterspersedFlags(t *testing.T) {
	args, err := parseArgs([]string{"first.log", "--dry-run", "-c", "config-muscat.toml", "second.log"})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}
	if !args.DryRun {
		t.Fatal("expected dry-run to be true")
	}
	if args.Config != "config-muscat.toml" {
		t.Fatalf("unexpected config: %s", args.Config)
	}
	if len(args.LogFiles) != 2 {
		t.Fatalf("unexpected logfiles: %#v", args.LogFiles)
	}
	if args.BotsFile != "bots.json" {
		t.Fatalf("unexpected default bots file: %s", args.BotsFile)
	}
}

func TestParseArgsReportImpliesDryRun(t *testing.T) {
	args, err := parseArgs([]string{"--report", "first.log"})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}
	if !args.Report || !args.DryRun {
		t.Fatalf("expected report and dry-run to be true: %#v", args)
	}
}

func TestParseArgsSupportsBotsFile(t *testing.T) {
	args, err := parseArgs([]string{"--bots-file", "/opt/log-analysis/bots.json", "first.log"})
	if err != nil {
		t.Fatalf("parseArgs error: %v", err)
	}
	if args.BotsFile != "/opt/log-analysis/bots.json" {
		t.Fatalf("unexpected bots file: %s", args.BotsFile)
	}
}

func TestRenderReportTableIncludesTotal(t *testing.T) {
	stats := []fileStats{
		{FilePath: "a.log", Total: 10, Real: 4, Bot: 3, Ignored: 2, Errors: 1},
		{FilePath: "b.log", Total: 20, Real: 8, Bot: 6, Ignored: 4, Errors: 2},
	}

	report := renderReportTable(stats)
	for _, expected := range []string{"File", "Real", "Bot", "Ignored", "Errors", "a.log", "b.log", "TOTAL"} {
		if !strings.Contains(report, expected) {
			t.Fatalf("report missing %q:\n%s", expected, report)
		}
	}
	if !strings.Contains(report, " 12 ") {
		t.Fatalf("report missing total real count:\n%s", report)
	}
}

func TestRenderTopBotUserAgents(t *testing.T) {
	stats := []fileStats{
		{
			FilePath: "a.log",
			BotUserAgents: map[string]int{
				"Bot A": 2,
				"Bot B": 1,
			},
		},
		{
			FilePath: "b.log",
			BotUserAgents: map[string]int{
				"Bot A": 3,
				"Bot C": 4,
				"Bot D": 1,
				"Bot E": 1,
				"Bot F": 1,
			},
		},
	}

	report := renderTopBotUserAgents(stats, 5)
	for _, expected := range []string{"Top Bot User Agents", "1. Bot A (5)", "2. Bot C (4)"} {
		if !strings.Contains(report, expected) {
			t.Fatalf("top bot report missing %q:\n%s", expected, report)
		}
	}
	if strings.Contains(report, "Bot F") {
		t.Fatalf("expected top 5 limit to exclude Bot F:\n%s", report)
	}
}

func benchmarkImporter(b *testing.B) *Importer {
	b.Helper()
	return mustBenchmarkImporter(b, []string{"ExampleBot", `(?<!HTC)[ _]Butterfly/`})
}

func benchmarkLogLines(count int) []byte {
	var builder strings.Builder
	builder.Grow(len(sampleLogLine) * count)
	for i := 0; i < count; i++ {
		line := sampleLogLine
		switch i % 4 {
		case 1:
			line = strings.Replace(line, "\"/ok\"", "\"/asset/site.css\"", 1)
		case 2:
			line = strings.Replace(line, "\"Mozilla/5.0\"", "\"Android Butterfly/1.0\"", 1)
		case 3:
			line = strings.Replace(line, "\"/ok\"", "\"/api/autocomplete?q=test\"", 1)
		}
		builder.WriteString(line)
	}
	return []byte(builder.String())
}

func BenchmarkParseLine(b *testing.B) {
	importer := benchmarkImporter(b)
	line := []byte(sampleLogLine)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := importer.parseLine(line, i+1)
		if err != nil {
			b.Fatalf("parseLine error: %v", err)
		}
	}
}

func BenchmarkParseLineBotFiltered(b *testing.B) {
	importer := benchmarkImporter(b)
	line := []byte(strings.Replace(sampleLogLine, "\"Mozilla/5.0\"", "\"Android Butterfly/1.0\"", 1))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := importer.parseLine(line, i+1)
		if err != nil {
			b.Fatalf("parseLine error: %v", err)
		}
	}
}

func BenchmarkBotMatcherLiteral(b *testing.B) {
	matcher, err := compileBotMatcher(botdata.BuildFile([]string{`Cloudflare\-Healthchecks`, `(?<!HTC)[ _]Butterfly/`}))
	if err != nil {
		b.Fatalf("compile matcher: %v", err)
	}
	ua := "Cloudflare-Healthchecks"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matched, err := matcher.MatchString(ua)
		if err != nil {
			b.Fatalf("MatchString error: %v", err)
		}
		if !matched {
			b.Fatal("expected literal bot match")
		}
	}
}

func BenchmarkBotMatcherRegex(b *testing.B) {
	matcher, err := compileBotMatcher(botdata.BuildFile([]string{`Cloudflare\-Healthchecks`, `(?<!HTC)[ _]Butterfly/`}))
	if err != nil {
		b.Fatalf("compile matcher: %v", err)
	}
	ua := "Android Butterfly/1.0"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matched, err := matcher.MatchString(ua)
		if err != nil {
			b.Fatalf("MatchString error: %v", err)
		}
		if !matched {
			b.Fatal("expected regex bot match")
		}
	}
}

func BenchmarkBotMatcherMiss(b *testing.B) {
	matcher, err := compileBotMatcher(botdata.BuildFile([]string{`Cloudflare\-Healthchecks`, `(?<!HTC)[ _]Butterfly/`}))
	if err != nil {
		b.Fatalf("compile matcher: %v", err)
	}
	ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matched, err := matcher.MatchString(ua)
		if err != nil {
			b.Fatalf("MatchString error: %v", err)
		}
		if matched {
			b.Fatal("expected non-bot user agent to miss")
		}
	}
}

func BenchmarkParseLogBuffer(b *testing.B) {
	importer := benchmarkImporter(b)
	logData := benchmarkLogLines(2000)
	b.SetBytes(int64(len(logData)))
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bufio.NewReader(bytes.NewReader(logData))
		lineNo := 0
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil && err != io.EOF {
				b.Fatalf("read error: %v", err)
			}
			if len(line) > 0 {
				lineNo++
				if _, _, err := importer.parseLine(line, lineNo); err != nil {
					b.Fatalf("parseLine error: %v", err)
				}
			}
			if err == io.EOF {
				break
			}
		}
	}
}

func BenchmarkParseLogFileFixture(b *testing.B) {
	fixturePath := os.Getenv("LOG_ANALYSIS_BENCH_FILE")
	if fixturePath == "" {
		b.Skip("set LOG_ANALYSIS_BENCH_FILE to benchmark a local logfile fixture")
	}

	info, err := os.Stat(fixturePath)
	if err != nil {
		b.Fatalf("stat fixture: %v", err)
	}

	importer := benchmarkImporter(b)
	b.SetBytes(info.Size())
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := importer.parseLogFile(fixturePath, true); !ok {
			b.Fatalf("parseLogFile returned failure")
		}
	}
}
