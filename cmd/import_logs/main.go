package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ahankins/log-analysis/internal/botdata"
	"github.com/cloudflare/ahocorasick"
	"github.com/dlclark/regexp2"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	segmentjson "github.com/segmentio/encoding/json"
)

var (
	gzipMagic = []byte{0x1f, 0x8b}
	bz2Magic  = []byte{'B', 'Z'}
)

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarning
)

type logger struct {
	level logLevel
	base  zerolog.Logger
}

func newLogger(level logLevel) *logger {
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	var zeroLevel zerolog.Level
	switch level {
	case levelDebug:
		zeroLevel = zerolog.DebugLevel
	case levelInfo:
		zeroLevel = zerolog.InfoLevel
	default:
		zeroLevel = zerolog.WarnLevel
	}

	return &logger{
		level: level,
		base:  zerolog.New(output).Level(zeroLevel).With().Timestamp().Logger(),
	}
}

func (l *logger) logf(level logLevel, label string, format string, args ...any) {
	switch label {
	case "DEBUG":
		l.base.Debug().Msgf(format, args...)
	case "INFO":
		l.base.Info().Msgf(format, args...)
	case "WARNING":
		l.base.Warn().Msgf(format, args...)
	case "ERROR":
		l.base.Error().Msgf(format, args...)
	default:
		l.base.Log().Msgf(format, args...)
	}
}

func (l *logger) Debugf(format string, args ...any) { l.logf(levelDebug, "DEBUG", format, args...) }
func (l *logger) Infof(format string, args ...any)  { l.logf(levelInfo, "INFO", format, args...) }
func (l *logger) Warnf(format string, args ...any)  { l.logf(levelWarning, "WARNING", format, args...) }
func (l *logger) Errorf(format string, args ...any) { l.logf(levelWarning, "ERROR", format, args...) }

type cliArgs struct {
	LogFiles    []string
	Config      string
	BotsFile    string
	Debug       bool
	Verbose     bool
	DryRun      bool
	Report      bool
	MatomoDebug bool
}

type Config struct {
	Matomo  MatomoConfig  `toml:"matomo"`
	Exclude ExcludeConfig `toml:"exclude"`
}

type MatomoConfig struct {
	URL        string `toml:"url"`
	AuthToken  string `toml:"auth_token"`
	IDSite     string `toml:"idsite"`
	BatchSize  int    `toml:"batch_size"`
	HTTPSProxy string `toml:"https_proxy"`
}

type ExcludeConfig struct {
	Bots       bool     `toml:"bots"`
	Paths      []string `toml:"paths"`
	Extensions []string `toml:"extensions"`
	Addresses  []string `toml:"addresses"`
}

type parsedLineContext struct {
	jsonRecord      *logRecord
	requestPath     string
	requestPathOnly string
	clientIP        string
	userAgent       string
}

type lineOutcome int

const (
	lineOutcomeReal lineOutcome = iota
	lineOutcomeBot
	lineOutcomeIgnored
	lineOutcomeError
)

type fileStats struct {
	FilePath      string
	Total         int
	Real          int
	Bot           int
	Ignored       int
	Errors        int
	BotUserAgents map[string]int
}

type matomoDiagnostics struct {
	SubmittedBatches int
	SubmittedHits    int
	TrackedHits      int
	InvalidHits      int
	UnknownHits      int
	ReasonCounts     map[string]int
	ParseErrors      int
}

type matomoBulkResponse struct {
	Status          string `json:"status"`
	Message         string `json:"message"`
	Tracked         *int   `json:"tracked"`
	Invalid         *int   `json:"invalid"`
	InvalidRequests []any  `json:"invalid_requests"`
}

func newMatomoDiagnostics() *matomoDiagnostics {
	return &matomoDiagnostics{
		ReasonCounts: make(map[string]int),
	}
}

func (d *matomoDiagnostics) addBatchResult(batchSize int, body []byte) {
	d.SubmittedBatches++
	d.SubmittedHits += batchSize

	var parsed matomoBulkResponse
	if err := segmentjson.Unmarshal(body, &parsed); err != nil {
		d.ParseErrors++
		d.UnknownHits += batchSize
		return
	}

	tracked := 0
	if parsed.Tracked != nil {
		tracked = *parsed.Tracked
	}
	invalid := 0
	if parsed.Invalid != nil {
		invalid = *parsed.Invalid
	}

	d.TrackedHits += tracked
	d.InvalidHits += invalid
	unknown := batchSize - tracked - invalid
	if unknown > 0 {
		d.UnknownHits += unknown
	}

	if len(parsed.InvalidRequests) > 0 {
		for _, reason := range parsed.InvalidRequests {
			message := strings.TrimSpace(fmt.Sprint(reason))
			if message == "" {
				message = "(empty reason)"
			}
			d.ReasonCounts[message]++
		}
	}

	if parsed.Message != "" && invalid == 0 {
		d.ReasonCounts[strings.TrimSpace(parsed.Message)]++
	}
}

func (d *matomoDiagnostics) render(limit int) string {
	if d == nil {
		return ""
	}

	var out strings.Builder
	out.WriteString("\nMatomo Batch Diagnostics\n")
	out.WriteString("=======================\n")
	fmt.Fprintf(&out, "Batches: %d\n", d.SubmittedBatches)
	fmt.Fprintf(&out, "Submitted hits: %d\n", d.SubmittedHits)
	fmt.Fprintf(&out, "Tracked hits: %d\n", d.TrackedHits)
	fmt.Fprintf(&out, "Invalid hits: %d\n", d.InvalidHits)
	fmt.Fprintf(&out, "Unknown status hits: %d\n", d.UnknownHits)
	fmt.Fprintf(&out, "Response parse errors: %d\n", d.ParseErrors)

	if len(d.ReasonCounts) == 0 {
		return out.String()
	}

	type reasonPair struct {
		Reason string
		Count  int
	}
	reasons := make([]reasonPair, 0, len(d.ReasonCounts))
	for reason, count := range d.ReasonCounts {
		reasons = append(reasons, reasonPair{Reason: reason, Count: count})
	}
	sort.Slice(reasons, func(i, j int) bool {
		if reasons[i].Count != reasons[j].Count {
			return reasons[i].Count > reasons[j].Count
		}
		return reasons[i].Reason < reasons[j].Reason
	})
	if limit > 0 && len(reasons) > limit {
		reasons = reasons[:limit]
	}

	out.WriteString("Top invalid reasons:\n")
	for index, item := range reasons {
		fmt.Fprintf(&out, "%d. %s (%d)\n", index+1, item.Reason, item.Count)
	}
	return out.String()
}

func (s *fileStats) addOutcome(outcome lineOutcome) {
	s.Total++
	switch outcome {
	case lineOutcomeReal:
		s.Real++
	case lineOutcomeBot:
		s.Bot++
	case lineOutcomeIgnored:
		s.Ignored++
	case lineOutcomeError:
		s.Errors++
	}
}

func (s *fileStats) addBotUserAgent(userAgent string) {
	if userAgent == "" {
		userAgent = "(empty)"
	}
	if s.BotUserAgents == nil {
		s.BotUserAgents = make(map[string]int)
	}
	s.BotUserAgents[userAgent]++
}

func (s fileStats) percent(value int) float64 {
	if s.Total == 0 {
		return 0
	}
	return (float64(value) / float64(s.Total)) * 100
}

type flexibleString string

func (s *flexibleString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*s = ""
		return nil
	}

	if len(data) > 0 && data[0] == '"' {
		var decoded string
		if err := segmentjson.Unmarshal(data, &decoded); err != nil {
			return err
		}
		*s = flexibleString(decoded)
		return nil
	}

	*s = flexibleString(string(data))
	return nil
}

func (s flexibleString) String() string {
	return string(s)
}

type logRecord struct {
	RemoteAddr        flexibleString `json:"remote_addr"`
	HTTPXForwardedFor flexibleString `json:"http_x_forwarded_for"`
	RequestURI        flexibleString `json:"request_uri"`
	HTTPUserAgent     flexibleString `json:"http_user_agent"`
	HTTPHost          flexibleString `json:"http_host"`
	Scheme            flexibleString `json:"scheme"`
	HTTPAccept        flexibleString `json:"http_accept"`
	HTTPReferer       flexibleString `json:"http_referer"`
	Status            flexibleString `json:"status"`
	TimeISO8601       flexibleString `json:"time_iso8601"`
	GeoIPCountryCode  flexibleString `json:"geoip_country_code"`
	GeoIPCity         flexibleString `json:"geoip_city"`
	GeoIPLatitude     flexibleString `json:"geoip_latitude"`
	GeoIPLongitude    flexibleString `json:"geoip_longitude"`
	RequestTime       flexibleString `json:"request_time"`
	BytesSent         flexibleString `json:"bytes_sent"`
	RequestID         flexibleString `json:"request_id"`
}

type Hit struct {
	URL            string `json:"url"`
	URLRef         string `json:"urlref"`
	UA             string `json:"ua"`
	CDT            string `json:"cdt"`
	CIP            string `json:"cip"`
	Country        string `json:"country"`
	City           string `json:"city"`
	Lat            string `json:"lat"`
	Long           string `json:"long"`
	PFSrv          string `json:"pf_srv"`
	BWBytes        string `json:"bw_bytes"`
	APIV           string `json:"apiv"`
	Rec            string `json:"rec"`
	IDSite         string `json:"idsite"`
	QueuedTracking string `json:"queuedtracking"`
	DP             string `json:"dp"`
	Dimension1     string `json:"dimension1"`
	Dimension2     string `json:"dimension2"`
}

type matomoPayload struct {
	TokenAuth string `json:"token_auth"`
	Requests  []Hit  `json:"requests"`
}

type BotMatcher struct {
	literalMatcher *ahocorasick.Matcher
	regex          *regexp2.Regexp
	cache          map[string]bool
	cacheKeys      []string
	cacheNext      int
}

const botMatcherCacheSize = 4096

func loadBotMatcher(paths []string) (*BotMatcher, string, error) {
	var lastErr error
	for _, path := range paths {
		if path == "" {
			continue
		}

		data, err := loadBotPatterns(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				lastErr = err
				continue
			}
			return nil, "", err
		}

		matcher, err := compileBotMatcher(data)
		if err != nil {
			return nil, "", fmt.Errorf("compile bot regexes from %s: %w", path, err)
		}
		return matcher, path, nil
	}

	if lastErr != nil {
		return nil, "", lastErr
	}
	return nil, "", errors.New("no bot regex sources configured")
}

func loadBotPatterns(path string) (botdata.File, error) {
	if strings.ToLower(filepath.Ext(path)) != ".json" {
		return botdata.File{}, fmt.Errorf("unsupported bot data file type: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return botdata.File{}, err
	}

	var file botdata.File
	if err := segmentjson.Unmarshal(data, &file); err != nil {
		return botdata.File{}, fmt.Errorf("decode bot json: %w", err)
	}
	if file.Version != botdata.SchemaVersion {
		return botdata.File{}, fmt.Errorf("unsupported bot schema version: %d", file.Version)
	}
	return file, nil
}

func compileBotMatcher(data botdata.File) (*BotMatcher, error) {
	if len(data.LiteralPatterns) == 0 && len(data.RegexPatterns) == 0 {
		return nil, errors.New("bot regex list is empty")
	}

	matcher := &BotMatcher{
		cache:     make(map[string]bool, botMatcherCacheSize),
		cacheKeys: make([]string, 0, botMatcherCacheSize),
	}
	if len(data.LiteralPatterns) > 0 {
		matcher.literalMatcher = ahocorasick.NewStringMatcher(data.LiteralPatterns)
	}

	if len(data.RegexPatterns) == 0 {
		return matcher, nil
	}

	var joined strings.Builder
	for i, pattern := range data.RegexPatterns {
		if i > 0 {
			joined.WriteString("|")
		}
		joined.WriteString("(?:")
		joined.WriteString(pattern)
		joined.WriteString(")")
	}

	re, err := regexp2.Compile(joined.String(), 0)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = 2 * time.Second
	matcher.regex = re
	return matcher, nil
}

func (m *BotMatcher) MatchString(value string) (bool, error) {
	if m == nil || value == "" {
		return false, nil
	}

	if matched, ok := m.cache[value]; ok {
		return matched, nil
	}

	matched := false
	if m.literalMatcher != nil && m.literalMatcher.Contains([]byte(value)) {
		matched = true
	} else if m.regex != nil {
		var err error
		matched, err = m.regex.MatchString(value)
		if err != nil {
			return false, err
		}
	}

	m.storeCachedResult(value, matched)
	return matched, nil
}

func (m *BotMatcher) storeCachedResult(value string, matched bool) {
	if len(m.cacheKeys) < botMatcherCacheSize {
		m.cacheKeys = append(m.cacheKeys, value)
		m.cache[value] = matched
		return
	}

	evicted := m.cacheKeys[m.cacheNext]
	delete(m.cache, evicted)
	m.cacheKeys[m.cacheNext] = value
	m.cache[value] = matched
	m.cacheNext++
	if m.cacheNext >= botMatcherCacheSize {
		m.cacheNext = 0
	}
}

type Importer struct {
	cfg          Config
	log          *logger
	botMatcher   *BotMatcher
	excludeGlobs []*regexp.Regexp
	excludeExts  map[string]struct{}
	excludeCIDRs []netip.Prefix
	httpClient   *http.Client
	matomoDebug  bool
	diagnostics  *matomoDiagnostics
}

func NewImporter(cfg Config, log *logger, matcher *BotMatcher) (*Importer, error) {
	if cfg.Matomo.BatchSize <= 0 {
		return nil, errors.New("matomo.batch_size must be greater than zero")
	}

	globs := make([]*regexp.Regexp, 0, len(cfg.Exclude.Paths))
	for _, pattern := range cfg.Exclude.Paths {
		globRe, err := compileFnmatch(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude path pattern %q: %w", pattern, err)
		}
		globs = append(globs, globRe)
	}

	exts := make(map[string]struct{}, len(cfg.Exclude.Extensions))
	for _, ext := range cfg.Exclude.Extensions {
		exts[ext] = struct{}{}
	}

	cidrs := make([]netip.Prefix, 0, len(cfg.Exclude.Addresses))
	for _, value := range cfg.Exclude.Addresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude address %q: %w", value, err)
		}
		cidrs = append(cidrs, prefix)
	}

	return &Importer{
		cfg:          cfg,
		log:          log,
		botMatcher:   matcher,
		excludeGlobs: globs,
		excludeExts:  exts,
		excludeCIDRs: cidrs,
		httpClient:   buildHTTPClient(cfg.Matomo.HTTPSProxy),
		diagnostics:  newMatomoDiagnostics(),
	}, nil
}

func buildHTTPClient(proxyURL string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   600 * time.Second,
	}
}

func compileFnmatch(pattern string) (*regexp.Regexp, error) {
	var out strings.Builder
	out.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			out.WriteString(".*")
		case '?':
			out.WriteString(".")
		case '[':
			end := i + 1
			if end < len(pattern) && (pattern[end] == '!' || pattern[end] == '^') {
				end++
			}
			if end < len(pattern) && pattern[end] == ']' {
				end++
			}
			for end < len(pattern) && pattern[end] != ']' {
				end++
			}
			if end >= len(pattern) {
				out.WriteString(`\[`)
				continue
			}

			class := pattern[i+1 : end]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			class = strings.ReplaceAll(class, `\`, `\\`)
			out.WriteString("[")
			out.WriteString(class)
			out.WriteString("]")
			i = end
		default:
			out.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}

	out.WriteString("$")
	return regexp.Compile(out.String())
}

func normalizeRequestPath(path string) string {
	if strings.HasPrefix(path, "//") {
		return "/" + strings.TrimLeft(path, "/")
	}
	return path
}

func getIPAddress(parsedLine *logRecord, log *logger) (string, error) {
	remote := parsedLine.RemoteAddr.String()
	if remote == "" {
		return "", errors.New("remote_addr was missing")
	}

	xForwarded := parsedLine.HTTPXForwardedFor.String()
	if xForwarded == "" {
		return remote, nil
	}

	if strings.Contains(xForwarded, ",") {
		firstClient, _, _ := strings.Cut(xForwarded, ",")
		xForwarded = strings.TrimSpace(firstClient)
	}

	if net.ParseIP(xForwarded) == nil {
		log.Infof("Could not parse x-forwarded value: %s", xForwarded)
		return remote, nil
	}

	return xForwarded, nil
}

func (i *Importer) buildParsedLineContext(jsonRecord *logRecord) (parsedLineContext, error) {
	requestPath := normalizeRequestPath(jsonRecord.RequestURI.String())
	clientIP, err := getIPAddress(jsonRecord, i.log)
	if err != nil {
		return parsedLineContext{}, err
	}

	return parsedLineContext{
		jsonRecord:      jsonRecord,
		requestPath:     requestPath,
		requestPathOnly: cutBeforeQuery(requestPath),
		clientIP:        clientIP,
		userAgent:       jsonRecord.HTTPUserAgent.String(),
	}, nil
}

func cutBeforeQuery(path string) string {
	if index := strings.IndexByte(path, '?'); index >= 0 {
		return path[:index]
	}
	return path
}

func (i *Importer) applyLineFilters(parsedLine parsedLineContext) (lineOutcome, error) {
	requestID := parsedLine.jsonRecord.RequestID.String()
	i.log.Debugf("checking if request %s needs to be filtered out", requestID)

	for index := range i.cfg.Exclude.Paths {
		if i.excludeGlobs[index].MatchString(parsedLine.requestPath) {
			i.log.Debugf("filtering %s: Path was excluded: ID: %s", parsedLine.requestPath, requestID)
			return lineOutcomeIgnored, nil
		}
		i.log.Debugf("passing %s on to the next filter: ID: %s", parsedLine.requestPath, requestID)
	}

	if ext := extractExtension(parsedLine.requestPathOnly); ext != "" {
		if _, excluded := i.excludeExts[ext]; excluded {
			i.log.Debugf("filtering %s: Extension was excluded: ID: %s", parsedLine.requestPath, requestID)
			return lineOutcomeIgnored, nil
		}
	}

	i.log.Debugf("passed extension check: ID: %s", requestID)

	if i.cfg.Exclude.Bots {
		matched, err := i.botMatcher.MatchString(parsedLine.userAgent)
		if err != nil {
			return lineOutcomeError, err
		}
		if matched {
			i.log.Debugf("filtering %s: User agent is a bot. ID: %s", parsedLine.userAgent, requestID)
			return lineOutcomeBot, nil
		}

		i.log.Debugf("keeping %s: User agent is not a bot. ID: %s", parsedLine.userAgent, requestID)
	}

	if len(i.excludeCIDRs) > 0 {
		addr, err := netip.ParseAddr(parsedLine.clientIP)
		if err != nil {
			return lineOutcomeError, fmt.Errorf("invalid client ip %q: %w", parsedLine.clientIP, err)
		}
		for _, prefix := range i.excludeCIDRs {
			if prefix.Contains(addr) {
				i.log.Debugf("filtering IP address %s: ID %s", parsedLine.clientIP, requestID)
				return lineOutcomeIgnored, nil
			}
		}
	}

	i.log.Debugf("keeping line with request ID %s", requestID)
	return lineOutcomeReal, nil
}

func extractExtension(path string) string {
	lastSlash := strings.LastIndexByte(path, '/')
	lastDot := strings.LastIndexByte(path, '.')
	if lastDot < 0 || lastDot < lastSlash+1 {
		return ""
	}
	return path[lastDot+1:]
}

func createHit(parsedLine *logRecord, idSite string, clientIP string, requestPath string) Hit {
	host := parsedLine.HTTPHost.String()
	scheme := parsedLine.Scheme.String()
	url := scheme + "://" + host + requestPath

	acceptHeader := strings.ReplaceAll(parsedLine.HTTPAccept.String(), "+", "%2b")

	return Hit{
		URL:            url,
		URLRef:         parsedLine.HTTPReferer.String(),
		UA:             parsedLine.HTTPUserAgent.String(),
		Dimension1:     acceptHeader,
		Dimension2:     parsedLine.Status.String(),
		CDT:            parsedLine.TimeISO8601.String(),
		CIP:            clientIP,
		Country:        strings.ToLower(parsedLine.GeoIPCountryCode.String()),
		City:           parsedLine.GeoIPCity.String(),
		Lat:            parsedLine.GeoIPLatitude.String(),
		Long:           parsedLine.GeoIPLongitude.String(),
		PFSrv:          parsedLine.RequestTime.String(),
		BWBytes:        parsedLine.BytesSent.String(),
		APIV:           "1",
		Rec:            "1",
		IDSite:         idSite,
		QueuedTracking: "0",
		DP:             "1",
	}
}

func (i *Importer) parseLine(line []byte, lineno int) (Hit, lineOutcome, error) {
	i.log.Debugf("Processing line %d", lineno)

	if bytes.Contains(line, []byte(`\x`)) {
		line = bytes.ReplaceAll(line, []byte(`\x`), []byte(`\u00`))
	}

	var jsonRecord logRecord
	if err := segmentjson.Unmarshal(line, &jsonRecord); err != nil {
		i.log.Errorf("Could not decode line %s", strings.TrimSpace(string(line)))
		return Hit{}, lineOutcomeError, nil
	}

	parsedLine, err := i.buildParsedLineContext(&jsonRecord)
	if err != nil {
		return Hit{}, lineOutcomeError, err
	}

	outcome, err := i.applyLineFilters(parsedLine)
	if err != nil {
		return Hit{}, lineOutcomeError, err
	}
	if outcome != lineOutcomeReal {
		return Hit{}, outcome, nil
	}

	i.log.Debugf("creating hit for line with request ID %s", jsonRecord.RequestID.String())
	hit := createHit(&jsonRecord, i.cfg.Matomo.IDSite, parsedLine.clientIP, parsedLine.requestPath)
	return hit, lineOutcomeReal, nil
}

func openLogFile(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 2)
	n, err := io.ReadFull(file, header)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		file.Close()
		return nil, err
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}

	header = header[:n]
	switch {
	case bytes.Equal(header, gzipMagic):
		reader, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		return &compoundReadCloser{Reader: reader, closers: []io.Closer{reader, file}}, nil
	case bytes.Equal(header, bz2Magic):
		return &compoundReadCloser{Reader: bzip2.NewReader(file), closers: []io.Closer{file}}, nil
	default:
		return file, nil
	}
}

type compoundReadCloser struct {
	io.Reader
	closers []io.Closer
}

func (c *compoundReadCloser) Close() error {
	var errs []error
	for _, closer := range c.closers {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (i *Importer) submitHits(batch []Hit) bool {
	matomoURL := fmt.Sprintf("%s/piwik.php", i.cfg.Matomo.URL)
	reqData := matomoPayload{
		TokenAuth: i.cfg.Matomo.AuthToken,
		Requests:  batch,
	}

	jsonData, err := segmentjson.Marshal(reqData)
	if err != nil {
		i.log.Errorf("Could not encode request body: %v", err)
		return false
	}
	i.log.Debugf("Size of request body: %.3f KB", float64(len(jsonData))/1000.0)

	req, err := http.NewRequest(http.MethodPost, matomoURL, bytes.NewReader(jsonData))
	if err != nil {
		i.log.Errorf("Request creation failed: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.httpClient.Do(req)
	if err != nil {
		i.log.Errorf("Request failed: %v", err)
		return false
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		i.log.Errorf("Could not read Matomo response body: %v", readErr)
		return false
	}

	if resp.StatusCode != http.StatusOK {
		i.log.Errorf("Request failed: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return false
	}

	i.log.Debugf("Actual status code: %d", resp.StatusCode)
	if i.matomoDebug {
		i.diagnostics.addBatchResult(len(batch), body)
	}
	return true
}

func (i *Importer) parseLogFile(logfilePath string, dryRun bool) (fileStats, bool) {
	stats := fileStats{FilePath: logfilePath}
	lineno := 0
	pendingHits := make([]Hit, 0, i.cfg.Matomo.BatchSize)
	count := 0
	success := true

	logfile, err := openLogFile(logfilePath)
	if err != nil {
		i.log.Errorf("Error opening file %s: %v", logfilePath, err)
		return stats, false
	}
	defer logfile.Close()

	reader := bufio.NewReader(logfile)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			i.log.Errorf("Error reading file %s: %v", logfilePath, err)
			success = false
			break
		}

		if len(line) > 0 {
			lineno++
			if lineno%1000 == 0 {
				i.log.Infof("Read %d lines", lineno)
			}

			result, outcome, parseErr := i.parseLine(line, lineno)
			if parseErr != nil {
				i.log.Errorf("An exception occurred: %v", parseErr)
				stats.addOutcome(lineOutcomeError)
			} else if outcome != lineOutcomeReal {
				stats.addOutcome(outcome)
				if outcome == lineOutcomeBot {
					stats.addBotUserAgent(extractUserAgentFromLine(line))
				}
			} else {
				stats.addOutcome(lineOutcomeReal)
				pendingHits = append(pendingHits, result)

				if !dryRun && len(pendingHits) >= i.cfg.Matomo.BatchSize {
					success = i.submitHits(pendingHits) && success
					count += len(pendingHits)
					pendingHits = pendingHits[:0]
					i.log.Infof("Submitted %d records", count)
				}
			}
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}

	if len(pendingHits) > 0 && !dryRun {
		success = i.submitHits(pendingHits) && success
		count += len(pendingHits)
		i.log.Infof("Submitted %d records", count)
	}

	i.log.Infof("Found %d lines", stats.Total)
	i.log.Infof("Filtered %d", stats.Bot+stats.Ignored+stats.Errors)
	i.log.Infof("Submitting %d results", stats.Real)

	if dryRun {
		i.log.Infof("Dry run. Exiting before submitting results")
		return stats, success
	}
	if !success {
		i.log.Errorf("Some uploads failed. Please see the log messages.")
	}
	return stats, success
}

func (i *Importer) run(logfiles []string, dryRun bool) ([]fileStats, bool) {
	stats := make([]fileStats, 0, len(logfiles))
	success := true
	for _, logfile := range logfiles {
		i.log.Infof("Processing file %s", logfile)
		fileStats, fileSuccess := i.parseLogFile(logfile, dryRun)
		stats = append(stats, fileStats)
		success = fileSuccess && success
	}
	return stats, success
}

func parseArgs(args []string) (cliArgs, error) {
	parsed := cliArgs{Config: "config.toml", BotsFile: "bots.json"}

	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			parsed.LogFiles = append(parsed.LogFiles, args[index+1:]...)
			break
		}

		switch {
		case arg == "--debug" || arg == "-d":
			parsed.Debug = true
		case arg == "--verbose" || arg == "-v":
			parsed.Verbose = true
		case arg == "--dry-run" || arg == "-r":
			parsed.DryRun = true
		case arg == "--report":
			parsed.Report = true
			parsed.DryRun = true
		case arg == "--matomo-debug":
			parsed.MatomoDebug = true
		case arg == "--config" || arg == "-c":
			index++
			if index >= len(args) {
				return cliArgs{}, errors.New("missing value for --config")
			}
			parsed.Config = args[index]
		case arg == "--bots-file":
			index++
			if index >= len(args) {
				return cliArgs{}, errors.New("missing value for --bots-file")
			}
			parsed.BotsFile = args[index]
		case strings.HasPrefix(arg, "--config="):
			parsed.Config = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "--bots-file="):
			parsed.BotsFile = strings.TrimPrefix(arg, "--bots-file=")
		case strings.HasPrefix(arg, "-c="):
			parsed.Config = strings.TrimPrefix(arg, "-c=")
		case strings.HasPrefix(arg, "-"):
			return cliArgs{}, fmt.Errorf("unknown argument: %s", arg)
		default:
			parsed.LogFiles = append(parsed.LogFiles, arg)
		}
	}

	if len(parsed.LogFiles) == 0 {
		return cliArgs{}, errors.New("at least one logfile is required")
	}
	return parsed, nil
}

func readConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [--config FILE] [--bots-file FILE] [--debug] [--verbose] [--dry-run] [--report] [--matomo-debug] logfile [logfile ...]\n", filepath.Base(os.Args[0]))
}

func renderReportTable(stats []fileStats) string {
	total := fileStats{FilePath: "TOTAL"}
	rows := make([]fileStats, 0, len(stats)+1)
	rows = append(rows, stats...)
	if len(stats) > 1 {
		for _, stat := range stats {
			total.Total += stat.Total
			total.Real += stat.Real
			total.Bot += stat.Bot
			total.Ignored += stat.Ignored
			total.Errors += stat.Errors
		}
		rows = append(rows, total)
	}

	fileWidth := len("File")
	for _, row := range rows {
		if len(row.FilePath) > fileWidth {
			fileWidth = len(row.FilePath)
		}
	}

	var out strings.Builder
	fmt.Fprintf(&out, "%-*s  %10s  %7s  %10s  %7s  %10s  %7s  %10s  %7s\n",
		fileWidth, "File",
		"Real", "Real %",
		"Bot", "Bot %",
		"Ignored", "Ignored %",
		"Errors", "Error %",
	)
	for _, row := range rows {
		fmt.Fprintf(&out, "%-*s  %10d  %6.2f%%  %10d  %6.2f%%  %10d  %6.2f%%  %10d  %6.2f%%\n",
			fileWidth, row.FilePath,
			row.Real, row.percent(row.Real),
			row.Bot, row.percent(row.Bot),
			row.Ignored, row.percent(row.Ignored),
			row.Errors, row.percent(row.Errors),
		)
	}
	return out.String()
}

type botUserAgentCount struct {
	UserAgent string
	Count     int
}

func aggregateTopBotUserAgents(stats []fileStats, limit int) []botUserAgentCount {
	if limit <= 0 {
		return nil
	}

	combined := make(map[string]int)
	for _, stat := range stats {
		for userAgent, count := range stat.BotUserAgents {
			combined[userAgent] += count
		}
	}

	top := make([]botUserAgentCount, 0, len(combined))
	for userAgent, count := range combined {
		top = append(top, botUserAgentCount{UserAgent: userAgent, Count: count})
	}

	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].UserAgent < top[j].UserAgent
	})

	if len(top) > limit {
		top = top[:limit]
	}
	return top
}

func renderTopBotUserAgents(stats []fileStats, limit int) string {
	top := aggregateTopBotUserAgents(stats, limit)
	if len(top) == 0 {
		return ""
	}

	var out strings.Builder
	out.WriteString("\nTop Bot User Agents\n")
	out.WriteString("===================\n")
	for index, item := range top {
		fmt.Fprintf(&out, "%d. %s (%d)\n", index+1, item.UserAgent, item.Count)
	}
	return out.String()
}

func extractUserAgentFromLine(line []byte) string {
	var record struct {
		HTTPUserAgent flexibleString `json:"http_user_agent"`
	}
	if err := segmentjson.Unmarshal(line, &record); err != nil {
		return ""
	}
	return record.HTTPUserAgent.String()
}

func main() {
	args, err := parseArgs(os.Args[1:])
	if err != nil {
		usage()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	level := levelWarning
	if args.Debug {
		level = levelDebug
	} else if args.Verbose {
		level = levelInfo
	}
	log := newLogger(level)

	cfg, err := readConfig(args.Config)
	if err != nil {
		log.Errorf("Could not read config %s: %v", args.Config, err)
		os.Exit(1)
	}

	matcher, matcherPath, err := loadBotMatcher([]string{args.BotsFile})
	if err != nil {
		log.Errorf("Could not load bot regex data: %v", err)
		os.Exit(1)
	}
	log.Infof("Loaded bot regexes from %s", matcherPath)

	importer, err := NewImporter(cfg, log, matcher)
	if err != nil {
		log.Errorf("Configuration error: %v", err)
		os.Exit(1)
	}
	importer.matomoDebug = args.MatomoDebug

	stats, success := importer.run(args.LogFiles, args.DryRun)
	if args.Report {
		fmt.Print(renderReportTable(stats))
		fmt.Print(renderTopBotUserAgents(stats, 5))
	}
	if args.MatomoDebug && !args.DryRun {
		fmt.Print(importer.diagnostics.render(10))
	}

	if !success {
		os.Exit(1)
	}
}
