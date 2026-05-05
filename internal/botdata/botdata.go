package botdata

import (
	"encoding/json"
	"strings"
)

const (
	SchemaVersion = 1
	SourceURL     = "https://raw.githubusercontent.com/matomo-org/device-detector/refs/heads/master/regexes/bots.yml"
)

var PreludePatterns = []string{
	"check_ssl_cert.*",
	"synthetic-monitoring-agent.*",
	"monitoring360bot",
}

type File struct {
	Version         int      `json:"version"`
	SourceURL       string   `json:"source_url"`
	LiteralPatterns []string `json:"literal_patterns"`
	RegexPatterns   []string `json:"regex_patterns"`
}

func (f File) Marshal() ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}

func BuildFile(patterns []string) File {
	literalPatterns := make([]string, 0, len(patterns))
	regexPatterns := make([]string, 0, len(patterns))
	seenLiteral := make(map[string]struct{}, len(patterns))
	seenRegex := make(map[string]struct{}, len(patterns))

	for _, pattern := range append(append([]string{}, PreludePatterns...), patterns...) {
		if literals, ok := expandSimpleLiteralPattern(pattern); ok {
			for _, literal := range literals {
				if _, exists := seenLiteral[literal]; exists {
					continue
				}
				seenLiteral[literal] = struct{}{}
				literalPatterns = append(literalPatterns, literal)
			}
			continue
		}

		if _, exists := seenRegex[pattern]; exists {
			continue
		}
		seenRegex[pattern] = struct{}{}
		regexPatterns = append(regexPatterns, pattern)
	}

	return File{
		Version:         SchemaVersion,
		SourceURL:       SourceURL,
		LiteralPatterns: literalPatterns,
		RegexPatterns:   regexPatterns,
	}
}

func expandSimpleLiteralPattern(pattern string) ([]string, bool) {
	parts, ok := splitTopLevelAlternation(pattern)
	if !ok {
		return nil, false
	}

	literals := make([]string, 0, len(parts))
	for _, part := range parts {
		literal, ok := decodeLiteralPattern(part)
		if !ok {
			return nil, false
		}
		literals = append(literals, literal)
	}

	if len(literals) == 0 {
		return nil, false
	}
	return literals, true
}

func splitTopLevelAlternation(pattern string) ([]string, bool) {
	var parts []string
	start := 0
	parenDepth := 0
	bracketDepth := 0
	escaped := false

	for index := 0; index < len(pattern); index++ {
		ch := pattern[index]

		if escaped {
			escaped = false
			continue
		}

		switch ch {
		case '\\':
			escaped = true
		case '[':
			if bracketDepth == 0 {
				bracketDepth = 1
			}
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '(':
			if bracketDepth == 0 {
				parenDepth++
			}
		case ')':
			if bracketDepth == 0 && parenDepth > 0 {
				parenDepth--
			}
		case '|':
			if bracketDepth == 0 && parenDepth == 0 {
				parts = append(parts, pattern[start:index])
				start = index + 1
			}
		}
	}

	if escaped || bracketDepth != 0 || parenDepth != 0 {
		return nil, false
	}

	parts = append(parts, pattern[start:])
	return parts, true
}

func decodeLiteralPattern(pattern string) (string, bool) {
	if pattern == "" {
		return "", false
	}

	var literal strings.Builder
	for index := 0; index < len(pattern); index++ {
		ch := pattern[index]
		if ch == '\\' {
			index++
			if index >= len(pattern) {
				return "", false
			}
			escaped := pattern[index]
			if !isEscapedLiteralByte(escaped) {
				return "", false
			}
			literal.WriteByte(escaped)
			continue
		}

		if isRegexMetaByte(ch) {
			return "", false
		}
		literal.WriteByte(ch)
	}

	if literal.Len() == 0 {
		return "", false
	}
	return literal.String(), true
}

func isRegexMetaByte(ch byte) bool {
	switch ch {
	case '.', '*', '+', '?', '|', '(', ')', '[', ']', '{', '}', '^', '$':
		return true
	default:
		return false
	}
}

func isEscapedLiteralByte(ch byte) bool {
	switch ch {
	case '.', '-', '/', ' ', ':', ';', ',', '_', '+', '&', '%', '!', '@', '#', '=', '\\':
		return true
	default:
		return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
	}
}
