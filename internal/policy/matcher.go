package policy

import (
	"path/filepath"
	"strings"

	"github.com/CliXiD/keycloak-pep-plugin/config"
)

// Matcher handles path and method matching for policy enforcement
type Matcher struct {
	config *config.Config
}

// NewMatcher creates a new path matcher
func NewMatcher(cfg *config.Config) *Matcher {
	return &Matcher{
		config: cfg,
	}
}

// FindMatchingPath finds the matching path configuration for a given path and method
func (m *Matcher) FindMatchingPath(requestPath, method string) *config.PathConfig {
	var bestMatch *config.PathConfig
	var bestMatchLength int

	for i := range m.config.Paths {
		pathConfig := &m.config.Paths[i]

		// Check if path matches
		if !m.pathMatches(requestPath, pathConfig.Path) {
			continue
		}

		// Check if method matches (if methods are specified)
		if len(pathConfig.Methods) > 0 && !m.methodMatches(method, pathConfig.Methods) {
			continue
		}

		// Find the most specific match (longest path pattern)
		pathLength := len(pathConfig.Path)
		if bestMatch == nil || pathLength > bestMatchLength {
			bestMatch = pathConfig
			bestMatchLength = pathLength
		}
	}

	return bestMatch
}

// pathMatches checks if a request path matches a configured path pattern
func (m *Matcher) pathMatches(requestPath, pathPattern string) bool {
	// Exact match
	if requestPath == pathPattern {
		return true
	}

	// Wildcard matching using filepath.Match
	matched, err := filepath.Match(pathPattern, requestPath)
	if err != nil {
		// Fallback to simple prefix matching if filepath.Match fails
		return m.prefixMatches(requestPath, pathPattern)
	}

	// Additional custom matching patterns
	if !matched {
		matched = m.customPathMatches(requestPath, pathPattern)
	}

	return matched
}

// prefixMatches handles prefix-based matching with wildcards
func (m *Matcher) prefixMatches(requestPath, pathPattern string) bool {
	// Handle trailing /* pattern
	if strings.HasSuffix(pathPattern, "/*") {
		prefix := strings.TrimSuffix(pathPattern, "/*")
		return strings.HasPrefix(requestPath, prefix)
	}

	// Handle trailing /** pattern (recursive)
	if strings.HasSuffix(pathPattern, "/**") {
		prefix := strings.TrimSuffix(pathPattern, "/**")
		return strings.HasPrefix(requestPath, prefix)
	}

	// Simple prefix match
	return strings.HasPrefix(requestPath, pathPattern)
}

// customPathMatches handles custom path matching patterns
func (m *Matcher) customPathMatches(requestPath, pathPattern string) bool {
	// Split paths into segments
	requestSegments := strings.Split(strings.Trim(requestPath, "/"), "/")
	patternSegments := strings.Split(strings.Trim(pathPattern, "/"), "/")

	return m.segmentMatches(requestSegments, patternSegments)
}

// segmentMatches matches path segments with wildcard support
func (m *Matcher) segmentMatches(requestSegments, patternSegments []string) bool {
	reqIndex := 0
	patIndex := 0

	for patIndex < len(patternSegments) && reqIndex < len(requestSegments) {
		pattern := patternSegments[patIndex]

		switch pattern {
		case "*":
			// Single wildcard - matches one segment
			reqIndex++
			patIndex++
		case "**":
			// Double wildcard - matches zero or more segments
			if patIndex == len(patternSegments)-1 {
				// ** at the end matches everything remaining
				return true
			}
			// Try to match the next pattern segment
			nextPattern := patternSegments[patIndex+1]
			found := false
			for i := reqIndex; i < len(requestSegments); i++ {
				if m.segmentMatch(requestSegments[i], nextPattern) {
					reqIndex = i
					found = true
					break
				}
			}
			if !found {
				return false
			}
			patIndex += 2
		default:
			// Literal segment or single wildcard pattern
			if !m.segmentMatch(requestSegments[reqIndex], pattern) {
				return false
			}
			reqIndex++
			patIndex++
		}
	}

	// Check if we've consumed all segments
	if patIndex < len(patternSegments) {
		// Check if remaining patterns are all ** or empty
		for i := patIndex; i < len(patternSegments); i++ {
			if patternSegments[i] != "**" && patternSegments[i] != "" {
				return false
			}
		}
	}

	// If we have remaining request segments, they must be matched by ** at the end
	if reqIndex < len(requestSegments) {
		return patIndex > 0 && patternSegments[patIndex-1] == "**"
	}

	return true
}

// segmentMatch matches a single path segment against a pattern
func (m *Matcher) segmentMatch(segment, pattern string) bool {
	if pattern == "*" {
		return true
	}

	// Use filepath.Match for glob patterns within a segment
	matched, err := filepath.Match(pattern, segment)
	if err != nil {
		// Fallback to exact match
		return segment == pattern
	}
	return matched
}

// methodMatches checks if the request method matches any of the allowed methods
func (m *Matcher) methodMatches(requestMethod string, allowedMethods []string) bool {
	requestMethod = strings.ToUpper(requestMethod)

	for _, method := range allowedMethods {
		if strings.ToUpper(method) == requestMethod {
			return true
		}
	}
	return false
}