package policy

import (
	"fmt"
	"net/http"

	"github.com/CliXiD/keycloak-pep-plugin/config"
	"github.com/CliXiD/keycloak-pep-plugin/internal/keycloak"
)

// Enforcer handles policy enforcement decisions
type Enforcer struct {
	config    *config.Config
	client    *keycloak.Client
	evaluator *Evaluator
	matcher   *Matcher
}

// Decision represents an authorization decision
type Decision struct {
	Permitted bool
	Reason    string
	Scopes    []string
	Roles     []string
}

// NewEnforcer creates a new policy enforcer
func NewEnforcer(cfg *config.Config) (*Enforcer, error) {
	client, err := keycloak.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Keycloak client: %w", err)
	}

	evaluator := NewEvaluator(cfg)
	matcher := NewMatcher(cfg)

	return &Enforcer{
		config:    cfg,
		client:    client,
		evaluator: evaluator,
		matcher:   matcher,
	}, nil
}

// Evaluate evaluates a request against configured policies
func (e *Enforcer) Evaluate(req *http.Request, token string) (*Decision, error) {
	// Find matching path configuration
	pathConfig := e.matcher.FindMatchingPath(req.URL.Path, req.Method)
	if pathConfig == nil {
		// No specific path configuration, check if we have a default policy
		if len(e.config.Paths) == 0 {
			// No paths configured, allow access in permissive mode
			return &Decision{Permitted: !e.config.IsEnforcing(), Reason: "No policies configured"}, nil
		}
		// Path not configured, deny access
		return &Decision{Permitted: false, Reason: "Path not configured for policy enforcement"}, nil
	}

	// If no token provided
	if token == "" {
		return &Decision{
			Permitted: false,
			Reason:    "No authorization token provided",
		}, nil
	}

	// Validate token
	tokenInfo, err := e.client.ValidateToken(token)
	if err != nil {
		return &Decision{
			Permitted: false,
			Reason:    fmt.Sprintf("Token validation failed: %v", err),
		}, nil
	}

	// Evaluate policy
	return e.evaluator.EvaluatePolicy(tokenInfo, pathConfig, req)
}

// IsEnforcing returns true if the enforcer is in enforcing mode
func (e *Enforcer) IsEnforcing() bool {
	return e.config.IsEnforcing()
}

// IsPermissive returns true if the enforcer is in permissive mode
func (e *Enforcer) IsPermissive() bool {
	return e.config.IsPermissive()
}

// IsDisabled returns true if the enforcer is disabled
func (e *Enforcer) IsDisabled() bool {
	return e.config.IsDisabled()
}