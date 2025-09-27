// Package main implements a Traefik plugin for Keycloak Policy Enforcement Point (PEP)
package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/CliXiD/keycloak-pep-plugin/config"
	"github.com/CliXiD/keycloak-pep-plugin/internal/policy"
)

// CreateConfig creates the default plugin configuration
func CreateConfig() *config.Config {
	return config.DefaultConfig()
}

// KeycloakPEP is the main plugin struct
type KeycloakPEP struct {
	next     http.Handler
	enforcer *policy.Enforcer
	name     string
}

// New creates a new instance of the Keycloak PEP plugin
func New(ctx context.Context, next http.Handler, cfg *config.Config, name string) (http.Handler, error) {
	// Validate required configuration
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create policy enforcer
	enforcer, err := policy.NewEnforcer(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy enforcer: %w", err)
	}

	return &KeycloakPEP{
		next:     next,
		enforcer: enforcer,
		name:     name,
	}, nil
}

// validateConfig validates the plugin configuration
func validateConfig(cfg *config.Config) error {
	if cfg.Keycloak.ServerURL == "" {
		return fmt.Errorf("keycloak server URL is required")
	}
	if cfg.Keycloak.Realm == "" {
		return fmt.Errorf("keycloak realm is required")
	}
	if cfg.Keycloak.ClientID == "" {
		return fmt.Errorf("keycloak client ID is required")
	}

	// Validate enforcement mode
	switch cfg.EnforcementMode {
	case config.EnforcementModeEnforcing, config.EnforcementModePermissive, config.EnforcementModeDisabled:
		// Valid modes
	default:
		return fmt.Errorf("invalid enforcement mode: %s", cfg.EnforcementMode)
	}

	return nil
}

// ServeHTTP implements the http.Handler interface
func (k *KeycloakPEP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Skip enforcement if mode is DISABLED
	if k.enforcer.IsDisabled() {
		k.next.ServeHTTP(rw, req)
		return
	}

	// Extract JWT token from Authorization header
	token := extractToken(req)
	if token == "" {
		if k.enforcer.IsEnforcing() {
			k.writeError(rw, "Authorization token required", http.StatusUnauthorized)
			return
		}
		// In PERMISSIVE mode, continue without token
		k.next.ServeHTTP(rw, req)
		return
	}

	// Evaluate policy
	decision, err := k.enforcer.Evaluate(req, token)
	if err != nil {
		if k.enforcer.IsEnforcing() {
			k.writeError(rw, "Policy evaluation failed", http.StatusInternalServerError)
			return
		}
		// In PERMISSIVE mode, log error but continue
		// TODO: Add proper logging here
		k.next.ServeHTTP(rw, req)
		return
	}

	// Check authorization decision
	if !decision.Permitted {
		if k.enforcer.IsEnforcing() {
			k.writeError(rw, fmt.Sprintf("Access denied: %s", decision.Reason), http.StatusForbidden)
			return
		}
		// In PERMISSIVE mode, log violation but continue
		// TODO: Add proper logging here
	}

	// Add authorization context to request headers for downstream services
	if decision.Permitted {
		k.addAuthHeaders(rw, decision)
	}

	// Continue to next handler
	k.next.ServeHTTP(rw, req)
}

// writeError writes an error response with proper headers
func (k *KeycloakPEP) writeError(rw http.ResponseWriter, message string, statusCode int) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)

	errorResponse := fmt.Sprintf(`{"error": "%s", "plugin": "%s"}`, message, k.name)
	rw.Write([]byte(errorResponse))
}

// addAuthHeaders adds authorization context to response headers
func (k *KeycloakPEP) addAuthHeaders(rw http.ResponseWriter, decision *policy.Decision) {
	if len(decision.Scopes) > 0 {
		rw.Header().Set("X-Auth-Scopes", strings.Join(decision.Scopes, ","))
	}
	if len(decision.Roles) > 0 {
		rw.Header().Set("X-Auth-Roles", strings.Join(decision.Roles, ","))
	}
}

// extractToken extracts the JWT token from the Authorization header
func extractToken(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Remove "Bearer " prefix using CutPrefix (Go 1.20+)
	if token, found := strings.CutPrefix(authHeader, "Bearer "); found {
		return token
	}

	return authHeader
}