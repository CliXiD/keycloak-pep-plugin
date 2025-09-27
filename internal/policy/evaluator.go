package policy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/CliXiD/keycloak-pep-plugin/config"
	"github.com/CliXiD/keycloak-pep-plugin/internal/keycloak"
)

// Evaluator evaluates authorization policies
type Evaluator struct {
	config *config.Config
}

// NewEvaluator creates a new policy evaluator
func NewEvaluator(cfg *config.Config) *Evaluator {
	return &Evaluator{
		config: cfg,
	}
}

// EvaluatePolicy evaluates a policy for the given token and path configuration
func (e *Evaluator) EvaluatePolicy(tokenInfo *keycloak.TokenInfo, pathConfig *config.PathConfig, req *http.Request) (*Decision, error) {
	// Check if token is active
	if !tokenInfo.Active {
		return &Decision{
			Permitted: false,
			Reason:    "Token is not active",
		}, nil
	}

	// Check token expiration
	if tokenInfo.IsExpired() {
		return &Decision{
			Permitted: false,
			Reason:    "Token has expired",
		}, nil
	}

	// Check required scopes
	if len(pathConfig.Scopes) > 0 {
		if !e.hasRequiredScopes(tokenInfo.Scopes, pathConfig.Scopes) {
			return &Decision{
				Permitted: false,
				Reason:    fmt.Sprintf("Missing required scopes: %v", pathConfig.Scopes),
			}, nil
		}
	}

	// Check required roles
	if len(pathConfig.Roles) > 0 {
		if !e.hasRequiredRoles(tokenInfo.Roles, pathConfig.Roles) {
			return &Decision{
				Permitted: false,
				Reason:    fmt.Sprintf("Missing required roles: %v", pathConfig.Roles),
			}, nil
		}
	}

	// Check custom claims validation
	if len(pathConfig.ClaimsValidation) > 0 {
		if !e.validateClaims(tokenInfo.Claims, pathConfig.ClaimsValidation) {
			return &Decision{
				Permitted: false,
				Reason:    "Claims validation failed",
			}, nil
		}
	}

	// All checks passed
	return &Decision{
		Permitted: true,
		Reason:    "Access granted",
		Scopes:    tokenInfo.Scopes,
		Roles:     tokenInfo.Roles,
	}, nil
}

// hasRequiredScopes checks if the token has all required scopes
func (e *Evaluator) hasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	tokenScopeSet := make(map[string]bool)
	for _, scope := range tokenScopes {
		tokenScopeSet[scope] = true
	}

	for _, requiredScope := range requiredScopes {
		if !tokenScopeSet[requiredScope] {
			return false
		}
	}
	return true
}

// hasRequiredRoles checks if the token has all required roles
func (e *Evaluator) hasRequiredRoles(tokenRoles, requiredRoles []string) bool {
	tokenRoleSet := make(map[string]bool)
	for _, role := range tokenRoles {
		tokenRoleSet[role] = true
	}

	for _, requiredRole := range requiredRoles {
		if !tokenRoleSet[requiredRole] {
			return false
		}
	}
	return true
}

// validateClaims validates custom claims against configured rules
func (e *Evaluator) validateClaims(tokenClaims map[string]interface{}, validationRules map[string]interface{}) bool {
	for claimName, expectedValue := range validationRules {
		tokenValue, exists := tokenClaims[claimName]
		if !exists {
			return false
		}

		// Handle different types of validation
		switch expected := expectedValue.(type) {
		case string:
			if tokenStr, ok := tokenValue.(string); !ok || tokenStr != expected {
				return false
			}
		case []interface{}:
			// Check if token value is in the list of allowed values
			if !e.isValueInList(tokenValue, expected) {
				return false
			}
		case map[string]interface{}:
			// Complex validation rules (e.g., regex, range checks)
			if !e.validateComplexClaim(tokenValue, expected) {
				return false
			}
		default:
			// Direct comparison
			if tokenValue != expectedValue {
				return false
			}
		}
	}
	return true
}

// isValueInList checks if a value is in a list of allowed values
func (e *Evaluator) isValueInList(value interface{}, allowedValues []interface{}) bool {
	for _, allowed := range allowedValues {
		if value == allowed {
			return true
		}
	}
	return false
}

// validateComplexClaim validates a claim against complex rules
func (e *Evaluator) validateComplexClaim(value interface{}, rules map[string]interface{}) bool {
	// Handle regex validation
	if regex, exists := rules["regex"]; exists {
		if regexStr, ok := regex.(string); ok {
			if valueStr, ok := value.(string); ok {
				// Simple contains check (replace with proper regex if needed)
				return strings.Contains(valueStr, regexStr)
			}
		}
	}

	// Handle minimum/maximum values for numbers
	if min, exists := rules["min"]; exists {
		if valueFloat, ok := value.(float64); ok {
			if minFloat, ok := min.(float64); ok && valueFloat < minFloat {
				return false
			}
		}
	}

	if max, exists := rules["max"]; exists {
		if valueFloat, ok := value.(float64); ok {
			if maxFloat, ok := max.(float64); ok && valueFloat > maxFloat {
				return false
			}
		}
	}

	return true
}