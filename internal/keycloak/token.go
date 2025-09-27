package keycloak

import (
	"time"
)

// TokenInfo represents validated token information
type TokenInfo struct {
	Active   bool                   `json:"active"`
	Sub      string                 `json:"sub"`
	Aud      interface{}            `json:"aud"` // Can be string or []string
	Iss      string                 `json:"iss"`
	Exp      int64                  `json:"exp"`
	Iat      int64                  `json:"iat"`
	ClientID string                 `json:"client_id"`
	Username string                 `json:"username"`
	Scopes   []string               `json:"scopes"`
	Roles    []string               `json:"roles"`
	Claims   map[string]interface{} `json:"claims"`
}

// IntrospectionResponse represents the response from Keycloak token introspection
type IntrospectionResponse struct {
	Active            bool                        `json:"active"`
	Sub               string                      `json:"sub"`
	Aud               interface{}                 `json:"aud"`
	Iss               string                      `json:"iss"`
	Exp               int64                       `json:"exp"`
	Iat               int64                       `json:"iat"`
	ClientID          string                      `json:"client_id"`
	Username          string                      `json:"username"`
	Scope             string                      `json:"scope"`
	PreferredUsername string                      `json:"preferred_username"`
	Email             string                      `json:"email"`
	EmailVerified     bool                        `json:"email_verified"`
	Name              string                      `json:"name"`
	GivenName         string                      `json:"given_name"`
	FamilyName        string                      `json:"family_name"`
	RealmAccess       RealmAccess                 `json:"realm_access"`
	ResourceAccess    map[string]ResourceAccess   `json:"resource_access"`
}

// RealmAccess represents realm-level role assignments
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// ResourceAccess represents client-specific role assignments
type ResourceAccess struct {
	Roles []string `json:"roles"`
}

// TokenResponse represents the response from token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IsExpired checks if the token has expired
func (t *TokenInfo) IsExpired() bool {
	if t.Exp == 0 {
		return false // No expiration set
	}
	return time.Now().Unix() >= t.Exp
}

// HasScope checks if the token has a specific scope
func (t *TokenInfo) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole checks if the token has a specific role
func (t *TokenInfo) HasRole(role string) bool {
	for _, r := range t.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token has any of the specified scopes
func (t *TokenInfo) HasAnyScope(scopes []string) bool {
	for _, scope := range scopes {
		if t.HasScope(scope) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the token has all of the specified scopes
func (t *TokenInfo) HasAllScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !t.HasScope(scope) {
			return false
		}
	}
	return true
}

// HasAnyRole checks if the token has any of the specified roles
func (t *TokenInfo) HasAnyRole(roles []string) bool {
	for _, role := range roles {
		if t.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the token has all of the specified roles
func (t *TokenInfo) HasAllRoles(roles []string) bool {
	for _, role := range roles {
		if !t.HasRole(role) {
			return false
		}
	}
	return true
}

// GetClaim retrieves a claim value from the token
func (t *TokenInfo) GetClaim(name string) (interface{}, bool) {
	value, exists := t.Claims[name]
	return value, exists
}

// GetClaimAsString retrieves a claim value as a string
func (t *TokenInfo) GetClaimAsString(name string) (string, bool) {
	value, exists := t.Claims[name]
	if !exists {
		return "", false
	}
	if str, ok := value.(string); ok {
		return str, true
	}
	return "", false
}

// GetClaimAsBool retrieves a claim value as a boolean
func (t *TokenInfo) GetClaimAsBool(name string) (bool, bool) {
	value, exists := t.Claims[name]
	if !exists {
		return false, false
	}
	if b, ok := value.(bool); ok {
		return b, true
	}
	return false, false
}

// GetClaimAsFloat retrieves a claim value as a float64
func (t *TokenInfo) GetClaimAsFloat(name string) (float64, bool) {
	value, exists := t.Claims[name]
	if !exists {
		return 0, false
	}
	if f, ok := value.(float64); ok {
		return f, true
	}
	return 0, false
}