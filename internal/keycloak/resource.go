package keycloak

// Resource represents a Keycloak resource
type Resource struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type,omitempty"`
	URI         string            `json:"uri,omitempty"`
	URIs        []string          `json:"uris,omitempty"`
	Scopes      []Scope           `json:"scopes,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	OwnerManagedAccess bool       `json:"ownerManagedAccess,omitempty"`
	DisplayName string            `json:"displayName,omitempty"`
	IconURI     string            `json:"icon_uri,omitempty"`
}

// Scope represents a Keycloak scope
type Scope struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	IconURI     string `json:"iconUri,omitempty"`
}

// Policy represents a Keycloak policy
type Policy struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description,omitempty"`
	Type             string                 `json:"type"`
	Logic            string                 `json:"logic,omitempty"`
	DecisionStrategy string                 `json:"decisionStrategy,omitempty"`
	Config           map[string]interface{} `json:"config,omitempty"`
}

// Permission represents a Keycloak permission
type Permission struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description,omitempty"`
	Type             string                 `json:"type"`
	Logic            string                 `json:"logic,omitempty"`
	DecisionStrategy string                 `json:"decisionStrategy,omitempty"`
	Config           map[string]interface{} `json:"config,omitempty"`
	Resources        []string               `json:"resources,omitempty"`
	Scopes           []string               `json:"scopes,omitempty"`
	Policies         []string               `json:"policies,omitempty"`
}

// AuthorizationRequest represents a request to evaluate permissions
type AuthorizationRequest struct {
	GrantType   string                 `json:"grant_type"`
	Audience    string                 `json:"audience"`
	Permissions []PermissionRequest    `json:"permissions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PermissionRequest represents a specific permission request
type PermissionRequest struct {
	ResourceID   string   `json:"resource_id,omitempty"`
	ResourceName string   `json:"resource_name,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// AuthorizationResponse represents the response from authorization evaluation
type AuthorizationResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy,omitempty"`
	SessionState     string `json:"session_state,omitempty"`
	Scope            string `json:"scope,omitempty"`
}

// ResourceServer represents a Keycloak resource server configuration
type ResourceServer struct {
	ID                   string                 `json:"id"`
	ClientID             string                 `json:"clientId"`
	Name                 string                 `json:"name,omitempty"`
	Description          string                 `json:"description,omitempty"`
	AllowRemoteResourceManagement bool          `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode string                 `json:"policyEnforcementMode"`
	Resources            []Resource             `json:"resources,omitempty"`
	Policies             []Policy               `json:"policies,omitempty"`
	Scopes               []Scope                `json:"scopes,omitempty"`
	DecisionStrategy     string                 `json:"decisionStrategy,omitempty"`
}

// MatchesURI checks if the resource matches the given URI
func (r *Resource) MatchesURI(uri string) bool {
	// Check exact URI match
	if r.URI == uri {
		return true
	}

	// Check URI list
	for _, resourceURI := range r.URIs {
		if resourceURI == uri {
			return true
		}
		// Simple wildcard matching
		if r.wildcardMatch(resourceURI, uri) {
			return true
		}
	}

	return false
}

// wildcardMatch performs simple wildcard matching
func (r *Resource) wildcardMatch(pattern, text string) bool {
	// Simple implementation - can be enhanced with more sophisticated pattern matching
	if pattern == "*" {
		return true
	}

	// Handle trailing /* pattern
	if len(pattern) > 1 && pattern[len(pattern)-2:] == "/*" {
		prefix := pattern[:len(pattern)-2]
		return len(text) >= len(prefix) && text[:len(prefix)] == prefix
	}

	return pattern == text
}

// HasScope checks if the resource has a specific scope
func (r *Resource) HasScope(scopeName string) bool {
	for _, scope := range r.Scopes {
		if scope.Name == scopeName {
			return true
		}
	}
	return false
}

// GetScopeNames returns all scope names for the resource
func (r *Resource) GetScopeNames() []string {
	var names []string
	for _, scope := range r.Scopes {
		names = append(names, scope.Name)
	}
	return names
}