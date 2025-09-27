package config

import "time"

// Config represents the plugin configuration
type Config struct {
	// EnforcementMode defines how policies are enforced
	// ENFORCING: Strict enforcement, deny access on policy violation
	// PERMISSIVE: Log policy violations but allow access
	// DISABLED: No policy enforcement
	EnforcementMode string `json:"enforcement_mode,omitempty" yaml:"enforcement_mode,omitempty"`

	// Keycloak configuration
	Keycloak KeycloakConfig `json:"keycloak" yaml:"keycloak"`

	// Path-specific configurations
	Paths []PathConfig `json:"paths,omitempty" yaml:"paths,omitempty"`

	// Cache configuration
	Cache CacheConfig `json:"cache,omitempty" yaml:"cache,omitempty"`

	// HTTP client timeout
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// KeycloakConfig contains Keycloak server configuration
type KeycloakConfig struct {
	// ServerURL is the base URL of the Keycloak server
	ServerURL string `json:"server_url" yaml:"server_url"`

	// Realm is the Keycloak realm name
	Realm string `json:"realm" yaml:"realm"`

	// ClientID is the client identifier in Keycloak
	ClientID string `json:"client_id" yaml:"client_id"`

	// ClientSecret is the client secret (optional for public clients)
	ClientSecret string `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`

	// CredentialsSecret contains credentials for service account
	CredentialsSecret map[string]interface{} `json:"credentials_secret,omitempty" yaml:"credentials_secret,omitempty"`

	// UseResourceName indicates whether to use resource name matching
	UseResourceName bool `json:"use_resource_name,omitempty" yaml:"use_resource_name,omitempty"`

	// LazyLoadPaths enables lazy loading of protected resource paths
	LazyLoadPaths bool `json:"lazy_load_paths,omitempty" yaml:"lazy_load_paths,omitempty"`
}

// PathConfig defines policy enforcement for specific paths
type PathConfig struct {
	// Path pattern to match (supports wildcards)
	Path string `json:"path" yaml:"path"`

	// HTTP methods to protect
	Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`

	// Required scopes for access
	Scopes []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`

	// Required roles for access
	Roles []string `json:"roles,omitempty" yaml:"roles,omitempty"`

	// Enforcement mode override for this path
	EnforcementMode string `json:"enforcement_mode,omitempty" yaml:"enforcement_mode,omitempty"`

	// Resource name in Keycloak
	ResourceName string `json:"resource_name,omitempty" yaml:"resource_name,omitempty"`

	// Claims validation
	ClaimsValidation map[string]interface{} `json:"claims_validation,omitempty" yaml:"claims_validation,omitempty"`
}

// CacheConfig defines caching behavior
type CacheConfig struct {
	// Enable caching
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty"`

	// TTL for cached tokens
	TokenTTL time.Duration `json:"token_ttl,omitempty" yaml:"token_ttl,omitempty"`

	// TTL for cached policies
	PolicyTTL time.Duration `json:"policy_ttl,omitempty" yaml:"policy_ttl,omitempty"`

	// Maximum cache size
	MaxSize int `json:"max_size,omitempty" yaml:"max_size,omitempty"`
}

// EnforcementMode constants
const (
	EnforcementModeEnforcing  = "ENFORCING"
	EnforcementModePermissive = "PERMISSIVE"
	EnforcementModeDisabled   = "DISABLED"
)

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		EnforcementMode: EnforcementModeEnforcing,
		Timeout:         30 * time.Second,
		Cache: CacheConfig{
			Enabled:   true,
			TokenTTL:  5 * time.Minute,
			PolicyTTL: 10 * time.Minute,
			MaxSize:   1000,
		},
	}
}

// IsEnforcing returns true if enforcement mode is ENFORCING
func (c *Config) IsEnforcing() bool {
	return c.EnforcementMode == EnforcementModeEnforcing
}

// IsPermissive returns true if enforcement mode is PERMISSIVE
func (c *Config) IsPermissive() bool {
	return c.EnforcementMode == EnforcementModePermissive
}

// IsDisabled returns true if enforcement mode is DISABLED
func (c *Config) IsDisabled() bool {
	return c.EnforcementMode == EnforcementModeDisabled
}