package keycloak

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CliXiD/keycloak-pep-plugin/config"
	"github.com/CliXiD/keycloak-pep-plugin/internal/cache"
)

// Client handles communication with Keycloak
type Client struct {
	config     *config.Config
	httpClient *http.Client
	cache      *cache.Cache
	baseURL    string
}

// NewClient creates a new Keycloak client
func NewClient(cfg *config.Config) (*Client, error) {
	baseURL := strings.TrimSuffix(cfg.Keycloak.ServerURL, "/")

	httpClient := &http.Client{
		Timeout: cfg.Timeout,
	}

	var cacheInstance *cache.Cache
	if cfg.Cache.Enabled {
		cacheInstance = cache.New()
	}

	return &Client{
		config:     cfg,
		httpClient: httpClient,
		cache:      cacheInstance,
		baseURL:    baseURL,
	}, nil
}

// ValidateToken validates a JWT token with Keycloak
func (c *Client) ValidateToken(token string) (*TokenInfo, error) {
	// Check cache first
	if c.cache != nil {
		if cached, found := c.cache.Get("token:" + token); found {
			if tokenInfo, ok := cached.(*TokenInfo); ok {
				return tokenInfo, nil
			}
		}
	}

	// Introspect token with Keycloak
	tokenInfo, err := c.introspectToken(token)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if c.cache != nil && tokenInfo.Active {
		expiration := time.Until(time.Unix(tokenInfo.Exp, 0))
		if expiration > 0 && expiration < c.config.Cache.TokenTTL {
			c.cache.Set("token:"+token, tokenInfo, expiration)
		} else if expiration > 0 {
			c.cache.Set("token:"+token, tokenInfo, c.config.Cache.TokenTTL)
		}
	}

	return tokenInfo, nil
}

// introspectToken performs token introspection with Keycloak
func (c *Client) introspectToken(token string) (*TokenInfo, error) {
	introspectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect",
		c.baseURL, c.config.Keycloak.Realm)

	// Prepare form data
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", c.config.Keycloak.ClientID)
	if c.config.Keycloak.ClientSecret != "" {
		data.Set("client_secret", c.config.Keycloak.ClientSecret)
	}

	// Create request
	req, err := http.NewRequest("POST", introspectURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token introspection failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var introspectionResponse IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectionResponse); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	// Convert to TokenInfo
	tokenInfo := &TokenInfo{
		Active:   introspectionResponse.Active,
		Sub:      introspectionResponse.Sub,
		Aud:      introspectionResponse.Aud,
		Iss:      introspectionResponse.Iss,
		Exp:      introspectionResponse.Exp,
		Iat:      introspectionResponse.Iat,
		ClientID: introspectionResponse.ClientID,
		Username: introspectionResponse.Username,
		Scopes:   strings.Fields(introspectionResponse.Scope),
		Claims:   make(map[string]interface{}),
	}

	// Extract roles from realm_access and resource_access
	if introspectionResponse.RealmAccess.Roles != nil {
		tokenInfo.Roles = append(tokenInfo.Roles, introspectionResponse.RealmAccess.Roles...)
	}

	// Extract resource-specific roles
	for clientID, access := range introspectionResponse.ResourceAccess {
		if access.Roles != nil {
			for _, role := range access.Roles {
				tokenInfo.Roles = append(tokenInfo.Roles, fmt.Sprintf("%s:%s", clientID, role))
			}
		}
	}

	// Copy additional claims
	tokenInfo.Claims["preferred_username"] = introspectionResponse.PreferredUsername
	tokenInfo.Claims["email"] = introspectionResponse.Email
	tokenInfo.Claims["email_verified"] = introspectionResponse.EmailVerified
	tokenInfo.Claims["name"] = introspectionResponse.Name
	tokenInfo.Claims["given_name"] = introspectionResponse.GivenName
	tokenInfo.Claims["family_name"] = introspectionResponse.FamilyName

	return tokenInfo, nil
}

// GetResource retrieves resource information from Keycloak
func (c *Client) GetResource(resourceName string) (*Resource, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("resource:%s", resourceName)
	if c.cache != nil {
		if cached, found := c.cache.Get(cacheKey); found {
			if resource, ok := cached.(*Resource); ok {
				return resource, nil
			}
		}
	}

	// Get access token for service account
	accessToken, err := c.getServiceAccountToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get service account token: %w", err)
	}

	// Retrieve resource from Keycloak
	resourceURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/authz/resource-server/resource",
		c.baseURL, c.config.Keycloak.Realm, c.config.Keycloak.ClientID)

	req, err := http.NewRequest("GET", resourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	q := req.URL.Query()
	q.Add("name", resourceName)
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get resource with status %d: %s", resp.StatusCode, string(body))
	}

	var resources []Resource
	if err := json.NewDecoder(resp.Body).Decode(&resources); err != nil {
		return nil, fmt.Errorf("failed to decode resource response: %w", err)
	}

	if len(resources) == 0 {
		return nil, fmt.Errorf("resource not found: %s", resourceName)
	}

	resource := &resources[0]

	// Cache the result
	if c.cache != nil {
		c.cache.Set(cacheKey, resource, c.config.Cache.PolicyTTL)
	}

	return resource, nil
}

// getServiceAccountToken retrieves an access token for the service account
func (c *Client) getServiceAccountToken() (string, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		c.baseURL, c.config.Keycloak.Realm)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.config.Keycloak.ClientID)
	if c.config.Keycloak.ClientSecret != "" {
		data.Set("client_secret", c.config.Keycloak.ClientSecret)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get token with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResponse.AccessToken, nil
}